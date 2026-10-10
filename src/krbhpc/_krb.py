"""Shared helpers for the krbhpc shared-home package: durations, klist parsing,
error classification, and subprocess wrappers around the MIT Kerberos client
tools (kinit, klist, kvno).

No third-party dependencies; standard library only.
"""
from __future__ import annotations

import calendar
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass

_DUR = re.compile(r"(\d+)([smhd]?)")
_UNIT = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}

# `kvno --out-cache` (used for the S4U mint) first appeared in MIT krb5 1.19.
MIN_MIT_VERSION = (1, 19)

DEFAULT_TOOLS = {"kinit": "/usr/bin/kinit", "klist": "/usr/bin/klist", "kvno": "/usr/bin/kvno"}


def duration_seconds(text: str) -> int:
    """Parse '10h', '7d', '300', '2h' -> seconds."""
    m = _DUR.fullmatch(text.strip())
    if not m:
        raise ValueError(f"bad duration: {text!r}")
    return int(m.group(1)) * _UNIT[m.group(2)]


@dataclass(frozen=True)
class TgtTimes:
    expires: float      # epoch seconds the TGT is valid until
    renew_until: float  # epoch seconds renewal is possible until


def _parse_klist_time(date: str, clock: str) -> float:
    # The tools run with LC_ALL=C and TZ=UTC0, so klist prints MM/DD/YY
    # HH:MM:SS in UTC. Converting with timegm (not local-time mktime) avoids
    # the ambiguous hour when daylight saving time ends.
    for fmt in ("%m/%d/%y %H:%M:%S", "%m/%d/%Y %H:%M:%S"):
        try:
            return float(calendar.timegm(time.strptime(f"{date} {clock}", fmt)))
        except ValueError:
            continue
    raise ValueError(f"unparseable klist time: {date} {clock}")


def parse_klist(output: str) -> TgtTimes | None:
    """Extract (expires, renew_until) for the krbtgt line from `klist` output.
    Returns None if no TGT line is present."""
    lines = output.splitlines()
    for i, line in enumerate(lines):
        if "krbtgt/" in line:
            parts = line.split()
            # cols: valid-start(2)  expires(2)  service
            expires = _parse_klist_time(parts[2], parts[3])
            renew = expires
            if i + 1 < len(lines) and "renew until" in lines[i + 1]:
                q = lines[i + 1].replace(",", " ").split()
                renew = _parse_klist_time(q[2], q[3])
            return TgtTimes(expires, renew)
    return None


def earliest_expiry(output: str) -> float | None:
    """Earliest 'Expires' across ALL tickets in `klist` output (service-ticket
    cache; there is no TGT). Returns epoch seconds, or None if no ticket line
    parses. Used to decide when to re-mint a user's service tickets."""
    earliest: float | None = None
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 5 or "/" not in parts[-1]:
            continue
        try:
            exp = _parse_klist_time(parts[2], parts[3])
        except (ValueError, IndexError):
            continue
        if earliest is None or exp < earliest:
            earliest = exp
    return earliest


# AES encryption types. A minted ticket's session key must be one of these;
# a ticket encrypted with anything else (the target service account's choice)
# is reported as a warning.
ALLOWED_ENCTYPES = frozenset({
    "aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96",
    "aes256-cts-hmac-sha384-192", "aes128-cts-hmac-sha256-128",
})


@dataclass(frozen=True)
class Ticket:
    server: str               # service principal the ticket is for
    expires: float            # epoch seconds
    client: str | None        # set only when it differs from the default principal
    skey_etype: str | None
    tkt_etype: str | None


@dataclass(frozen=True)
class CacheInfo:
    default_principal: str | None
    tickets: tuple[Ticket, ...]


def parse_klist_details(output: str) -> CacheInfo:
    """Parse `klist -e -f` output (LC_ALL=C, TZ=UTC0) into the default
    principal and one Ticket per entry. MIT prints, per ticket: a times +
    service line, then optional tab-indented lines ("for client X",
    "renew until ...", "Flags: ..., Etype (skey, tkt): A, B")."""
    default = None
    tickets: list[dict] = []
    for line in output.splitlines():
        if line.startswith("Default principal:"):
            default = line.split(":", 1)[1].strip()
            continue
        parts = line.split()
        if not parts:
            continue
        if not line[:1].isspace() and len(parts) >= 5:
            try:
                expires = _parse_klist_time(parts[2], parts[3])
            except ValueError:
                continue
            tickets.append({"server": parts[4], "expires": expires, "client": None,
                            "skey_etype": None, "tkt_etype": None})
            continue
        if not tickets or not line[:1].isspace():
            continue
        cur = tickets[-1]
        text = line.strip()
        if text.startswith("for client "):
            cur["client"] = text[len("for client "):].split(",")[0].strip()
        m = re.search(r"Etype \(skey, tkt\): ([^,\s]+), ([^,\s]+)", text)
        if m:
            cur["skey_etype"], cur["tkt_etype"] = m.group(1), m.group(2)
    return CacheInfo(default, tuple(Ticket(**t) for t in tickets))


# A minted ticket with less life than this is refused outright (expired or
# about to be: clock skew or a broken KDC policy).
MIN_TICKET_VALID_S = 300


def _qualify(principal: str, realm: str) -> str:
    return principal if "@" in principal else f"{principal}@{realm}"


def validate_user_cache(info: CacheInfo, accepted_principals: list[str], realm: str,
                        targets: list[str], min_valid_s: int,
                        now: float | None = None, strict: bool = True) -> list[str]:
    """Check a freshly minted cache before anyone uses it.

    Fatal (raises KrbToolError, category "bad_ticket"): no default principal;
    tickets for someone other than one of `accepted_principals` (compared
    case-insensitively, bare names qualified with `realm`); a TGT; a delegation
    target missing; a ticket naming a different client; a non-AES session key;
    less than `min_valid_s` of life.

    Returned as warnings (the cache is still usable): extra non-TGT entries,
    and a ticket encrypted with a non-AES key -- that is chosen by the TARGET
    service account's msDS-SupportedEncryptionTypes, so it is a back-end
    setting to fix, not a reason to deny every user of that service.

    strict=False (ticket_checks = warn) turns only the two name-matching
    checks -- an unexpected principal name and a missing target -- into
    warnings, for sites still sorting out name formats. A TGT, a ticket for a
    different client, a non-AES session key and too short a life stay fatal."""
    now = time.time() if now is None else now
    warnings: list[str] = []

    def bad(why: str) -> None:
        raise KrbToolError("kvno", "minted cache rejected", why, "bad_ticket")

    def name_problem(why: str) -> None:
        if strict:
            bad(why)
        warnings.append(f"(ticket_checks=warn, not enforced) {why}")

    ok = {_qualify(p, realm).lower() for p in accepted_principals}
    if not info.default_principal:
        bad("cache has no default principal")
    if info.default_principal.lower() not in ok:
        name_problem(f"tickets are for {info.default_principal}, expected "
            f"{' or '.join(sorted({_qualify(p, realm) for p in accepted_principals}))}")
    servers = {t.server.lower(): t.server for t in info.tickets}
    if any(s.startswith("krbtgt/") for s in servers):
        bad("cache contains a ticket-granting ticket")
    missing = [t for t in targets if t.lower() not in servers]
    if missing:
        name_problem(f"no ticket for {', '.join(missing)} (cache holds "
            f"{', '.join(servers.values()) or 'nothing'})")
    wanted = {t.lower() for t in targets}
    extra = [v for k, v in servers.items() if k not in wanted]
    if extra:
        warnings.append(f"cache also holds {', '.join(extra)}")
    for t in info.tickets:
        if t.client and t.client.lower() != info.default_principal.lower():
            bad(f"ticket for {t.server} names client {t.client}")
        if t.skey_etype is None:
            bad(f"no encryption type reported for {t.server}")
        if t.skey_etype not in ALLOWED_ENCTYPES:
            bad(f"{t.server} session key uses {t.skey_etype}; only AES is allowed")
        if t.tkt_etype not in ALLOWED_ENCTYPES:
            warnings.append(f"{t.server} ticket is encrypted with {t.tkt_etype}: enable "
                            "AES on that service account (msDS-SupportedEncryptionTypes)")
        if t.expires - now < min_valid_s:
            bad(f"ticket for {t.server} expires in {int(t.expires - now)}s "
                f"(minimum {min_valid_s}s)")
    return warnings


def parse_mit_version(text: str) -> tuple[int, ...] | None:
    """'Kerberos 5 version 1.20.1' (MIT `klist -V`) -> (1, 20, 1).
    Returns None for anything else (e.g. Heimdal)."""
    m = re.search(r"Kerberos 5 version (\d+)\.(\d+)(?:\.(\d+))?", text)
    if not m:
        return None
    return tuple(int(x) for x in m.groups() if x is not None)


# --------------------------------------------------------------- errors
# Failure categories, from the MIT error messages the tools print. Used for
# logging/alerting and to decide whether a retry is worthwhile.
_CATEGORIES = [
    ("kdc_unreachable", ("cannot contact any kdc", "cannot find kdc", "connection refused",
                         "resource temporarily unavailable", "timed out")),
    ("clock_skew", ("clock skew too great",)),
    ("not_delegable", ("constrained delegation failed", "kdc can't fulfill requested option",
                       "kdc policy rejects request")),
    ("unknown_principal", ("not found in kerberos database",)),
    ("broker_key", ("key table entry not found", "key table file", "keytab contains no suitable keys",
                    "preauthentication failed", "password incorrect", "no suitable keys")),
    ("bad_cache", ("no credentials cache found", "credentials cache file", "matching credential not found",
                   "ticket expired")),
]
# "bad_ticket" (a minted cache failed validate_user_cache) is assigned
# directly, never inferred from tool output; it needs an admin.
# Categories a later retry might fix on its own; the others need an admin.
TRANSIENT = frozenset({"kdc_unreachable", "timeout", "bad_cache"})


def classify_error(text: str) -> str:
    """Map a Kerberos tool's stderr to a coarse failure category."""
    low = text.lower()
    for cat, needles in _CATEGORIES:
        if any(n in low for n in needles):
            return cat
    return "other"


class KrbToolError(RuntimeError):
    """A Kerberos command failed. `category` is from classify_error()."""

    def __init__(self, tool: str, what: str, detail: str, category: str | None = None):
        self.tool, self.detail = tool, detail
        self.category = category or classify_error(detail)
        super().__init__(f"{what} [{self.category}]: {detail}")

    @property
    def transient(self) -> bool:
        return self.category in TRANSIENT


class Krb5:
    """Thin wrapper over kinit/klist/kvno with pinned paths, config, locale and
    time zone."""

    # Variables scrubbed from the Kerberos tools' environment: the arbitrary-
    # code dynamic-linker vectors, and any inherited credential-cache / keytab
    # / config pointers (every call passes -c / -t explicitly and KRB5_CONFIG
    # is pinned, so these must not leak in). LD_LIBRARY_PATH is intentionally
    # preserved: some sites install MIT krb5 under a non-standard prefix.
    _SCRUB = ("LD_PRELOAD", "LD_AUDIT", "KRB5CCNAME", "KRB5_KTNAME", "KRB5_CLIENT_KTNAME",
              "KRB5_TRACE", "KRB5_KDC_PROFILE", "KRB5RCACHEDIR", "KRB5RCACHETYPE",
              "KRB5_CONFIG", "TZ", "LANG", "LANGUAGE")
    _SCRUB_PREFIXES = ("LC_",)

    def __init__(self, krb5_conf: str, extra_env: dict | None = None,
                 tools: dict | None = None, s4u_enterprise: bool = True):
        # Start from the daemon's (systemd-controlled) environment so the
        # standard paths are preserved, then remove the injection vectors and
        # pin the config, C locale and UTC (stable, unambiguous date parsing).
        env = {k: v for k, v in os.environ.items()
               if k not in self._SCRUB and not k.startswith(self._SCRUB_PREFIXES)}
        env["KRB5_CONFIG"] = krb5_conf
        env["LC_ALL"] = "C"
        env["TZ"] = "UTC0"
        if extra_env:
            env.update(extra_env)
        self.env = env
        # Tools are run by absolute path, never looked up on PATH.
        self.tools = dict(DEFAULT_TOOLS, **(tools or {}))
        for name, path in self.tools.items():
            if not os.path.isabs(path):
                raise ValueError(f"{name} must be an absolute path, got {path!r}")
        # kvno -U treats the user as an enterprise name (AD resolves UPNs and
        # sAMAccountNames); -I uses a plain principal name.
        self.s4u_flag = "-U" if s4u_enterprise else "-I"
        # klist results, memoized per file identity (see _klist_cached).
        self._klist_cache: dict[tuple[str, str], tuple[tuple, object]] = {}
        self._klist_lock = threading.Lock()

    def run(self, tool: str, *args: str, timeout: int = 60) -> subprocess.CompletedProcess:
        try:
            return subprocess.run([self.tools[tool], *args], env=self.env,
                                  capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as e:
            raise KrbToolError(tool, f"{tool} timed out after {timeout}s",
                               "no answer from the KDC in time", "timeout") from e

    def version(self) -> tuple[int, ...]:
        """MIT version of the configured tools; raises if not MIT >= 1.19."""
        r = self.run("klist", "-V")
        v = parse_mit_version(r.stdout + r.stderr)
        if v is None:
            raise RuntimeError(f"{self.tools['klist']} is not MIT Kerberos "
                               f"(klist -V said: {(r.stdout + r.stderr).strip()!r})")
        if v[:2] < MIN_MIT_VERSION:
            raise RuntimeError(
                f"MIT Kerberos {'.'.join(map(str, v))} is too old: kvno --out-cache "
                f"needs {'.'.join(map(str, MIN_MIT_VERSION))} or newer")
        return v

    def _klist_cached(self, kind: str, ccache: str, parse):
        """Run `klist` on a cache only when the file has changed. Caches are
        always replaced atomically (new inode) or rewritten (new mtime/size),
        so (inode, mtime_ns, size) identifies the content; a missing file is
        None without starting a process. This turns the per-request and
        per-refresh-pass klist calls into a stat() for unchanged caches."""
        try:
            st = os.stat(ccache)
        except OSError:
            return None
        key = (st.st_ino, st.st_mtime_ns, st.st_size)
        with self._klist_lock:
            hit = self._klist_cache.get((kind, ccache))
        if hit is not None and hit[0] == key:
            return hit[1]
        r = self.run("klist", "-c", f"FILE:{ccache}")
        value = parse(r.stdout) if r.returncode == 0 else None
        with self._klist_lock:
            self._klist_cache[(kind, ccache)] = (key, value)
        return value

    def forget(self, ccache: str) -> None:
        """Drop memoized results for a cache that is being retired."""
        with self._klist_lock:
            for kind in ("tgt", "exp"):
                self._klist_cache.pop((kind, ccache), None)

    def klist_times(self, ccache: str) -> TgtTimes | None:
        """Expiry and renew-until of the TGT in a cache (the broker's)."""
        return self._klist_cached("tgt", ccache, parse_klist)

    def cache_expiry(self, ccache: str) -> float | None:
        """Earliest expiry across all (service) tickets in a cache, or None."""
        return self._klist_cached("exp", ccache, earliest_expiry)

    def inspect(self, ccache: str) -> CacheInfo:
        """Principal, services, expiries and encryption types of every ticket
        in a cache (not memoized: used once on each freshly minted cache)."""
        r = self.run("klist", "-e", "-f", "-c", f"FILE:{ccache}")
        if r.returncode != 0:
            raise KrbToolError("klist", "cannot read minted cache",
                               r.stderr.strip() or "unknown error", "bad_ticket")
        return parse_klist_details(r.stdout)

    def kinit_keytab(self, principal: str, keytab: str, ccache: str,
                     lifetime: str, renew_lifetime: str) -> None:
        """Get the BROKER's own forwardable, renewable TGT from its keytab."""
        r = self.run("kinit", "-f", "-r", renew_lifetime, "-l", lifetime,
                     "-k", "-t", keytab, "-c", f"FILE:{ccache}", principal)
        if r.returncode != 0:
            raise KrbToolError("kinit", f"kinit failed for {principal}", r.stderr.strip())

    def kinit_renew(self, ccache: str) -> bool:
        """Renew the TGT in `ccache` WITHOUT rewriting it in place: `kinit -R`
        re-initializes the file it renews, so renew a private copy and rename
        it over the original. A kvno reading the broker cache at the same
        moment then sees the old or the new cache, never a half-written one."""
        tmp = f"{ccache}.renew"
        try:
            shutil.copyfile(ccache, tmp)
            os.chmod(tmp, 0o600)
            r = self.run("kinit", "-R", "-c", f"FILE:{tmp}")
            if r.returncode != 0:
                return False
            os.replace(tmp, ccache)
            return True
        except (OSError, KrbToolError):
            return False
        finally:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass

    def s4u_mint(self, broker_ccache: str, for_user: str, targets: list[str],
                 out_ccache: str) -> None:
        """Constrained delegation: using the broker's TGT in `broker_ccache`,
        obtain SERVICE tickets to each SPN in `targets` on behalf of `for_user`
        (S4U2Self + S4U2Proxy, i.e. `kvno -U|-I <user> -P ...`) and write them
        to `out_ccache`. No TGT is produced -- only tickets to the allow-listed
        backends. Requires AD's msDS-AllowedToDelegateTo (or an MIT KDC whose
        database can hold a delegation allow-list) for the proxy leg.

        kvno honors --out-cache for S4U2Self but still stores each S4U2Proxy
        ticket in the cache it was given (MIT kvno.c passes only
        KRB5_GC_CANONICALIZE to krb5_get_credentials_for_proxy). So kvno gets a
        private, throwaway COPY of the broker cache: the real one keeps only
        the broker's TGT, never accumulates every user's service tickets, and
        parallel mints never write to the same file."""
        out_dir = os.path.dirname(os.path.abspath(out_ccache))
        fd, scratch = tempfile.mkstemp(prefix=".broker.", suffix=".cc", dir=out_dir)
        try:
            with os.fdopen(fd, "wb") as dst, open(broker_ccache, "rb") as src:
                shutil.copyfileobj(src, dst)
            r = self.run("kvno", "-c", f"FILE:{scratch}",
                         "--out-cache", f"FILE:{out_ccache}",
                         self.s4u_flag, for_user, "-P", *targets)
        except OSError as e:
            raise KrbToolError("kvno", "cannot read the broker cache", str(e), "bad_cache") from e
        finally:
            try:
                os.unlink(scratch)
            except FileNotFoundError:
                pass
        if r.returncode != 0:
            msg = (r.stderr.strip() or r.stdout.strip() or "unknown error")
            raise KrbToolError("kvno", f"S4U mint failed for {for_user} -> {targets}", msg)
