"""Shared helpers for the krbhpc shared-home package: durations, klist parsing,
and subprocess wrappers around the MIT Kerberos client tools.

No third-party dependencies; standard library only.
"""
from __future__ import annotations

import re
import subprocess
import time
from dataclasses import dataclass

_DUR = re.compile(r"(\d+)([smhd]?)")
_UNIT = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}


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
    # MIT klist prints MM/DD/YY HH:MM:SS under LC_ALL=C.
    for fmt in ("%m/%d/%y %H:%M:%S", "%m/%d/%Y %H:%M:%S"):
        try:
            return time.mktime(time.strptime(f"{date} {clock}", fmt))
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


class Krb5:
    """Thin wrapper over kinit/klist with a pinned config and C locale."""

    # Variables scrubbed from the Kerberos tools' environment: the arbitrary-
    # code dynamic-linker vectors, and any inherited credential-cache / keytab
    # pointers (every call passes -c / -t explicitly, so these must not leak
    # in). LD_LIBRARY_PATH is intentionally preserved: some sites install MIT
    # krb5 under a non-standard prefix and rely on it.
    _SCRUB = ("LD_PRELOAD", "LD_AUDIT", "KRB5CCNAME", "KRB5_KTNAME", "KRB5_TRACE")

    def __init__(self, krb5_conf: str, extra_env: dict | None = None):
        import os
        # Start from the daemon's (systemd-controlled) environment so TZ and
        # the standard paths are preserved, then remove the injection vectors
        # and pin the config and C locale (stable date parsing).
        env = {k: v for k, v in os.environ.items() if k not in self._SCRUB}
        env["KRB5_CONFIG"] = krb5_conf
        env["LC_ALL"] = "C"
        if extra_env:
            env.update(extra_env)
        self.env = env

    def run(self, *args: str, timeout: int = 60) -> subprocess.CompletedProcess:
        return subprocess.run(args, env=self.env, capture_output=True,
                              text=True, timeout=timeout)

    def klist_times(self, ccache: str) -> TgtTimes | None:
        r = self.run("klist", "-c", f"FILE:{ccache}")
        if r.returncode != 0:
            return None
        return parse_klist(r.stdout)

    def cache_expiry(self, ccache: str) -> float | None:
        """Earliest expiry across all (service) tickets in a cache, or None."""
        r = self.run("klist", "-c", f"FILE:{ccache}")
        if r.returncode != 0:
            return None
        return earliest_expiry(r.stdout)

    def kinit_keytab(self, principal: str, keytab: str, ccache: str,
                     lifetime: str, renew_lifetime: str) -> None:
        """Get the BROKER's own forwardable, renewable TGT from its keytab."""
        r = self.run("kinit", "-f", "-r", renew_lifetime, "-l", lifetime,
                     "-k", "-t", keytab, "-c", f"FILE:{ccache}", principal)
        if r.returncode != 0:
            raise RuntimeError(f"kinit failed for {principal}: {r.stderr.strip()}")

    def kinit_renew(self, ccache: str) -> bool:
        r = self.run("kinit", "-R", "-c", f"FILE:{ccache}")
        return r.returncode == 0

    def s4u_mint(self, broker_ccache: str, for_user: str, targets: list[str],
                 out_ccache: str) -> None:
        """Constrained delegation: using the broker's TGT in `broker_ccache`,
        obtain SERVICE tickets to each SPN in `targets` on behalf of `for_user`
        (S4U2Self + S4U2Proxy, i.e. `kvno -U <user> -P ...`) and write them to
        `out_ccache`. No TGT is produced -- only tickets to the allow-listed
        backends. Requires AD's msDS-AllowedToDelegateTo (or an LDAP-backed MIT
        KDC) to authorize the proxy leg; a file/DB2 KDC cannot store the list
        and returns 'constrained delegation failed'."""
        r = self.run("kvno", "-c", f"FILE:{broker_ccache}",
                     "--out-cache", f"FILE:{out_ccache}",
                     "-U", for_user, "-P", *targets)
        if r.returncode != 0:
            msg = (r.stderr.strip() or r.stdout.strip() or "unknown error")
            raise RuntimeError(
                f"S4U mint failed for {for_user} -> {targets}: {msg}")
