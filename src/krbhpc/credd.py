#!/usr/bin/env python3
"""
krb-credd -- Kerberos client broker (root) for a CAC / UID-GID HPC cluster
(shared-home design, pure Python).

It is a Kerberos CLIENT of Active Directory -- it runs no KDC or realm of its
own. AD is the single KDC; this daemon holds one broker service-account keytab
and calls S4U2Self/S4U2Proxy as an ordinary MIT krb5 client.

Users reach the HPC with a CAC, which cannot be used through GSSAPI/PKINIT to
get a TGT, and GSSAPI credential forwarding over SSH is blocked. Instead of an
escrowed per-user keytab (one standing secret per user), this root daemon holds
a SINGLE broker service-account credential and uses Kerberos constrained
delegation to mint each enrolled user's tickets:

    1. kinit the broker's own TGT from one keytab  (renewable, unattended)
    2. S4U2Self + S4U2Proxy (`kvno -U <user> -P <spn>...`) to obtain SERVICE
       tickets to the allow-listed backends ON BEHALF OF the real user
    3. write that cache into the user's home on the shared filesystem:

           {home}/.krb5/krb5cc_hpc

Because home is mounted on every compute node, the tickets are already present
cluster-wide; a one-line Slurm TaskProlog points KRB5CCNAME at the cache. There
is no SPANK plugin, no KCM, no node-side daemon, and NO per-user keytab.

What the user gets is service tickets to the enumerated backends only -- NOT a
general-purpose TGT (there is no approved way to do initial auth as the user on
HPC, and S4U is least-privilege by design). Every Kerberized backend a job
touches must be listed in `delegate_targets` and in the broker account's
msDS-AllowedToDelegateTo in AD.

The daemon keeps every "active" user's tickets fresh by RE-MINTING before
expiry (service tickets cannot be renewed); the broker's own TGT is what
renews/re-acquires unattended from the keytab. A user is active for
`active_window` after a `krb-get`, and for as long as they have a pending or
running Slurm job (squeue), so a long-queued or multi-day job never finds an
expired ticket.

Front door: a UNIX-domain socket. The caller's UID comes from the kernel
(SO_PEERCRED), never from the request, so a user can only ever obtain their own
tickets, and only if enrolled.

Dependencies: python3 stdlib, MIT krb5 1.19+ client tools (kinit, klist, kvno;
run by absolute path),
util-linux setpriv, and the Slurm client (squeue) when watch_slurm is on.
"""
from __future__ import annotations

import argparse
import configparser
import logging
import os
import pwd
import socket
import socketserver
import struct
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from ._krb import (DEFAULT_TOOLS, MIN_TICKET_VALID_S, Krb5, KrbToolError,
                   duration_seconds, validate_user_cache)

log = logging.getLogger("krb-credd")
SO_PEERCRED = getattr(socket, "SO_PEERCRED", 17)

# Hard caps to bound local denial-of-service on the UNIX socket.
MAX_CLIENTS = 32            # concurrent in-flight requests
CLIENT_TIMEOUT_S = 10       # per-connection socket timeout

# Background-refresh backoff after a failed mint: transient failures (KDC
# unreachable, timeout) retry sooner than ones that need an admin (account not
# delegable, unknown principal, broker key problem).
BACKOFF_TRANSIENT_S = (60, 900)      # first retry, cap
BACKOFF_PERMANENT_S = (900, 3600)

# What a user sees for each failure category (details go to the log only).
USER_MESSAGES = {
    "not_delegable": "your account cannot be delegated to the HPC services; contact the HPC admins",
    "unknown_principal": "your account was not found in Active Directory; contact the HPC admins",
    "kdc_unreachable": "the Kerberos server is unreachable; try again shortly",
    "timeout": "the Kerberos server did not answer in time; try again shortly",
    "clock_skew": "clock skew with the Kerberos server; contact the HPC admins",
    "bad_ticket": "the Kerberos server returned unexpected tickets; contact the HPC admins",
}


def _assert_secure(path: Path, *, is_dir: bool, label: str, strict: bool = False) -> None:
    """Fail closed unless `path` is root-owned, not a symlink, of the expected
    type, and not group/world writable. With strict=True (used for secret
    keytabs) require no group/world permission bits at all (i.e. mode 0600)."""
    import stat as _stat
    st = path.lstat()
    if _stat.S_ISLNK(st.st_mode):
        raise PermissionError(f"{label} {path} must not be a symlink")
    if st.st_uid != 0:
        raise PermissionError(f"{label} {path} must be owned by root (uid 0)")
    if is_dir and not _stat.S_ISDIR(st.st_mode):
        raise PermissionError(f"{label} {path} must be a directory")
    if not is_dir and not _stat.S_ISREG(st.st_mode):
        raise PermissionError(f"{label} {path} must be a regular file")
    mask = 0o077 if strict else 0o022
    if st.st_mode & mask:
        kind = "mode 0600 or stricter" if strict else "not group/world writable"
        raise PermissionError(f"{label} {path} must be {kind}")


@dataclass
class Config:
    realm: str
    krb5_conf: str
    broker_principal: str
    broker_keytab: Path
    broker_ccache: Path
    delegate_targets: list[str]   # concrete backend SPNs (S4U2Proxy allow-list)
    state_dir: Path
    map_file: Path
    unix_socket: Path
    ccache_path: str          # tokens: {home} {uid} {user}
    install_helper: str
    setpriv: str
    broker_lifetime: str
    broker_renew: str
    renew_margin_s: int
    refresh_interval_s: int
    active_window_s: int
    watch_slurm: bool
    squeue: str
    min_reissue_s: int
    tools: dict                   # absolute paths of kinit / klist / kvno
    s4u_enterprise: bool          # kvno -U (enterprise name) vs -I (principal)
    refresh_workers: int          # users refreshed in parallel per pass
    min_uid: int = 1000           # never serve system accounts (root, daemons)
    disable_file: Path = Path("/etc/krb-hpc/disabled")   # kill switch
    failure_cooldown_s: int = 60  # min seconds between attempts after a failure
    ticket_checks_enforce: bool = True   # False = "warn": log problems, still publish

    @staticmethod
    def load(path: str) -> "Config":
        # Refuse a config that an attacker could have tampered with.
        _assert_secure(Path(path), is_dir=False, label="config")
        cp = configparser.ConfigParser(inline_comment_prefixes=(";", "#"))
        with open(path) as fh:
            cp.read_file(fh)
        if not cp.has_section("broker"):
            raise ValueError(f"{path}: missing [broker] section")
        s = cp["broker"]
        unknown = sorted(set(s) - KNOWN_KEYS)
        if unknown:   # most likely a typo that would otherwise be ignored silently
            log.warning("%s: ignoring unknown option(s): %s", path, ", ".join(unknown))
        missing = [k for k in ("realm", "broker_principal", "delegate_targets") if not s.get(k)]
        if missing:
            raise ValueError(f"{path}: required option(s) missing: {', '.join(missing)}")

        def dur(key: str, default: str) -> int:
            try:
                return duration_seconds(s.get(key, default))
            except ValueError as e:
                raise ValueError(f"{path}: {key}: {e}") from None

        realm = s.get("realm")
        targets = [t for t in s.get("delegate_targets", "").replace(",", " ").split()]
        # Qualify any bare SPN with the realm so AD/auth all agree on the name.
        targets = [t if "@" in t else f"{t}@{realm}" for t in targets]
        targets = list(dict.fromkeys(targets))          # drop duplicates, keep order
        if not targets:
            raise ValueError(f"{path}: delegate_targets lists no services")
        disable_file = Path(s.get("disable_file", "/etc/krb-hpc/disabled"))
        if not disable_file.is_absolute():
            raise ValueError(f"{path}: disable_file must be an absolute path")
        checks = s.get("ticket_checks", "enforce").strip().lower()
        if checks not in ("enforce", "warn"):
            raise ValueError(f"{path}: ticket_checks must be 'enforce' or 'warn', not {checks!r}")
        return Config(
            realm=realm,
            krb5_conf=s.get("krb5_conf", "/etc/krb5.conf"),
            broker_principal=s.get("broker_principal"),
            broker_keytab=Path(s.get("broker_keytab", "/etc/krb-hpc/broker.keytab")),
            broker_ccache=Path(s.get("broker_ccache", "/var/lib/krb-hpc/broker.cc")),
            delegate_targets=targets,
            state_dir=Path(s.get("state_dir", "/var/lib/krb-hpc/ccache")),
            map_file=Path(s.get("map_file", "/etc/krb-hpc/uidmap.conf")),
            unix_socket=Path(s.get("unix_socket", "/run/krb-hpc/credd.sock")),
            ccache_path=s.get("ccache_path", "{home}/.krb5/krb5cc_hpc"),
            install_helper=s.get("install_helper",
                                 "/usr/local/libexec/krb-hpc/krb-install-ccache"),
            setpriv=s.get("setpriv", "/usr/bin/setpriv"),
            broker_lifetime=s.get("broker_lifetime", "10h"),
            broker_renew=s.get("broker_renew", "7d"),
            renew_margin_s=dur("renew_margin", "1h"),
            refresh_interval_s=dur("refresh_interval", "5m"),
            active_window_s=dur("active_window", "7d"),
            watch_slurm=s.getboolean("watch_slurm", True),
            squeue=s.get("squeue", "/usr/bin/squeue"),
            min_reissue_s=dur("min_reissue_interval", "10s"),
            tools={t: s.get(t, DEFAULT_TOOLS[t]) for t in DEFAULT_TOOLS},
            s4u_enterprise=_name_type(s.get("s4u_name_type", "enterprise")),
            refresh_workers=max(1, s.getint("refresh_workers", 4)),
            min_uid=s.getint("min_uid", _login_defs_uid_min()),
            disable_file=disable_file,
            failure_cooldown_s=dur("failure_cooldown", "60s"),
            ticket_checks_enforce=(checks == "enforce"),
        )


KNOWN_KEYS = frozenset({
    "realm", "krb5_conf", "broker_principal", "broker_keytab", "broker_ccache",
    "delegate_targets", "state_dir", "map_file", "unix_socket", "ccache_path",
    "install_helper", "setpriv", "broker_lifetime", "broker_renew", "renew_margin",
    "min_reissue_interval", "refresh_interval", "refresh_workers", "active_window",
    "watch_slurm", "squeue", "s4u_name_type", "min_uid", "disable_file",
    "failure_cooldown", "ticket_checks", *DEFAULT_TOOLS,
})

# Failures worth remembering for failure_cooldown: ones only an admin can fix.
# Transient errors (KDC unreachable, timeout) are always retried at once.
COOLDOWN_CATEGORIES = frozenset({"not_delegable", "unknown_principal", "bad_ticket"})


def _login_defs_uid_min(path: str = "/etc/login.defs") -> int:
    """Default min_uid: the system's own first regular-user UID (UID_MIN in
    /etc/login.defs; 1000 on current distributions, 500 on some older ones)."""
    try:
        with open(path) as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "UID_MIN" and parts[1].isdigit():
                    return int(parts[1])
    except OSError:
        pass
    return 1000


def _name_type(value: str) -> bool:
    v = value.strip().lower()
    if v not in ("enterprise", "principal"):
        raise ValueError(f"s4u_name_type must be 'enterprise' or 'principal', not {value!r}")
    return v == "enterprise"


class UidMap:
    """uidmap.conf: '<username-or-uid>  <REAL AD user principal>'.

    With constrained delegation the daemon impersonates the user's own AD
    identity (e.g. jdoe@CORP.EXAMPLE.MIL), so the right-hand column is the
    user's real sAMAccountName -- NOT an hpc-<user> shadow account. A UPN also
    works when the Linux name equals the sAMAccountName (AD puts the
    sAMAccountName in the tickets); write a user of another domain as
    name@THAT.REALM. The account must be delegation-eligible (not in Protected Users, not flagged
    'sensitive -- cannot be delegated').

    Re-read on mtime change (enrollment needs no restart). Rejected unless the
    file is root-owned and not group/world writable."""

    def __init__(self, path: Path, realm: str):
        self.path, self.realm = path, realm
        self._mtime = -1.0
        self._map: dict[int, str] = {}
        self._lock = threading.Lock()

    def principal(self, uid: int) -> str | None:
        with self._lock:
            st = self.path.lstat()
            if st.st_mtime != self._mtime:
                # Same checks as every other trusted file, including "not a
                # symlink" (stat() would have followed one).
                _assert_secure(self.path, is_dir=False, label="map_file")
                m: dict[int, str] = {}
                for line in self.path.read_text().splitlines():
                    line = line.split("#", 1)[0].strip()
                    if not line:
                        continue
                    who, princ = line.split()[:2]
                    try:
                        u = int(who) if who.isdigit() else pwd.getpwnam(who).pw_uid
                    except KeyError:
                        log.warning("uidmap: unknown user %s", who)
                        continue
                    # Store the principal as written. For S4U2Self the KDC
                    # resolves a bare name in the default realm (same-realm AD);
                    # a cross-realm user is written fully-qualified (user@OTHER).
                    m[u] = princ
                self._map, self._mtime = m, st.st_mtime
                log.info("uid map loaded: %d entries", len(m))
            return self._map.get(uid)


class TicketManager:
    def __init__(self, cfg: Config, uidmap: UidMap):
        self.cfg, self.map = cfg, uidmap
        # Kerberos tools run by absolute path; each must be root-owned and not
        # writable by others (checked on the resolved file, so a root-owned
        # distro symlink such as an alternatives link is fine).
        tools = {}
        for name, path in cfg.tools.items():
            real = Path(os.path.realpath(path))
            _assert_secure(real, is_dir=False, label=name)
            tools[name] = str(real)
        self.krb = Krb5(cfg.krb5_conf, tools=tools, s4u_enterprise=cfg.s4u_enterprise)
        self._locks: dict[int, threading.Lock] = {}
        self._glock = threading.Lock()
        self._broker_lock = threading.Lock()
        self._active: dict[int, float] = {}
        self._active_lock = threading.Lock()
        self._last_install: dict[int, float] = {}
        self._failures: dict[int, tuple[int, float]] = {}   # uid -> (count, retry_at)
        self._fail_lock = threading.Lock()
        # Last failed mint per uid: (time, error). Any request inside
        # failure_cooldown gets the same error without another KDC round trip.
        self._last_error: dict[int, tuple[float, Exception]] = {}
        self._warned_margin = False
        self._warned: dict[str, float] = {}  # validation warning -> last logged
        self._checked: dict[int, str] = {}   # uid -> principal its master cache passed for
        # The broker keytab is the single crown jewel: refuse to run unless it
        # is a root-owned, non-symlink, mode-0600 regular file.
        _assert_secure(cfg.broker_keytab, is_dir=False, label="broker_keytab",
                       strict=True)
        cfg.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(cfg.state_dir, 0o700)
        _assert_secure(cfg.state_dir, is_dir=True, label="state_dir")
        # The helper we exec under setpriv must itself be root-owned and
        # non-writable, or a local attacker who could edit it would run code
        # as any user. (setpriv is a trusted system binary; left as-is.)
        _assert_secure(Path(cfg.install_helper), is_dir=False, label="install_helper")
        # Only root may be able to create the kill-switch file: its directory
        # must pass the usual checks, and no ancestor may let others swap it
        # (root-owned, and not group/world writable unless sticky, like /tmp).
        _assert_secure(cfg.disable_file.parent, is_dir=True, label="disable_file directory")
        for anc in cfg.disable_file.parent.parents:
            st = anc.lstat()
            if st.st_uid != 0 or (st.st_mode & 0o022 and not st.st_mode & 0o1000):
                raise PermissionError(f"disable_file: {anc} must be root-owned and not "
                                      "writable by others (or sticky)")
        self._seed_active()

    def _seed_active(self) -> None:
        """After a restart, resume refreshing users who were active: every
        enrolled user with a master cache in state_dir (masters are deleted
        when a user goes idle). The file's mtime -- the last mint -- stands in
        for their last krb-get, so at worst they are retired a little early
        and come back on their next login."""
        for f in self.cfg.state_dir.glob("krb5cc_*"):
            uid = f.name[len("krb5cc_"):]
            if uid.isdigit():
                try:
                    self._active[int(uid)] = f.stat().st_mtime
                except OSError:
                    pass
        if self._active:
            log.info("resuming refresh for %d previously active user(s)", len(self._active))

    def master(self, uid: int) -> Path:
        return self.cfg.state_dir / f"krb5cc_{uid}"

    def home_ccache(self, pw: pwd.struct_passwd) -> Path:
        return Path(self.cfg.ccache_path.format(
            home=pw.pw_dir, uid=pw.pw_uid, user=pw.pw_name))

    def _ensure_broker(self) -> None:
        """Keep the broker's own TGT fresh -- this is the unattended-renewal
        engine. Renew while possible, otherwise re-kinit from the one keytab.
        Everything the daemon mints for users rides on this single credential."""
        with self._broker_lock:
            cc = self.cfg.broker_ccache
            t = self.krb.klist_times(str(cc))
            now = time.time()
            if t is not None and t.expires - now >= self.cfg.renew_margin_s:
                return  # still good
            if t is not None and t.renew_until - now > self.cfg.renew_margin_s \
                    and self.krb.kinit_renew(str(cc)):
                log.info("renewed broker TGT")
                return
            tmp = cc.with_suffix(".new")
            self.krb.kinit_keytab(self.cfg.broker_principal,
                                  str(self.cfg.broker_keytab), str(tmp),
                                  self.cfg.broker_lifetime, self.cfg.broker_renew)
            os.chmod(tmp, 0o600)
            os.replace(tmp, cc)
            log.info("acquired broker TGT principal=%s", self.cfg.broker_principal)

    def _validate(self, path: Path, principal: str, user: str):
        """Inspect a cache and apply validate_user_cache. Tickets may name the
        uidmap principal or the Linux user (AD returns the sAMAccountName,
        which by policy matches the Linux name, even when uidmap holds a UPN).
        ticket_checks=warn relaxes only the name checks (see
        validate_user_cache). Warnings are logged at most once a day each."""
        info = self.krb.inspect(str(path))
        warns = validate_user_cache(info, [principal, user], self.cfg.realm,
                                    self.cfg.delegate_targets, MIN_TICKET_VALID_S,
                                    strict=self.cfg.ticket_checks_enforce)
        now = time.time()
        for w in warns:
            if now - self._warned.get(w, 0.0) >= 86400:
                self._warned[w] = now
                log.warning("ticket check for %s: %s", principal, w)
        return info

    def _mint(self, principal: str, cc: Path, user: str | None = None) -> None:
        """Mint the user's service tickets via constrained delegation (no TGT)
        into `cc`, atomically. Relies on the broker TGT being fresh. The new
        cache is checked (right user, every delegation target, no TGT, AES
        session key, enough lifetime) BEFORE it replaces anything: a cache
        that fails is discarded and the previous one stays in place."""
        self._ensure_broker()
        tmp = cc.with_suffix(".new")
        try:
            self.krb.s4u_mint(str(self.cfg.broker_ccache), principal,
                              self.cfg.delegate_targets, str(tmp))
            os.chmod(tmp, 0o600)
            info = self._validate(tmp, principal, user or principal)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
        os.replace(tmp, cc)  # atomic
        life = min((t.expires for t in info.tickets), default=0) - time.time()
        if life < self.cfg.renew_margin_s and not self._warned_margin:
            self._warned_margin = True
            log.warning("tickets from AD last %ds, less than renew_margin (%ds): every "
                        "refresh pass will re-mint them; lower renew_margin",
                        int(life), self.cfg.renew_margin_s)

    def _install(self, pw: pwd.struct_passwd, src: Path) -> Path:
        """Copy the master ccache into the user's home, running AS THE USER
        with all capabilities dropped and a minimal, clean environment."""
        dest = self.home_ccache(pw)
        clean_env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": pw.pw_dir}
        r = subprocess.run(
            [self.cfg.setpriv, f"--reuid={pw.pw_uid}", f"--regid={pw.pw_gid}",
             "--init-groups", "--inh-caps=-all", "--bounding-set=-all",
             "--no-new-privs", self.cfg.install_helper, str(dest)],
            input=src.read_bytes(), capture_output=True, timeout=30, env=clean_env)
        if r.returncode != 0:
            raise RuntimeError(
                f"install into {dest} failed: {r.stderr.decode(errors='replace').strip()}")
        self._last_install[pw.pw_uid] = time.time()
        return dest

    def due_for_install(self, uid: int) -> bool:
        """Throttle: skip a fresh re-copy into $HOME if we installed very
        recently (bounds a krb-get spam / DoS from re-copying each call)."""
        last = self._last_install.get(uid, 0.0)
        return (time.time() - last) >= self.cfg.min_reissue_s

    def disabled(self) -> bool:
        """Kill switch: while this file exists nothing is minted or installed."""
        return self.cfg.disable_file.exists()

    def ensure(self, uid: int, force_install: bool = False) -> Path:
        if self.disabled():
            raise PermissionError("krb-credd is disabled by the HPC administrators")
        if uid < self.cfg.min_uid:
            raise PermissionError(f"uid {uid} is a system account (below min_uid "
                                  f"{self.cfg.min_uid}) and is never served")
        principal = self.map.principal(uid)
        if not principal:
            raise PermissionError(f"uid {uid} is not enrolled")
        pw = pwd.getpwuid(uid)
        cc = self.master(uid)
        with self._glock:
            lock = self._locks.setdefault(uid, threading.Lock())
        with lock:
            changed = False
            exp = self.krb.cache_expiry(str(cc))
            now = time.time()
            # Service tickets can't be "renewed" -- re-mint them when missing or
            # within the margin of the earliest expiry.
            need = exp is None or exp - now < self.cfg.renew_margin_s
            if not need and self._checked.get(uid) != principal:
                # First use since start-up of a master minted earlier (perhaps
                # by an older version): check it once; re-mint if it fails.
                try:
                    self._validate(cc, principal, pw.pw_name)
                    self._checked[uid] = principal
                except KrbToolError as e:
                    log.warning("existing cache for uid=%d failed validation, re-minting: %s", uid, e)
                    need = True
            if need:
                last = self._last_error.get(uid)
                if last is not None and now - last[0] < self.cfg.failure_cooldown_s:
                    e = last[1]         # same answer, no new request to AD
                    again = KrbToolError(e.tool, "unchanged since the last attempt",
                                         e.detail, e.category)
                    again.from_cooldown = True
                    raise again
                try:
                    self._mint(principal, cc, pw.pw_name)
                except KrbToolError as e:
                    if e.category in COOLDOWN_CATEGORIES:
                        self._last_error[uid] = (time.time(), e)
                    raise
                self._last_error.pop(uid, None)
                self._checked[uid] = principal
                changed = True
                log.info("minted service tickets uid=%d principal=%s", uid, principal)
            dest = self.home_ccache(pw)
            if changed or force_install or _missing(dest):
                dest = self._install(pw, cc)
            self._clear_failure(uid)
            return dest

    def status(self, uid: int) -> dict:
        """What `krb-get --status` reports: never mints, never contacts AD."""
        st = {"disabled": self.disabled()}
        try:
            st["enrolled"] = uid >= self.cfg.min_uid and bool(self.map.principal(uid))
        except Exception:
            st["enrolled"] = False
        exp = self.krb.cache_expiry(str(self.master(uid)))
        st["expires"] = int(exp) if exp else 0
        with self._fail_lock:
            f = self._failures.get(uid)
        st["retry_at"] = int(f[1]) if f and f[1] > time.time() else 0
        last = self._last_error.get(uid)
        if last is not None:
            cat = getattr(last[1], "category", "")  # only admin-fixable errors are kept
            st["last_error"] = USER_MESSAGES.get(cat, "could not obtain ticket")
            st["last_error_at"] = int(last[0])
        return st

    def touch(self, uid: int) -> None:
        with self._active_lock:
            self._active[uid] = time.time()

    # ---- failure backoff (background refresh only) ------------------------
    def _record_failure(self, uid: int, err: Exception) -> float:
        transient = getattr(err, "transient", True)
        first, cap = BACKOFF_TRANSIENT_S if transient else BACKOFF_PERMANENT_S
        with self._fail_lock:
            count = self._failures.get(uid, (0, 0.0))[0] + 1
            delay = min(cap, first * 2 ** (count - 1))
            self._failures[uid] = (count, time.time() + delay)
        return delay

    def _clear_failure(self, uid: int) -> None:
        with self._fail_lock:
            self._failures.pop(uid, None)

    def _backing_off(self, uid: int) -> bool:
        with self._fail_lock:
            f = self._failures.get(uid)
        return f is not None and time.time() < f[1]

    def _enrolled(self, uid: int) -> bool:
        try:
            return bool(self.map.principal(uid))
        except Exception as e:
            log.error("cannot read %s: %s", self.cfg.map_file, e)
            return False

    def _refresh_one(self, uid: int) -> None:
        if self._backing_off(uid):
            return
        try:
            self.ensure(uid)
        except Exception as e:
            if getattr(e, "from_cooldown", False):
                return          # no new attempt was made; don't grow the backoff
            delay = self._record_failure(uid, e)
            cat = getattr(e, "category", type(e).__name__)
            log.error("refresh uid=%d failed (%s; next try in %ds): %s", uid, cat, delay, e)

    def _slurm_uids(self) -> set[int]:
        try:
            r = subprocess.run(
                [self.cfg.squeue, "-h", "-a", "-t", "PD,CF,R,CG", "-o", "%U"],
                capture_output=True, text=True, timeout=30)
            if r.returncode != 0:
                log.warning("squeue exited %d: %s", r.returncode, r.stderr.strip())
                return set()
            return {int(x) for x in r.stdout.split() if x.isdigit()}
        except Exception as e:
            log.warning("squeue failed: %s", e)
            return set()

    def refresh_pass(self, pool: ThreadPoolExecutor) -> None:
        horizon = time.time() - self.cfg.active_window_s
        with self._active_lock:
            idle = [uid for uid, ts in self._active.items() if ts < horizon]
            for uid in idle:
                del self._active[uid]
            uids = set(self._active)
        for uid in idle:
            self.master(uid).unlink(missing_ok=True)
            self.krb.forget(str(self.master(uid)))
            self._clear_failure(uid)
            self._last_error.pop(uid, None)
            self._checked.pop(uid, None)
            with self._glock:
                self._locks.pop(uid, None)
            self._last_install.pop(uid, None)
            log.info("retired idle master ccache uid=%d", uid)
        if self.cfg.watch_slurm:
            uids |= self._slurm_uids()
        uids = {u for u in uids if u >= self.cfg.min_uid and self._enrolled(u)}
        if not uids:
            return
        if self.disabled():
            log.warning("disabled by %s: skipping refresh of %d user(s)",
                        self.cfg.disable_file, len(uids))
            return
        # Refresh the broker TGT once up front: if it can't be obtained, every
        # user would fail the same way, so log it once and skip this pass.
        try:
            self._ensure_broker()
        except Exception as e:
            log.error("broker TGT unavailable, skipping refresh of %d user(s): %s", len(uids), e)
            return
        # Users are refreshed in parallel (per-user locks keep each user's
        # mint/install serialized), so one slow KDC answer doesn't hold up
        # everyone else. list() waits for the whole pass to finish.
        list(pool.map(self._refresh_one, sorted(uids)))

    def refresh_loop(self, stop: threading.Event) -> None:
        with ThreadPoolExecutor(max_workers=self.cfg.refresh_workers,
                                thread_name_prefix="refresh") as pool:
            while True:   # first pass right away, then every refresh_interval
                try:
                    self.refresh_pass(pool)
                except Exception as e:     # never let the refresh thread die
                    log.exception("refresh pass failed: %s", e)
                if stop.wait(self.cfg.refresh_interval_s):
                    return


def _missing(path: Path) -> bool:
    """True only if the user's cache is known to be gone (e.g. deleted by the
    user), so the background refresh puts it back. If root can't look
    (root-squashed NFS), assume it is still there."""
    try:
        os.stat(path)
        return False
    except FileNotFoundError:
        return True
    except OSError:
        return False


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        tm: TicketManager = self.server.tm
        sem: threading.BoundedSemaphore = self.server.sem
        try:
            self.request.settimeout(CLIENT_TIMEOUT_S)
        except OSError:
            pass
        # Bound concurrent work; shed load rather than fork-bomb under abuse.
        if not sem.acquire(timeout=CLIENT_TIMEOUT_S):
            try:
                self.wfile.write(b"ERR busy\n")
            except OSError:
                pass
            return
        try:
            creds = self.request.getsockopt(
                socket.SOL_SOCKET, SO_PEERCRED, struct.calcsize("3i"))
            _pid, uid, _gid = struct.unpack("3i", creds)
            try:
                req = self.rfile.readline(256).decode("ascii", "replace").strip()
                if req == "STATUS":
                    st = tm.status(uid)
                    self.wfile.write(("OK " + " ".join(
                        f"{k}={str(v).replace(' ', '_')}" for k, v in st.items()) + "\n").encode())
                    return
                if req != "GET":
                    raise ValueError("unsupported request")
                # Always ensure validity; only re-copy into $HOME when due
                # (throttle) or when the ticket actually changed.
                path = tm.ensure(uid, force_install=tm.due_for_install(uid))
                tm.touch(uid)
                self.wfile.write(f"OK {path}\n".encode())
                log.info("issued tickets uid=%d -> %s", uid, path)
            except PermissionError as e:
                self.wfile.write(f"ERR {e}\n".encode())
                log.warning("denied uid=%d: %s", uid, e)
            except KrbToolError as e:
                msg = USER_MESSAGES.get(e.category, "could not obtain ticket")
                self.wfile.write(f"ERR {msg}\n".encode())
                log.error("failed uid=%d (%s): %s", uid, e.category, e)
            except Exception as e:
                self.wfile.write(b"ERR could not obtain ticket\n")
                log.error("failed uid=%d: %s", uid, e)
        finally:
            sem.release()


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    # Reap threads promptly; cap concurrent handlers via the semaphore below.
    block_on_close = False


def check(cfg_path: str, user: str | None) -> int:
    """`krb-credd --check [--user NAME]`: validate a deployment without
    starting the daemon or touching anyone's home directory. Each step prints
    PASS/FAIL with the reason; exit status 1 if anything failed."""
    failed = 0

    def step(label, fn):
        nonlocal failed
        try:
            detail = fn()
            print(f"PASS  {label}" + (f": {detail}" if detail else ""))
            return True
        except Exception as e:
            failed += 1
            print(f"FAIL  {label}: {e}")
            return False

    box = {}
    if not step("config " + cfg_path, lambda: box.setdefault("cfg", Config.load(cfg_path)) and None):
        return 1
    cfg = box["cfg"]
    if not step("trusted files and tools (keytab 0600, state dir, helper, kinit/klist/kvno)",
                lambda: box.setdefault("tm", TicketManager(cfg, UidMap(cfg.map_file, cfg.realm))) and None):
        return 1
    tm = box["tm"]
    step("MIT Kerberos version", lambda: ".".join(map(str, tm.krb.version())))

    def kill_switch():
        if tm.disabled():
            raise RuntimeError(f"{cfg.disable_file} exists: nothing will be minted "
                               "until it is removed")
        return f"off ({cfg.disable_file} absent)"
    step("kill switch", kill_switch)
    def uid_map():
        tm.map.principal(-1)
        low = sorted(u for u in tm.map._map if u < cfg.min_uid)
        if low:
            raise PermissionError(f"enrolled uid(s) {', '.join(map(str, low))} are below "
                                  f"min_uid {cfg.min_uid} and will be refused")
        return f"{len(tm.map._map)} enrolled; min_uid {cfg.min_uid}"
    step(f"uid map {cfg.map_file}", uid_map)

    def broker():
        tm._ensure_broker()
        t = tm.krb.klist_times(str(cfg.broker_ccache))
        return f"{cfg.broker_principal}, expires {time.ctime(t.expires)}" if t else "no TGT in cache"
    broker_ok = step("broker TGT from keytab", broker)

    if cfg.watch_slurm:
        def slurm():
            r = subprocess.run([cfg.squeue, "-h", "-o", "%U"], capture_output=True, text=True, timeout=30)
            if r.returncode != 0:
                raise RuntimeError(r.stderr.strip() or f"exit {r.returncode}")
            return f"{len(set(r.stdout.split()))} user(s) with jobs"
        step(f"squeue ({cfg.squeue})", slurm)

    if user and broker_ok and tm.disabled():
        def skipped():
            raise RuntimeError("skipped: the kill switch is on (no request sent to AD)")
        step(f"constrained delegation for {user}", skipped)
    elif user and broker_ok:
        def mint():
            pw = pwd.getpwnam(user)
            if pw.pw_uid < cfg.min_uid:
                raise PermissionError(f"{user} (uid {pw.pw_uid}) is below min_uid {cfg.min_uid}")
            principal = tm.map.principal(pw.pw_uid)
            if not principal:
                raise PermissionError(f"{user} (uid {pw.pw_uid}) is not in {cfg.map_file}")
            out = cfg.state_dir / f".check.{pw.pw_uid}.cc"
            try:
                tm._mint(principal, out, user)    # includes the cache validation
                exp = tm.krb.cache_expiry(str(out))
            finally:
                out.unlink(missing_ok=True)
                tm.krb.forget(str(out))
            return (f"{principal} -> {', '.join(cfg.delegate_targets)}; validated; "
                    f"expires {time.ctime(exp) if exp else '?'} (not installed)")
        step(f"constrained delegation for {user}", mint)
    print("all checks passed" if not failed else f"{failed} check(s) failed")
    return 1 if failed else 0


def _harden_process() -> None:
    """No core dumps and no ptrace/proc access by other non-root processes:
    the daemon handles every user's tickets in memory. (Child processes reset
    'dumpable' on exec; the systemd unit also sets LimitCORE=0.)"""
    import resource
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, OSError) as e:
        log.warning("could not disable core dumps: %s", e)
    try:
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        PR_SET_DUMPABLE = 4
        if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "prctl(PR_SET_DUMPABLE) failed")
    except (OSError, AttributeError) as e:
        log.warning("could not mark the process non-dumpable: %s", e)


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="krb-credd")
    ap.add_argument("-c", "--config", default="/etc/krb-hpc/credd.conf")
    ap.add_argument("--check", action="store_true",
                    help="validate the configuration, tools, keytab and broker TGT, then exit")
    ap.add_argument("--user", metavar="NAME",
                    help="with --check: also mint (but not install) this user's tickets")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    if os.geteuid() != 0:
        raise SystemExit("krb-credd must run as root")
    os.umask(0o077)
    _harden_process()
    if args.check:
        raise SystemExit(check(args.config, args.user))
    # Configuration and file-permission problems are reported as one clear
    # line rather than a traceback.
    try:
        cfg = Config.load(args.config)
        tm = TicketManager(cfg, UidMap(cfg.map_file, cfg.realm))
        # Fail fast on tools that can't do the job (not MIT, or older than
        # 1.19, which lacks `kvno --out-cache`).
        version = tm.krb.version()
    except (OSError, ValueError, RuntimeError, KeyError) as e:
        raise SystemExit(f"krb-credd: {e}")
    try:
        tm.map.principal(-1)
        low = sorted(u for u in tm.map._map if u < cfg.min_uid)
        if low:
            log.warning("enrolled uid(s) %s are below min_uid %d and will be refused",
                        ", ".join(map(str, low)), cfg.min_uid)
    except Exception:
        pass
    log.info("MIT Kerberos %s tools: %s", ".".join(map(str, version)),
             ", ".join(f"{k}={v}" for k, v in tm.krb.tools.items()))
    # Acquire the broker TGT up front so a bad keytab/principal shows up in the
    # log at once; a transient KDC hiccup is non-fatal (the refresh loop and
    # first request retry).
    try:
        tm._ensure_broker()
    except Exception as e:
        log.warning("initial broker TGT acquisition failed (will retry): %s", e)
    cfg.unix_socket.parent.mkdir(parents=True, exist_ok=True)
    cfg.unix_socket.unlink(missing_ok=True)
    srv = Server(str(cfg.unix_socket), Handler)
    os.chmod(cfg.unix_socket, 0o666)  # anyone may connect; SO_PEERCRED decides whose ticket
    srv.tm = tm
    srv.sem = threading.BoundedSemaphore(MAX_CLIENTS)
    stop = threading.Event()
    threading.Thread(target=tm.refresh_loop, args=(stop,), daemon=True, name="refresh").start()
    log.info("listening on %s (shared-home S4U; broker=%s; targets=%s; "
             "refresh %ds x%d workers; slurm-watch=%s; s4u=%s)", cfg.unix_socket,
             cfg.broker_principal, ",".join(cfg.delegate_targets),
             cfg.refresh_interval_s, cfg.refresh_workers, cfg.watch_slurm,
             "enterprise" if cfg.s4u_enterprise else "principal")
    try:
        srv.serve_forever()
    finally:
        stop.set()


if __name__ == "__main__":
    main()
