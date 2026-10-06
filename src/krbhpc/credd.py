#!/usr/bin/env python3
"""
krb-credd -- Kerberos credential daemon for a CAC / UID-GID HPC cluster
(shared-home design, pure Python).

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

Dependencies: python3 stdlib, MIT krb5 client tools (kinit, klist, kvno),
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
from dataclasses import dataclass
from pathlib import Path

from ._krb import Krb5, duration_seconds

log = logging.getLogger("krb-credd")
SO_PEERCRED = getattr(socket, "SO_PEERCRED", 17)

# Hard caps to bound local denial-of-service on the UNIX socket.
MAX_CLIENTS = 32            # concurrent in-flight requests
CLIENT_TIMEOUT_S = 10       # per-connection socket timeout


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

    @staticmethod
    def load(path: str) -> "Config":
        # Refuse a config that an attacker could have tampered with.
        _assert_secure(Path(path), is_dir=False, label="config")
        cp = configparser.ConfigParser(inline_comment_prefixes=(";", "#"))
        cp.read(path)
        s = cp["broker"]
        realm = s.get("realm")
        targets = [t for t in s.get("delegate_targets", "").replace(",", " ").split()]
        if not targets:
            raise ValueError("delegate_targets must list at least one backend SPN")
        # Qualify any bare SPN with the realm so AD/auth all agree on the name.
        targets = [t if "@" in t else f"{t}@{realm}" for t in targets]
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
            renew_margin_s=duration_seconds(s.get("renew_margin", "1h")),
            refresh_interval_s=duration_seconds(s.get("refresh_interval", "5m")),
            active_window_s=duration_seconds(s.get("active_window", "7d")),
            watch_slurm=s.getboolean("watch_slurm", True),
            squeue=s.get("squeue", "/usr/bin/squeue"),
            min_reissue_s=duration_seconds(s.get("min_reissue_interval", "10s")),
        )


class UidMap:
    """uidmap.conf: '<username-or-uid>  <REAL AD user principal>'.

    With constrained delegation the daemon impersonates the user's own AD
    identity (e.g. jdoe@CORP.EXAMPLE.MIL), so the right-hand column is the
    user's real sAMAccountName/UPN -- NOT an hpc-<user> shadow account. The
    account must be delegation-eligible (not in Protected Users, not flagged
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
            st = self.path.stat()
            if st.st_mtime != self._mtime:
                if st.st_uid != 0 or st.st_mode & 0o022:
                    raise PermissionError(
                        f"{self.path} must be root-owned and not group/world writable")
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
        self.krb = Krb5(cfg.krb5_conf)
        self._locks: dict[int, threading.Lock] = {}
        self._glock = threading.Lock()
        self._broker_lock = threading.Lock()
        self._active: dict[int, float] = {}
        self._last_install: dict[int, float] = {}
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

    def _mint(self, principal: str, cc: Path) -> None:
        """Mint the user's service tickets via constrained delegation (no TGT)
        into `cc`, atomically. Relies on the broker TGT being fresh."""
        self._ensure_broker()
        tmp = cc.with_suffix(".new")
        self.krb.s4u_mint(str(self.cfg.broker_ccache), principal,
                          self.cfg.delegate_targets, str(tmp))
        os.chmod(tmp, 0o600)
        os.replace(tmp, cc)  # atomic

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

    def ensure(self, uid: int, force_install: bool = False) -> Path:
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
            if exp is None or exp - now < self.cfg.renew_margin_s:
                self._mint(principal, cc)
                changed = True
                log.info("minted service tickets uid=%d principal=%s", uid, principal)
            dest = self.home_ccache(pw)
            if changed or force_install:
                dest = self._install(pw, cc)
            return dest

    def touch(self, uid: int) -> None:
        self._active[uid] = time.time()

    def _slurm_uids(self) -> set[int]:
        try:
            r = subprocess.run(
                [self.cfg.squeue, "-h", "-a", "-t", "PD,CF,R,CG", "-o", "%U"],
                capture_output=True, text=True, timeout=30)
            return {int(x) for x in r.stdout.split() if x.isdigit()}
        except Exception as e:
            log.warning("squeue failed: %s", e)
            return set()

    def refresh_loop(self, stop: threading.Event) -> None:
        while not stop.wait(self.cfg.refresh_interval_s):
            horizon = time.time() - self.cfg.active_window_s
            for uid, ts in list(self._active.items()):
                if ts < horizon:
                    del self._active[uid]
                    self.master(uid).unlink(missing_ok=True)
                    log.info("retired idle master ccache uid=%d", uid)
            uids = set(self._active)
            if self.cfg.watch_slurm:
                uids |= self._slurm_uids()
            for uid in sorted(uids):
                try:
                    if self.map.principal(uid):
                        self.ensure(uid)
                except Exception as e:
                    log.error("refresh uid=%d: %s", uid, e)


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
            except Exception as e:
                self.wfile.write(b"ERR could not obtain ticket\n")
                log.error("failed uid=%d: %s", uid, e)
        finally:
            sem.release()


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    # Reap threads promptly; cap concurrent handlers via the semaphore below.
    block_on_close = False


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="krb-credd")
    ap.add_argument("-c", "--config", default="/etc/krb-hpc/credd.conf")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    if os.geteuid() != 0:
        raise SystemExit("krb-credd must run as root")
    os.umask(0o077)
    cfg = Config.load(args.config)
    tm = TicketManager(cfg, UidMap(cfg.map_file, cfg.realm))
    # Acquire the broker TGT up front so a bad keytab/principal fails fast; a
    # transient KDC hiccup is non-fatal (the refresh loop and first request
    # retry).
    try:
        tm._ensure_broker()
    except Exception as e:
        log.warning("initial broker kinit failed (will retry): %s", e)
    stop = threading.Event()
    threading.Thread(target=tm.refresh_loop, args=(stop,), daemon=True).start()
    cfg.unix_socket.parent.mkdir(parents=True, exist_ok=True)
    cfg.unix_socket.unlink(missing_ok=True)
    srv = Server(str(cfg.unix_socket), Handler)
    os.chmod(cfg.unix_socket, 0o666)  # anyone may connect; SO_PEERCRED decides whose ticket
    srv.tm = tm
    srv.sem = threading.BoundedSemaphore(MAX_CLIENTS)
    log.info("listening on %s (shared-home S4U; broker=%s; targets=%s; "
             "refresh %ds; slurm-watch=%s)", cfg.unix_socket,
             cfg.broker_principal, ",".join(cfg.delegate_targets),
             cfg.refresh_interval_s, cfg.watch_slurm)
    try:
        srv.serve_forever()
    finally:
        stop.set()


if __name__ == "__main__":
    main()
