#!/usr/bin/env python3
"""
krb-credd -- Kerberos credential daemon for a CAC / UID-GID HPC cluster
(shared-home design, pure Python).

Users reach the HPC with a CAC, which cannot be used through GSSAPI/PKINIT to
get a TGT. This root daemon obtains each enrolled user's Active Directory TGT
from an escrowed per-user keytab and writes it into the user's home directory
on the shared filesystem:

    {home}/.krb5/krb5cc_hpc

Because home is mounted on every compute node, the ticket is already present
cluster-wide; a one-line Slurm TaskProlog points KRB5CCNAME at it. There is no
SPANK plugin, no KCM, and no node-side daemon.

The daemon keeps every "active" user's ticket fresh -- renewing before expiry,
re-acquiring from the keytab past the renew limit. A user is active for
`active_window` after a `krb-get`, and for as long as they have a pending or
running Slurm job (squeue), so a job that waits in the queue or runs for days
never finds an expired ticket.

Front door: a UNIX-domain socket. The caller's UID comes from the kernel
(SO_PEERCRED), never from the request, so a user can only ever obtain their own
ticket, and only if enrolled.

Dependencies: python3 stdlib, MIT krb5 client tools (kinit, klist),
util-linux setpriv, and the Slurm client (squeue) when watch_slurm is on.
Unlike the Java edition, nothing here serializes ccaches by hand -- MIT kinit
writes a native FILE cache directly.
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


@dataclass
class Config:
    realm: str
    krb5_conf: str
    keytab_dir: Path
    state_dir: Path
    map_file: Path
    unix_socket: Path
    ccache_path: str          # tokens: {home} {uid} {user}
    install_helper: str
    setpriv: str
    ticket_lifetime: str
    renew_lifetime: str
    renew_margin_s: int
    refresh_interval_s: int
    active_window_s: int
    watch_slurm: bool
    squeue: str

    @staticmethod
    def load(path: str) -> "Config":
        cp = configparser.ConfigParser(inline_comment_prefixes=(";", "#"))
        cp.read(path)
        s = cp["broker"]
        return Config(
            realm=s.get("realm"),
            krb5_conf=s.get("krb5_conf", "/etc/krb5.conf"),
            keytab_dir=Path(s.get("keytab_dir", "/etc/krb-hpc/keytabs")),
            state_dir=Path(s.get("state_dir", "/var/lib/krb-hpc/ccache")),
            map_file=Path(s.get("map_file", "/etc/krb-hpc/uidmap.conf")),
            unix_socket=Path(s.get("unix_socket", "/run/krb-hpc/credd.sock")),
            ccache_path=s.get("ccache_path", "{home}/.krb5/krb5cc_hpc"),
            install_helper=s.get("install_helper",
                                 "/usr/local/libexec/krb-hpc/krb-install-ccache"),
            setpriv=s.get("setpriv", "/usr/bin/setpriv"),
            ticket_lifetime=s.get("ticket_lifetime", "10h"),
            renew_lifetime=s.get("renew_lifetime", "7d"),
            renew_margin_s=duration_seconds(s.get("renew_margin", "2h")),
            refresh_interval_s=duration_seconds(s.get("refresh_interval", "5m")),
            active_window_s=duration_seconds(s.get("active_window", "7d")),
            watch_slurm=s.getboolean("watch_slurm", True),
            squeue=s.get("squeue", "/usr/bin/squeue"),
        )


class UidMap:
    """uidmap.conf: '<username-or-uid>  <AD sAMAccountName or principal>'.
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
                    m[u] = princ if "@" in princ else f"{princ}@{self.realm}"
                self._map, self._mtime = m, st.st_mtime
                log.info("uid map loaded: %d entries", len(m))
            return self._map.get(uid)


class TicketManager:
    def __init__(self, cfg: Config, uidmap: UidMap):
        self.cfg, self.map = cfg, uidmap
        self.krb = Krb5(cfg.krb5_conf)
        self._locks: dict[int, threading.Lock] = {}
        self._glock = threading.Lock()
        self._active: dict[int, float] = {}
        cfg.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(cfg.state_dir, 0o700)

    def master(self, uid: int) -> Path:
        return self.cfg.state_dir / f"krb5cc_{uid}"

    def home_ccache(self, pw: pwd.struct_passwd) -> Path:
        return Path(self.cfg.ccache_path.format(
            home=pw.pw_dir, uid=pw.pw_uid, user=pw.pw_name))

    def keytab(self, principal: str) -> Path:
        safe = principal.split("@")[0].replace("/", "_")
        return self.cfg.keytab_dir / f"{safe}.keytab"

    def _acquire(self, principal: str, cc: Path) -> None:
        kt = self.keytab(principal)
        if not kt.exists():
            raise FileNotFoundError(f"no escrowed keytab for {principal}")
        tmp = cc.with_suffix(".new")
        self.krb.kinit_keytab(principal, str(kt), str(tmp),
                              self.cfg.ticket_lifetime, self.cfg.renew_lifetime)
        os.chmod(tmp, 0o600)
        os.replace(tmp, cc)  # atomic

    def _renew(self, cc: Path) -> bool:
        tmp = cc.with_suffix(".new")
        import shutil
        shutil.copy2(cc, tmp)
        if not self.krb.kinit_renew(str(tmp)):
            tmp.unlink(missing_ok=True)
            return False
        os.chmod(tmp, 0o600)
        os.replace(tmp, cc)
        return True

    def _install(self, pw: pwd.struct_passwd, src: Path) -> Path:
        """Copy the master ccache into the user's home, running AS THE USER."""
        dest = self.home_ccache(pw)
        r = subprocess.run(
            [self.cfg.setpriv, f"--reuid={pw.pw_uid}", f"--regid={pw.pw_gid}",
             "--init-groups", "--inh-caps=-all", "--bounding-set=-all",
             self.cfg.install_helper, str(dest)],
            input=src.read_bytes(), capture_output=True, timeout=30)
        if r.returncode != 0:
            raise RuntimeError(
                f"install into {dest} failed: {r.stderr.decode(errors='replace').strip()}")
        return dest

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
            t = self.krb.klist_times(str(cc))
            now = time.time()
            if t is None:
                self._acquire(principal, cc)
                changed = True
                log.info("acquired TGT uid=%d principal=%s", uid, principal)
            elif t.expires - now < self.cfg.renew_margin_s:
                if t.renew_until - now > self.cfg.renew_margin_s and self._renew(cc):
                    log.info("renewed TGT uid=%d", uid)
                else:
                    self._acquire(principal, cc)
                    log.info("re-acquired TGT uid=%d (past renew limit)", uid)
                changed = True
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
        creds = self.request.getsockopt(
            socket.SOL_SOCKET, SO_PEERCRED, struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", creds)
        try:
            req = self.rfile.readline(256).decode().strip()
            if req != "GET":
                raise ValueError("unsupported request")
            path = tm.ensure(uid, force_install=True)
            tm.touch(uid)
            self.wfile.write(f"OK {path}\n".encode())
            log.info("issued TGT uid=%d -> %s", uid, path)
        except PermissionError as e:
            self.wfile.write(f"ERR {e}\n".encode())
            log.warning("denied uid=%d: %s", uid, e)
        except Exception as e:
            self.wfile.write(b"ERR could not obtain ticket\n")
            log.error("failed uid=%d: %s", uid, e)


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


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
    stop = threading.Event()
    threading.Thread(target=tm.refresh_loop, args=(stop,), daemon=True).start()
    cfg.unix_socket.parent.mkdir(parents=True, exist_ok=True)
    cfg.unix_socket.unlink(missing_ok=True)
    srv = Server(str(cfg.unix_socket), Handler)
    os.chmod(cfg.unix_socket, 0o666)  # anyone may connect; SO_PEERCRED decides whose ticket
    srv.tm = tm
    log.info("listening on %s (shared-home; refresh %ds; slurm-watch=%s)",
             cfg.unix_socket, cfg.refresh_interval_s, cfg.watch_slurm)
    try:
        srv.serve_forever()
    finally:
        stop.set()


if __name__ == "__main__":
    main()
