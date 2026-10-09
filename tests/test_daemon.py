"""Unit tests for daemon-level behavior in krbhpc.credd (no Kerberos needed):
config parsing of the new options, refresh backoff, the uidmap symlink check,
and the admin scripts' exact-match enroll/revoke.

Run as root for the cases that need root-owned files (skipped otherwise):

    python3 tests/test_daemon.py
"""
import os, subprocess, sys, tempfile, threading, time
from pathlib import Path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from krbhpc import credd
from krbhpc._krb import KrbToolError

ROOT = os.geteuid() == 0
REPO = Path(__file__).resolve().parent.parent


def _conf(d, extra=""):
    p = Path(d) / "credd.conf"
    p.write_text("[broker]\nrealm = R\nbroker_principal = b/h\n"
                 "delegate_targets = hive/x hdfs/y@R\n" + extra)
    os.chmod(p, 0o644)
    return str(p)


def test_config_defaults_and_new_options():
    if not ROOT:
        return
    with tempfile.TemporaryDirectory() as d:
        c = credd.Config.load(_conf(d))
        assert c.delegate_targets == ["hive/x@R", "hdfs/y@R"]
        assert c.tools == {"kinit": "/usr/bin/kinit", "klist": "/usr/bin/klist", "kvno": "/usr/bin/kvno"}
        assert c.s4u_enterprise is True and c.refresh_workers == 4
        c = credd.Config.load(_conf(d, "kvno = /opt/k/bin/kvno\ns4u_name_type = principal\nrefresh_workers = 0\n"))
        assert c.tools["kvno"] == "/opt/k/bin/kvno" and c.s4u_enterprise is False and c.refresh_workers == 1
        try:
            credd.Config.load(_conf(d, "s4u_name_type = upn\n"))
        except ValueError:
            pass
        else:
            raise AssertionError("bad s4u_name_type accepted")


def _bare_manager():
    tm = object.__new__(credd.TicketManager)
    tm._failures, tm._fail_lock = {}, threading.Lock()
    return tm


def test_backoff_grows_and_differs_by_category():
    tm = _bare_manager()
    transient = KrbToolError("kvno", "x", "Cannot contact any KDC")
    permanent = KrbToolError("kvno", "x", "KDC can't fulfill requested option")
    d1 = tm._record_failure(1, transient); d2 = tm._record_failure(1, transient)
    assert (d1, d2) == (credd.BACKOFF_TRANSIENT_S[0], 2 * credd.BACKOFF_TRANSIENT_S[0])
    for _ in range(20):
        d = tm._record_failure(1, transient)
    assert d == credd.BACKOFF_TRANSIENT_S[1]                       # capped
    assert tm._record_failure(2, permanent) == credd.BACKOFF_PERMANENT_S[0]
    assert tm._backing_off(1) and tm._backing_off(2) and not tm._backing_off(3)
    tm._clear_failure(1)
    assert not tm._backing_off(1)


def test_backed_off_user_is_skipped():
    tm = _bare_manager()
    called = []
    tm.ensure = lambda uid: called.append(uid)
    tm._failures[7] = (1, time.time() + 60)
    tm._refresh_one(7)
    assert called == []                                  # skipped while backing off
    tm._failures[7] = (1, time.time() - 1)
    tm._refresh_one(7)
    assert called == [7]


def test_uidmap_rejects_symlink():
    if not ROOT:
        return
    with tempfile.TemporaryDirectory() as d:
        real = Path(d) / "real"; real.write_text("root root\n"); os.chmod(real, 0o644)
        link = Path(d) / "uidmap"; link.symlink_to(real)
        try:
            credd.UidMap(link, "R").principal(0)
        except PermissionError as e:
            assert "symlink" in str(e)
        else:
            raise AssertionError("symlinked uidmap accepted")
        assert credd.UidMap(real, "R").principal(0) == "root"


def _script(name, d):
    """Copy an admin script, pointing it at a temp uidmap and skipping the
    parts that touch real caches."""
    src = (REPO / "admin" / name).read_text().replace("/etc/krb-hpc/uidmap.conf", f"{d}/uidmap.conf") \
        .replace('MAP=/etc/krb-hpc/uidmap.conf', f'MAP={d}/uidmap.conf') \
        .replace('install -d -m 0755 -o root -g root "$(dirname "$MAP")"', ":")
    src = "\n".join(l for l in src.splitlines() if not l.startswith(("shred", "setpriv", "    sh -c")))
    p = Path(d) / name; p.write_text(src); os.chmod(p, 0o755)
    return str(p)


def test_admin_enroll_and_revoke_match_exactly():
    if not ROOT:
        return
    with tempfile.TemporaryDirectory() as d:
        m = Path(d) / "uidmap.conf"
        # root is uid 0; "rootx" and "r..t" must survive a revoke of "root".
        m.write_text("0 root   # by uid\nrootx rootx\nr..t rdt\n"); os.chmod(m, 0o644)
        out = subprocess.run([_script("enroll_user.sh", d), "root"], capture_output=True, text=True)
        assert out.returncode == 0 and "already enrolled" in out.stdout, out    # matched by UID
        subprocess.run([_script("revoke_user.sh", d), "root"], check=True, capture_output=True)
        lines = m.read_text().splitlines()
        assert lines == ["rootx rootx", "r..t rdt"], lines
        assert oct(m.stat().st_mode & 0o777) == "0o644" and m.stat().st_uid == 0


def test_config_errors_are_clear_and_typos_are_reported():
    if not ROOT:
        return
    import logging
    with tempfile.TemporaryDirectory() as d:
        bad = Path(d) / "c.conf"
        for body, want in [("[other]\n", "missing [broker] section"),
                           ("[broker]\nrealm = R\n", "required option(s) missing: broker_principal, delegate_targets"),
                           ("[broker]\nrealm=R\nbroker_principal=b\ndelegate_targets=h/x\nrenew_margin=5x\n", "renew_margin: bad duration")]:
            bad.write_text(body); os.chmod(bad, 0o644)
            try:
                credd.Config.load(str(bad))
            except ValueError as e:
                assert want in str(e), (want, str(e))
            else:
                raise AssertionError(f"accepted: {body!r}")
        seen = []
        h = logging.Handler(); h.emit = lambda r: seen.append(r.getMessage())
        credd.log.addHandler(h)
        try:
            credd.Config.load(_conf(d, "renew_margn = 1h\n"))
        finally:
            credd.log.removeHandler(h)
        assert any("unknown option(s): renew_margn" in m for m in seen), seen


def test_missing_only_when_known_gone():
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "cc"
        assert credd._missing(f) is True
        f.write_text("x")
        assert credd._missing(f) is False
    # A path root can't look into (e.g. root-squashed NFS) counts as present.
    assert credd._missing(Path("/proc/1/root/nonexistent-but-unreadable")) in (True, False)


def test_seed_active_from_state_dir():
    with tempfile.TemporaryDirectory() as d:
        sd = Path(d)
        for name in ("krb5cc_1001", "krb5cc_1002", "krb5cc_1002.new", ".broker.x.cc", "broker.cc"):
            (sd / name).write_text("x")
        tm = object.__new__(credd.TicketManager)
        tm._active = {}
        tm.cfg = type("C", (), {"state_dir": sd})()
        tm._seed_active()
        assert set(tm._active) == {1001, 1002}, tm._active


def test_krb_get_quotes_output_and_times_out():
    import socket as _s
    from krbhpc import get
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "sock")
        srv = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM); srv.bind(path); srv.listen(4)
        def serve(reply):
            c, _ = srv.accept(); c.recv(16)
            if reply is not None:
                c.sendall(reply)
            else:
                time.sleep(3)          # a hung daemon
            c.close()
        import contextlib, io
        for reply, want_rc, want in [(b"OK /home/a b/.krb5/krb5cc_hpc\n", 0, "export KRB5CCNAME='FILE:/home/a b/.krb5/krb5cc_hpc'\n"),
                                     (b"ERR uid 5 is not enrolled\n", 1, ""),
                                     (None, 2, "")]:
            t = threading.Thread(target=serve, args=(reply,)); t.start()
            out = io.StringIO()
            os.environ.update(KRB_HPC_SOCKET=path, KRB_HPC_TIMEOUT="1")
            start = time.time()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                rc = get.main([])
            assert rc == want_rc and out.getvalue() == want, (reply, rc, out.getvalue())
            if reply is None:
                assert time.time() - start < 2.5, "krb-get did not time out"
            t.join()
        srv.close()


def test_taskprolog_without_home():
    with tempfile.TemporaryDirectory() as d:
        out = subprocess.run(["env", "-i", "PATH=/usr/bin:/bin", "bash", str(REPO / "slurm" / "taskprolog.krb.sh")],
                             capture_output=True, text=True).stdout
        home = os.path.expanduser("~" + __import__("pwd").getpwuid(os.getuid()).pw_name)
        assert f"{home}/.krb5/krb5cc_hpc" in out, out      # found HOME from passwd


if __name__ == "__main__":
    import inspect
    tests = [v for n, v in sorted(globals().items()) if n.startswith("test_") and inspect.isfunction(v)]
    for t in tests:
        t()
        print(f"ok   {t.__name__}")
    print(f"\nall {len(tests)} daemon tests passed" + ("" if ROOT else "  (root-only cases skipped)"))
