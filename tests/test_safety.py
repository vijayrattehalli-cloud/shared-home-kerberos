"""Unit tests for the safety controls borrowed from CRAFT's design (no Kerberos
needed): validation of every minted cache before use, the kill switch, the
min_uid floor, the per-user failure cooldown, `krb-get --status`, and process
hardening (no core dumps, non-dumpable).

    python3 tests/test_safety.py      (root for the config case; skipped otherwise)
"""
import os, socket, subprocess, sys, tempfile, threading, time
from pathlib import Path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from krbhpc import credd
from krbhpc._krb import (CacheInfo, KrbToolError, Ticket, parse_klist_details,
                         validate_user_cache)

ROOT = os.geteuid() == 0
REALM = "TEST.LAB"
TARGETS = ["HTTP/svc01.test.lab@TEST.LAB", "hive/hs2.test.lab@TEST.LAB"]

# `klist -e -f` as MIT prints it under LC_ALL=C TZ=UTC0 (dates are relative to
# now so the lifetime check passes).
def _klist_text(principal="jdoe@TEST.LAB", services=TARGETS, etype="aes256-cts-hmac-sha1-96",
                hours=10, extra=""):
    start = time.strftime("%m/%d/%y %H:%M:%S", time.gmtime())
    end = time.strftime("%m/%d/%y %H:%M:%S", time.gmtime(time.time() + hours * 3600))
    lines = [f"Ticket cache: FILE:/tmp/x.cc", f"Default principal: {principal}", "",
             "Valid starting       Expires              Service principal"]
    for svc in services:
        lines += [f"{start}  {end}  {svc}", extra or None,
                  f"\tFlags: FA, Etype (skey, tkt): {etype}, {etype} "]
    return "\n".join(l for l in lines if l is not None) + "\n"


def _rejects(info, want):
    try:
        validate_user_cache(info, "jdoe", REALM, TARGETS, 300)
    except KrbToolError as e:
        assert e.category == "bad_ticket" and want in str(e), (want, str(e))
    else:
        raise AssertionError(f"accepted a cache that should fail: {want}")


def test_parse_and_accept_good_cache():
    info = parse_klist_details(_klist_text())
    assert info.default_principal == "jdoe@TEST.LAB"
    assert [t.server for t in info.tickets] == TARGETS
    assert info.tickets[0].skey_etype == info.tickets[0].tkt_etype == "aes256-cts-hmac-sha1-96"
    validate_user_cache(info, "jdoe", REALM, TARGETS, 300)            # bare name gets the realm
    validate_user_cache(info, "JDoe@test.lab", REALM, TARGETS, 300)   # case-insensitive


def test_rejects_wrong_or_extra_tickets():
    _rejects(parse_klist_details(_klist_text(principal="asmith@TEST.LAB")), "expected jdoe@TEST.LAB")
    _rejects(parse_klist_details(_klist_text(services=TARGETS + ["krbtgt/TEST.LAB@TEST.LAB"])),
             "ticket-granting ticket")
    _rejects(parse_klist_details(_klist_text(services=TARGETS[:1])), "expected")
    _rejects(parse_klist_details(_klist_text(services=TARGETS + ["cifs/fs.test.lab@TEST.LAB"])), "expected")
    _rejects(parse_klist_details(_klist_text(extra="\tfor client asmith@TEST.LAB")), "names client asmith")
    _rejects(CacheInfo(None, ()), "no default principal")


def test_rejects_weak_crypto_and_short_life():
    _rejects(parse_klist_details(_klist_text(etype="arcfour-hmac")), "only AES")
    _rejects(parse_klist_details(_klist_text(hours=0.01)), "minimum 300s")
    no_etype = CacheInfo("jdoe@TEST.LAB", tuple(Ticket(s, time.time() + 3600, None, None, None)
                                                for s in TARGETS))
    _rejects(no_etype, "no encryption type")


class _FakeKrb:
    def __init__(self, text, fail=None):
        self.text, self.fail, self.mints = text, fail, 0
    def s4u_mint(self, broker, principal, targets, out):
        self.mints += 1
        if self.fail:
            raise self.fail
        Path(out).write_text("new")
    def inspect(self, path):
        return parse_klist_details(self.text)
    def cache_expiry(self, path):
        return None


def _manager(d, krb, **cfg):
    tm = object.__new__(credd.TicketManager)
    base = dict(realm=REALM, delegate_targets=TARGETS, renew_margin_s=3600, min_uid=1000,
                disable_file=Path(d) / "disabled", failure_cooldown_s=60, broker_ccache=Path(d) / "b.cc",
                state_dir=Path(d))
    base.update(cfg)
    tm.cfg = type("C", (), base)()
    tm.krb, tm._warned_margin = krb, False
    tm._failures, tm._fail_lock, tm._last_error = {}, threading.Lock(), {}
    tm._ensure_broker = lambda: None
    return tm


def test_mint_discards_a_cache_that_fails_validation():
    with tempfile.TemporaryDirectory() as d:
        cc = Path(d) / "krb5cc_1001"; cc.write_text("old")
        tm = _manager(d, _FakeKrb(_klist_text(principal="asmith@TEST.LAB")))
        try:
            tm._mint("jdoe", cc)
        except KrbToolError as e:
            assert e.category == "bad_ticket"
        else:
            raise AssertionError("bad cache published")
        assert cc.read_text() == "old" and not cc.with_suffix(".new").exists()
        tm.krb = _FakeKrb(_klist_text())
        tm._mint("jdoe", cc)
        assert cc.read_text() == "new"


def test_kill_switch_min_uid_and_cooldown():
    with tempfile.TemporaryDirectory() as d:
        err = KrbToolError("kvno", "x", "KDC can't fulfill requested option")
        krb = _FakeKrb(_klist_text(), fail=err)
        tm = _manager(d, krb)
        tm.map = type("M", (), {"principal": lambda self, uid: "jdoe"})()
        tm._glock, tm._locks = threading.Lock(), {}
        tm.master = lambda uid: Path(d) / f"krb5cc_{uid}"
        import pwd
        me = pwd.getpwuid(os.getuid())
        orig = credd.pwd.getpwuid
        credd.pwd.getpwuid = lambda uid: me
        try:
            for _ in range(3):                                # cooldown: one KDC attempt, three answers
                try:
                    tm.ensure(5000)
                except KrbToolError as e:
                    assert e.category == "not_delegable"
            assert krb.mints == 1, krb.mints
            tm._last_error[5000] = (time.time() - 61, err)    # cooldown over: tries again
            try:
                tm.ensure(5000)
            except KrbToolError:
                pass
            assert krb.mints == 2
            st = tm.status(5000)
            assert st["enrolled"] and "cannot be delegated" in st["last_error"] and st["expires"] == 0
            try:
                tm.ensure(999)
            except PermissionError as e:
                assert "system account" in str(e)
            else:
                raise AssertionError("uid below min_uid served")
            (Path(d) / "disabled").touch()
            try:
                tm.ensure(5000)
            except PermissionError as e:
                assert "disabled" in str(e)
            else:
                raise AssertionError("kill switch ignored")
            assert krb.mints == 2 and tm.status(5000)["disabled"] is True
        finally:
            credd.pwd.getpwuid = orig


def test_config_safety_options():
    if not ROOT:
        return
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "c.conf"
        p.write_text("[broker]\nrealm=R\nbroker_principal=b\ndelegate_targets=h/x\n"); os.chmod(p, 0o644)
        c = credd.Config.load(str(p))
        assert (c.min_uid, str(c.disable_file), c.failure_cooldown_s) == (1000, "/etc/krb-hpc/disabled", 60)
        p.write_text("[broker]\nrealm=R\nbroker_principal=b\ndelegate_targets=h/x\n"
                     "min_uid=5000\ndisable_file=/run/stop\nfailure_cooldown=2m\n")
        c = credd.Config.load(str(p))
        assert (c.min_uid, str(c.disable_file), c.failure_cooldown_s) == (5000, "/run/stop", 120)


def test_krb_get_status_output():
    import contextlib, io
    from krbhpc import get
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "sock")
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); srv.bind(path); srv.listen(1)
        exp = int(time.time()) + 5 * 3600
        def serve():
            c, _ = srv.accept(); assert c.recv(16) == b"STATUS\n"
            c.sendall(f"OK disabled=False enrolled=True expires={exp} retry_at=0 "
                      f"last_error=your_account_cannot_be_delegated last_error_at={exp - 9000}\n".encode())
            c.close()
        t = threading.Thread(target=serve); t.start()
        os.environ.update(KRB_HPC_SOCKET=path, KRB_HPC_TIMEOUT="2")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = get.main(["--status"])
        t.join(); srv.close()
        text = out.getvalue()
        assert rc == 0 and "enrolled:        True" in text and "(in 4h" in text, text
        assert "last error:      your account cannot be delegated" in text, text
        with contextlib.redirect_stderr(io.StringIO()):
            assert get.main(["--bogus"]) == 2


def test_process_hardening():
    code = ("import ctypes, resource, sys; sys.path.insert(0, %r); from krbhpc import credd; "
            "credd._harden_process(); libc = ctypes.CDLL(None); "
            "print(resource.getrlimit(resource.RLIMIT_CORE), libc.prctl(3, 0, 0, 0, 0))"
            % os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True).stdout.strip()
    assert out == "(0, 0) 0", out          # no core dumps; PR_GET_DUMPABLE == 0


if __name__ == "__main__":
    import inspect
    tests = [v for n, v in sorted(globals().items()) if n.startswith("test_") and inspect.isfunction(v)]
    for t in tests:
        t()
        print(f"ok   {t.__name__}")
    print(f"\nall {len(tests)} safety tests passed" + ("" if ROOT else "  (root-only cases skipped)"))
