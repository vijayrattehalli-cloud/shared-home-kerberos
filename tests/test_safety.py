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
                hours=10, extra="", tkt_etype=None):
    start = time.strftime("%m/%d/%y %H:%M:%S", time.gmtime())
    end = time.strftime("%m/%d/%y %H:%M:%S", time.gmtime(time.time() + hours * 3600))
    lines = [f"Ticket cache: FILE:/tmp/x.cc", f"Default principal: {principal}", "",
             "Valid starting       Expires              Service principal"]
    for svc in services:
        lines += [f"{start}  {end}  {svc}", extra or None,
                  f"\tFlags: FA, Etype (skey, tkt): {etype}, {tkt_etype or etype} "]
    return "\n".join(l for l in lines if l is not None) + "\n"


def _rejects(info, want, accepted=("jdoe",)):
    try:
        validate_user_cache(info, list(accepted), REALM, TARGETS, 300)
    except KrbToolError as e:
        assert e.category == "bad_ticket" and want in str(e), (want, str(e))
    else:
        raise AssertionError(f"accepted a cache that should fail: {want}")


def test_parse_and_accept_good_cache():
    info = parse_klist_details(_klist_text())
    assert info.default_principal == "jdoe@TEST.LAB"
    assert [t.server for t in info.tickets] == TARGETS
    assert info.tickets[0].skey_etype == info.tickets[0].tkt_etype == "aes256-cts-hmac-sha1-96"
    assert validate_user_cache(info, ["jdoe"], REALM, TARGETS, 300) == []     # bare name gets the realm
    assert validate_user_cache(info, ["JDoe@test.lab"], REALM, TARGETS, 300) == []   # case-insensitive


def test_upn_mapping_accepted_through_the_linux_name():
    # uidmap holds a UPN (e.g. a CAC EDIPI); AD returns the sAMAccountName,
    # which matches the Linux user name: accepted. Anyone else: rejected.
    info = parse_klist_details(_klist_text())
    assert validate_user_cache(info, ["1234567890@mil", "jdoe"], REALM, TARGETS, 300) == []
    _rejects(parse_klist_details(_klist_text(principal="asmith@TEST.LAB")), "expected",
             accepted=("1234567890@mil", "jdoe"))


def test_backend_rc4_ticket_warns_but_rc4_session_key_rejects():
    info = parse_klist_details(_klist_text(tkt_etype="DEPRECATED:arcfour-hmac"))
    w = validate_user_cache(info, ["jdoe"], REALM, TARGETS, 300)
    assert len(w) == 2 and "enable AES on that service account" in w[0], w
    _rejects(parse_klist_details(_klist_text(etype="DEPRECATED:arcfour-hmac")), "session key")


def test_rejects_wrong_or_extra_tickets():
    _rejects(parse_klist_details(_klist_text(principal="asmith@TEST.LAB")), "expected jdoe@TEST.LAB")
    _rejects(parse_klist_details(_klist_text(services=TARGETS + ["krbtgt/TEST.LAB@TEST.LAB"])),
             "ticket-granting ticket")
    _rejects(parse_klist_details(_klist_text(services=TARGETS[:1])), "no ticket for hive/")
    w = validate_user_cache(parse_klist_details(_klist_text(services=TARGETS + ["cifs/fs.test.lab@TEST.LAB"])),
                            ["jdoe"], REALM, TARGETS, 300)
    assert w == ["cache also holds cifs/fs.test.lab@TEST.LAB"], w        # extra: logged, not fatal
    _rejects(parse_klist_details(_klist_text(extra="\tfor client asmith@TEST.LAB")), "names client asmith")
    _rejects(CacheInfo(None, ()), "no default principal")


def test_rejects_weak_crypto_and_short_life():
    _rejects(parse_klist_details(_klist_text(etype="arcfour-hmac")), "session key uses arcfour-hmac")
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
                state_dir=Path(d), ticket_checks_enforce=True)
    base.update(cfg)
    tm.cfg = type("C", (), base)()
    tm.krb, tm._warned_margin, tm._warned, tm._checked = krb, False, {}, {}
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
        # ticket_checks = warn: the same bad cache is logged and published
        cc.write_text("old")
        tm = _manager(d, _FakeKrb(_klist_text(principal="asmith@TEST.LAB")), ticket_checks_enforce=False)
        tm._mint("jdoe", cc)
        assert cc.read_text() == "new" and any("not enforced" in w for w in tm._warned)
        # ...but warn mode never publishes a TGT, a non-AES session key or a short-lived ticket
        for bad_text in (_klist_text(services=TARGETS + ["krbtgt/TEST.LAB@TEST.LAB"]),
                         _klist_text(etype="arcfour-hmac"), _klist_text(hours=0.01)):
            cc.write_text("old")
            tm = _manager(d, _FakeKrb(bad_text), ticket_checks_enforce=False)
            try:
                tm._mint("jdoe", cc)
            except KrbToolError:
                pass
            else:
                raise AssertionError("warn mode published a cache it must refuse")
            assert cc.read_text() == "old"


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
            frames = []
            for _ in range(3):                                # cooldown: one KDC attempt, three answers
                try:
                    tm.ensure(5000)
                except KrbToolError as e:
                    assert e.category == "not_delegable"
                    n, tb = 0, e.__traceback__
                    while tb:
                        n, tb = n + 1, tb.tb_next
                    frames.append(n)
            assert krb.mints == 1, krb.mints
            assert frames[1] == frames[2], frames             # a fresh error each time: no traceback growth
            # a cooldown answer in the background doesn't grow the backoff
            tm._refresh_one(5000)
            assert 5000 not in tm._failures, tm._failures
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
            (Path(d) / "disabled").unlink()
            # transient errors are never cached: every request tries again
            tm._last_error.clear()
            tm.krb = krb = _FakeKrb(_klist_text(), fail=KrbToolError("kvno", "x", "Cannot contact any KDC"))
            for _ in range(3):
                try:
                    tm.ensure(5000)
                except KrbToolError as e:
                    assert e.category == "kdc_unreachable"
            assert krb.mints == 3 and 5000 not in tm._last_error
        finally:
            credd.pwd.getpwuid = orig


def test_existing_master_is_validated_once_after_start():
    with tempfile.TemporaryDirectory() as d:
        import pwd
        tm = _manager(d, _FakeKrb(_klist_text(principal="asmith@TEST.LAB")))
        tm.map = type("M", (), {"principal": lambda self, uid: "jdoe"})()
        tm._glock, tm._locks = threading.Lock(), {}
        tm.master = lambda uid: Path(d) / f"krb5cc_{uid}"
        tm.krb.cache_expiry = lambda path: time.time() + 9 * 3600      # looks fresh
        tm.home_ccache = lambda pw: Path(d) / "home.cc"
        tm._install = lambda pw, src: Path(d) / "home.cc"
        (Path(d) / "krb5cc_5000").write_text("from an older version")
        me = pwd.getpwuid(os.getuid()); orig = credd.pwd.getpwuid
        credd.pwd.getpwuid = lambda uid: me
        try:
            try:
                tm.ensure(5000)          # existing master fails the check -> re-mint -> new mint also bad
            except KrbToolError as e:
                assert e.category == "bad_ticket"
            assert tm.krb.mints == 1 and 5000 not in tm._checked
            # a master that passed for one principal is re-checked if uidmap now says another
            tm.krb = _FakeKrb(_klist_text())
            tm.krb.cache_expiry = lambda path: time.time() + 9 * 3600
            tm._checked[5000] = "someone-else"
            tm.ensure(5000)
            assert tm._checked[5000] == "jdoe" and tm.krb.mints == 0
        finally:
            credd.pwd.getpwuid = orig


def test_config_safety_options():
    if not ROOT:
        print("skip test_config_safety_options (needs root)")
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
        for body, want in [("delegate_targets=,\n", "lists no services"),
                           ("disable_file=disabled\n", "absolute path"),
                           ("ticket_checks=maybe\n", "ticket_checks")]:
            base = "[broker]\nrealm=R\nbroker_principal=b\ndelegate_targets=h/x\n"
            p.write_text(base.replace("delegate_targets=h/x\n", "") + body if "delegate" in body else base + body)
            try:
                credd.Config.load(str(p))
            except ValueError as e:
                assert want in str(e), (want, e)
            else:
                raise AssertionError(f"accepted {body!r}")
        p.write_text("[broker]\nrealm=R\nbroker_principal=b\ndelegate_targets=h/x h/x@R\nticket_checks=warn\n")
        c = credd.Config.load(str(p))
        assert c.delegate_targets == ["h/x@R"] and c.ticket_checks_enforce is False


def test_min_uid_default_follows_login_defs():
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "login.defs"
        f.write_text("# comment\nUID_MIN                   500\nUID_MAX 60000\n")
        assert credd._login_defs_uid_min(str(f)) == 500
        assert credd._login_defs_uid_min(str(Path(d) / "missing")) == 1000


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
