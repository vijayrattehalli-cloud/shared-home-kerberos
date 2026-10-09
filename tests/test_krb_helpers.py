"""Unit tests for krbhpc._krb (no Kerberos needed).

Pure functions (durations, klist parsing, version parsing, error
classification) plus the Krb5 wrapper driven by small fake kinit/klist/kvno
scripts: absolute tool paths, environment scrubbing, the MIT version gate,
-U vs -I, and the atomic renew.

Dependency-free: runs under pytest OR directly:

    python3 tests/test_krb_helpers.py
"""
import calendar, os, stat, sys, tempfile, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from krbhpc._krb import (Krb5, KrbToolError, classify_error, duration_seconds,
                         earliest_expiry, parse_klist, parse_mit_version)


def utc(s):
    return float(calendar.timegm(time.strptime(s, "%m/%d/%y %H:%M:%S")))


def test_duration():
    assert duration_seconds("300") == 300
    assert duration_seconds("5m") == 300
    assert duration_seconds("2h") == 7200
    assert duration_seconds("7d") == 7 * 86400


def test_parse_klist_with_renew():
    out = (
        "Ticket cache: FILE:/var/lib/krb-hpc/broker.cc\n"
        "Default principal: hpc-broker/mgmt@CORP.EXAMPLE.MIL\n\n"
        "Valid starting     Expires            Service principal\n"
        "10/06/26 06:00:00  10/06/26 16:00:00  krbtgt/CORP.EXAMPLE.MIL@CORP.EXAMPLE.MIL\n"
        "\trenew until 10/13/26 06:00:00\n"
    )
    t = parse_klist(out)
    assert t is not None
    assert t.expires == utc("10/06/26 16:00:00")          # read as UTC
    assert t.renew_until == utc("10/13/26 06:00:00")


def test_parse_klist_no_tgt():
    assert parse_klist("Ticket cache: FILE:/x\nDefault principal: a@B\n") is None


def test_times_are_utc_not_local():
    # 11/01/26 01:30 occurs twice in US/Eastern; as UTC it is unambiguous.
    old = os.environ.get("TZ")
    os.environ["TZ"] = "America/New_York"; time.tzset()
    try:
        out = ("Valid starting     Expires            Service principal\n"
               "11/01/26 00:00:00  11/01/26 01:30:00  hive/hs2@R\n")
        assert earliest_expiry(out) == utc("11/01/26 01:30:00")
    finally:
        if old is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = old
        time.tzset()


def test_earliest_expiry_service_cache():
    out = (
        "Ticket cache: FILE:/home/jdoe/.krb5/krb5cc_hpc\n"
        "Default principal: jdoe@CORP.EXAMPLE.MIL\n\n"
        "Valid starting     Expires            Service principal\n"
        "10/06/26 06:00:00  10/06/26 16:00:00  hive/hs2.corp@CORP.EXAMPLE.MIL\n"
        "10/06/26 06:00:00  10/06/26 14:00:00  hdfs/nn.corp@CORP.EXAMPLE.MIL\n"
    )
    assert earliest_expiry(out) == utc("10/06/26 14:00:00")


def test_earliest_expiry_empty():
    assert earliest_expiry("Ticket cache: FILE:/x\nDefault principal: a@B\n") is None


def test_parse_mit_version():
    assert parse_mit_version("Kerberos 5 version 1.20.1\n") == (1, 20, 1)
    assert parse_mit_version("Kerberos 5 version 1.19") == (1, 19)
    assert parse_mit_version("klist (Heimdal 7.7.0)") is None


def test_classify_error():
    cases = {
        "kvno: Cannot contact any KDC for realm 'CORP' while getting credentials": "kdc_unreachable",
        "kvno: Clock skew too great while getting credentials": "clock_skew",
        "kvno: KDC can't fulfill requested option while getting credentials for hive/x": "not_delegable",
        "hive/x@R: constrained delegation failed": "not_delegable",
        "Client 'nobody@R' not found in Kerberos database": "unknown_principal",
        "kinit: Key table entry not found while getting initial credentials": "broker_key",
        "kinit: Preauthentication failed while getting initial credentials": "broker_key",
        "something new": "other",
    }
    for text, want in cases.items():
        assert classify_error(text) == want, (text, classify_error(text))
    assert KrbToolError("kvno", "x", "Cannot contact any KDC").transient
    assert not KrbToolError("kvno", "x", "KDC can't fulfill requested option").transient


# ---------------------------------------------------------- fake tools
FAKE = r"""#!/bin/sh
# Records its argv and environment, then behaves per $FAKE_MODE.
tool=$(basename "$0")
{ echo "ARGS $tool $*"; env | sort | sed 's/^/ENV /'; } >> "$FAKE_LOG"
case "$tool:$*" in
  klist:-V) echo "${FAKE_VERSION:-Kerberos 5 version 1.20.1}" ;;
  kinit:-R*) eval cc=\${$#}; cc=${cc#FILE:}; [ "$FAKE_MODE" = renewfail ] && { echo "kinit: Ticket expired while renewing credentials" >&2; exit 1; }
             echo renewed > "$cc" ;;
  kvno:*) [ "$FAKE_MODE" = kvnofail ] && { echo "kvno: KDC can't fulfill requested option while getting credentials for hive/x@R" >&2; exit 1; } ;;
esac
exit 0
"""


def _fakes(d, **env):
    for t in ("kinit", "klist", "kvno"):
        p = os.path.join(d, t)
        open(p, "w").write(FAKE)
        os.chmod(p, 0o755)
    log = os.path.join(d, "log")
    k = Krb5(os.path.join(d, "krb5.conf"),
             extra_env={"FAKE_LOG": log, **env},
             tools={t: os.path.join(d, t) for t in ("kinit", "klist", "kvno")})
    return k, log


def test_tools_must_be_absolute():
    try:
        Krb5("/etc/krb5.conf", tools={"kinit": "kinit"})
    except ValueError:
        return
    raise AssertionError("relative tool path accepted")


def test_environment_is_scrubbed_and_pinned():
    with tempfile.TemporaryDirectory() as d:
        saved = dict(os.environ)
        os.environ.update(KRB5CCNAME="FILE:/evil", KRB5_TRACE="/dev/stderr", KRB5_CONFIG="/evil.conf",
                          KRB5_CLIENT_KTNAME="/evil.kt", LD_PRELOAD="/evil.so", LC_TIME="de_DE", TZ="Asia/Tokyo")
        try:
            k, log = _fakes(d)
        finally:
            os.environ.clear(); os.environ.update(saved)
        k.run("klist", "-c", "FILE:/x")
        env = [l[4:].rstrip("\n") for l in open(log) if l.startswith("ENV ")]
        joined = "\n".join(env)
        for bad in ("KRB5CCNAME=", "KRB5_TRACE=", "KRB5_CLIENT_KTNAME=", "LD_PRELOAD=", "LC_TIME=", "evil.conf"):
            assert bad not in joined, bad
        assert f"KRB5_CONFIG={d}/krb5.conf" in env and "LC_ALL=C" in env and "TZ=UTC0" in env


def test_version_gate():
    with tempfile.TemporaryDirectory() as d:
        assert _fakes(d)[0].version() == (1, 20, 1)
        for v, ok in (("Kerberos 5 version 1.18.2", False), ("klist (Heimdal 7.7.0)", False),
                      ("Kerberos 5 version 1.19", True)):
            k, _ = _fakes(d, FAKE_VERSION=v)
            try:
                k.version()
                assert ok, v
            except RuntimeError:
                assert not ok, v


def test_s4u_flag_and_error_category():
    with tempfile.TemporaryDirectory() as d:
        k, log = _fakes(d)
        b, o = os.path.join(d, "b.cc"), os.path.join(d, "o.cc")
        open(b, "w").write("broker")
        k.s4u_mint(b, "jdoe", ["hive/x@R", "hdfs/y@R"], o)
        args = [l for l in open(log) if l.startswith("ARGS kvno")][-1].split()
        # kvno works on a throwaway copy of the broker cache, never the real one
        assert args[3].startswith(f"FILE:{d}/.broker.") and args[3] != f"FILE:{b}", args
        assert args[4:] == ["--out-cache", f"FILE:{o}", "-U", "jdoe", "-P", "hive/x@R", "hdfs/y@R"], args
        assert sorted(os.listdir(d)) == sorted(["b.cc", "kinit", "klist", "kvno", "log"]), os.listdir(d)
        k2 = Krb5(k.env["KRB5_CONFIG"], extra_env={"FAKE_LOG": log}, tools=k.tools, s4u_enterprise=False)
        k2.s4u_mint(b, "jdoe", ["hive/x@R"], o)
        assert "-I jdoe -P hive/x@R" in open(log).read()
        try:
            k2.s4u_mint(os.path.join(d, "missing.cc"), "jdoe", ["hive/x@R"], o)
        except KrbToolError as e:
            assert e.category == "bad_cache" and e.transient
        else:
            raise AssertionError("missing broker cache not reported")
        k3, _ = _fakes(d, FAKE_MODE="kvnofail")
        try:
            k3.s4u_mint(b, "jdoe", ["hive/x@R"], o)
        except KrbToolError as e:
            assert e.category == "not_delegable" and not e.transient
        else:
            raise AssertionError("expected KrbToolError")


def test_renew_is_atomic_and_never_touches_original_on_failure():
    with tempfile.TemporaryDirectory() as d:
        cc = os.path.join(d, "broker.cc")
        open(cc, "w").write("original")
        k, log = _fakes(d, FAKE_MODE="renewfail")
        assert k.kinit_renew(cc) is False
        assert open(cc).read() == "original" and not os.path.exists(cc + ".renew")
        assert f"ARGS kinit -R -c FILE:{cc}.renew" in open(log).read()   # renewed a copy
        k, _ = _fakes(d)
        assert k.kinit_renew(cc) is True
        assert open(cc).read().strip() == "renewed"
        assert stat.S_IMODE(os.stat(cc).st_mode) == 0o600
        assert k.kinit_renew(os.path.join(d, "missing.cc")) is False


if __name__ == "__main__":
    import inspect
    tests = [v for n, v in sorted(globals().items()) if n.startswith("test_") and inspect.isfunction(v)]
    for t in tests:
        t()
        print(f"ok   {t.__name__}")
    print(f"\nall {len(tests)} helper tests passed")
