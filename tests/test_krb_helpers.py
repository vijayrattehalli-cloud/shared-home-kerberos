"""Unit tests for krbhpc._krb (pure functions; no Kerberos needed)."""
import os, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from krbhpc._krb import duration_seconds, parse_klist, earliest_expiry


def test_duration():
    assert duration_seconds("300") == 300
    assert duration_seconds("5m") == 300
    assert duration_seconds("2h") == 7200
    assert duration_seconds("7d") == 7 * 86400


def test_parse_klist_with_renew():
    out = (
        "Ticket cache: FILE:/home/jdoe/.krb5/krb5cc_hpc\n"
        "Default principal: hpc-jdoe@CORP.EXAMPLE.MIL\n\n"
        "Valid starting     Expires            Service principal\n"
        "10/06/26 06:00:00  10/06/26 16:00:00  krbtgt/CORP.EXAMPLE.MIL@CORP.EXAMPLE.MIL\n"
        "\trenew until 10/13/26 06:00:00\n"
    )
    t = parse_klist(out)
    assert t is not None
    # expires 10h after start; renew ~7d after start
    assert abs((t.renew_until - t.expires) - (6 * 86400 + 14 * 3600)) < 2


def test_parse_klist_no_tgt():
    assert parse_klist("Ticket cache: FILE:/x\nDefault principal: a@B\n") is None


def test_earliest_expiry_service_cache():
    # A constrained-delegation cache: SERVICE tickets, no TGT. earliest_expiry
    # should return the soonest Expires across them.
    out = (
        "Ticket cache: FILE:/home/jdoe/.krb5/krb5cc_hpc\n"
        "Default principal: jdoe@CORP.EXAMPLE.MIL\n\n"
        "Valid starting     Expires            Service principal\n"
        "10/06/26 06:00:00  10/06/26 16:00:00  hive/hs2.corp@CORP.EXAMPLE.MIL\n"
        "10/06/26 06:00:00  10/06/26 14:00:00  hdfs/nn.corp@CORP.EXAMPLE.MIL\n"
    )
    exp = earliest_expiry(out)
    assert exp is not None
    assert exp == time.mktime(time.strptime("10/06/26 14:00:00", "%m/%d/%y %H:%M:%S"))


def test_earliest_expiry_empty():
    assert earliest_expiry("Ticket cache: FILE:/x\nDefault principal: a@B\n") is None


if __name__ == "__main__":
    test_duration(); test_parse_klist_with_renew(); test_parse_klist_no_tgt()
    test_earliest_expiry_service_cache(); test_earliest_expiry_empty()
    print("unit tests OK")
