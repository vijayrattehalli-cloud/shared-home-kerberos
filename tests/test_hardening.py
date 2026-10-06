"""Unit tests for the fail-closed security checks in krbhpc.credd._assert_secure.

These verify the daemon refuses to trust a config, keytab directory, keytab, or
install helper that a non-root local user could have tampered with -- the core
of the privilege-separation threat model (see SECURITY.md).

Dependency-free (like test_krb_helpers.py): runs under pytest OR directly:

    python3 tests/test_hardening.py
    python3 -m pytest tests/test_hardening.py

Acceptance cases (a root-owned path is allowed) only run when executed as root;
otherwise files the test creates are owned by the test user and would -- quite
correctly -- be rejected, so those cases are skipped.
"""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from krbhpc.credd import _assert_secure

ROOT = os.geteuid() == 0


def _expect(exc, substr, fn, *a, **k):
    try:
        fn(*a, **k)
    except exc as e:
        assert substr in str(e), f"wrong message: {e!r} (wanted {substr!r})"
        return
    raise AssertionError(f"expected {exc.__name__} containing {substr!r}, none raised")


def test_rejects_group_writable_file():
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "config"; f.write_text("x"); os.chmod(f, 0o664)
        _expect(PermissionError, "group/world writable",
                _assert_secure, f, is_dir=False, label="config")


def test_rejects_world_writable_file():
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "config"; f.write_text("x"); os.chmod(f, 0o606)
        _expect(PermissionError, "group/world writable",
                _assert_secure, f, is_dir=False, label="config")


def test_rejects_symlink():
    with tempfile.TemporaryDirectory() as d:
        target = Path(d) / "real"; target.write_text("x"); os.chmod(target, 0o600)
        link = Path(d) / "link"; link.symlink_to(target)
        _expect(PermissionError, "must not be a symlink",
                _assert_secure, link, is_dir=False, label="config")


def test_rejects_file_when_dir_expected():
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "notadir"; f.write_text("x"); os.chmod(f, 0o600)
        _expect(PermissionError, "must be a directory",
                _assert_secure, f, is_dir=True, label="keytab_dir")


def test_rejects_dir_when_file_expected():
    with tempfile.TemporaryDirectory() as d:
        sub = Path(d) / "adir"; sub.mkdir(mode=0o700)
        _expect(PermissionError, "must be a regular file",
                _assert_secure, sub, is_dir=False, label="config")


def test_strict_rejects_group_readable_keytab():
    """A secret keytab must be 0600; 0640 (group-READABLE) is refused even
    though it is not group-writable -- a secret must not leak by read either."""
    with tempfile.TemporaryDirectory() as d:
        kt = Path(d) / "user.keytab"; kt.write_text("secret"); os.chmod(kt, 0o640)
        _expect(PermissionError, "mode 0600 or stricter",
                _assert_secure, kt, is_dir=False, label="keytab", strict=True)


def test_accepts_locked_down_file_as_root():
    if not ROOT:
        return  # skip: acceptance needs a root-owned path
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "config"; f.write_text("x"); os.chown(f, 0, 0); os.chmod(f, 0o644)
        _assert_secure(f, is_dir=False, label="config")  # must not raise


def test_accepts_0600_keytab_strict_as_root():
    if not ROOT:
        return
    with tempfile.TemporaryDirectory() as d:
        kt = Path(d) / "user.keytab"; kt.write_text("secret")
        os.chown(kt, 0, 0); os.chmod(kt, 0o600)
        _assert_secure(kt, is_dir=False, label="keytab", strict=True)  # must not raise


def test_rejects_non_root_owner():
    """A file owned by a non-root uid is refused even with a strict mode."""
    if not ROOT:
        return
    import pwd as _pwd
    victim = next((p.pw_uid for p in _pwd.getpwall() if p.pw_uid != 0), None)
    if victim is None:
        return
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "config"; f.write_text("x"); os.chown(f, victim, victim); os.chmod(f, 0o600)
        _expect(PermissionError, "must be owned by root",
                _assert_secure, f, is_dir=False, label="config")


if __name__ == "__main__":
    import inspect
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and inspect.isfunction(v)]
    for t in tests:
        t()
        print(f"ok   {t.__name__}")
    print(f"\nall {len(tests)} hardening tests passed"
          + ("" if ROOT else "  (acceptance cases skipped: not root)"))
