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


class Krb5:
    """Thin wrapper over kinit/klist with a pinned config and C locale."""

    def __init__(self, krb5_conf: str, extra_env: dict | None = None):
        import os
        self.env = dict(os.environ, KRB5_CONFIG=krb5_conf, LC_ALL="C")
        if extra_env:
            self.env.update(extra_env)

    def run(self, *args: str, timeout: int = 60) -> subprocess.CompletedProcess:
        return subprocess.run(args, env=self.env, capture_output=True,
                              text=True, timeout=timeout)

    def klist_times(self, ccache: str) -> TgtTimes | None:
        r = self.run("klist", "-c", f"FILE:{ccache}")
        if r.returncode != 0:
            return None
        return parse_klist(r.stdout)

    def kinit_keytab(self, principal: str, keytab: str, ccache: str,
                     lifetime: str, renew_lifetime: str) -> None:
        r = self.run("kinit", "-f", "-r", renew_lifetime, "-l", lifetime,
                     "-k", "-t", keytab, "-c", f"FILE:{ccache}", principal)
        if r.returncode != 0:
            raise RuntimeError(f"kinit failed for {principal}: {r.stderr.strip()}")

    def kinit_renew(self, ccache: str) -> bool:
        r = self.run("kinit", "-R", "-c", f"FILE:{ccache}")
        return r.returncode == 0
