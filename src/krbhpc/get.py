#!/usr/bin/env python3
"""
krb-get -- ask krb-credd to (re)install your service tickets in ~/.krb5 and print
the export. (You get service tickets for the allow-listed backends, not a TGT.)

    eval "$(krb-get)"      # sets KRB5CCNAME=FILE:$HOME/.krb5/krb5cc_hpc
    krb-get --status       # enrolled? when do my tickets expire? last error?

Never blocks for long: /etc/profile.d runs this at every login, so a stuck
daemon must not hang the login. Override the limit with KRB_HPC_TIMEOUT
(seconds, default 30).
"""
from __future__ import annotations

import os
import shlex
import socket
import sys
import time


def _ask(path: str, timeout: float, request: bytes) -> str:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(path)
        s.sendall(request)
        with s.makefile("r", encoding="utf-8", errors="replace") as f:
            return f.readline(4096).strip()


def _when(epoch: str, relative: bool = True) -> str:
    try:
        t = int(epoch)
    except ValueError:
        return epoch
    if t <= 0:
        return "-"
    if not relative:
        return time.strftime('%Y-%m-%d %H:%M', time.localtime(t))
    left = t - time.time()
    rel = f"in {int(left // 3600)}h{int(left % 3600 // 60):02d}m" if left > 0 else "already passed"
    return f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(t))} ({rel})"


def _status(path: str, timeout: float) -> int:
    try:
        resp = _ask(path, timeout, b"STATUS\n")
    except OSError as e:
        print(f"krb-get: cannot reach krb-credd at {path}: {e}", file=sys.stderr)
        return 2
    if not resp.startswith("OK "):
        print(f"krb-get: {resp.removeprefix('ERR ').strip() or 'no answer'}", file=sys.stderr)
        return 1
    st = dict(kv.split("=", 1) for kv in resp[3:].split() if "=" in kv)
    print(f"enrolled:        {st.get('enrolled', '?')}")
    if st.get("disabled") == "True":
        print("service:         DISABLED by the HPC administrators")
    print(f"tickets expire:  {_when(st.get('expires', '0'))}")
    if st.get("retry_at", "0") != "0":
        print(f"next retry:      {_when(st['retry_at'])}")
    if "last_error" in st:
        print(f"last error:      {st['last_error'].replace('_', ' ')} "
              f"(at {_when(st.get('last_error_at', '0'), relative=False)})")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    path = os.environ.get("KRB_HPC_SOCKET", "/run/krb-hpc/credd.sock")
    try:
        timeout = float(os.environ.get("KRB_HPC_TIMEOUT", "30"))
    except ValueError:
        timeout = 30.0
    if argv[:1] == ["--status"]:
        return _status(path, timeout)
    if argv:
        print("usage: krb-get [--status]", file=sys.stderr)
        return 2
    try:
        resp = _ask(path, timeout, b"GET\n")
    except OSError as e:          # includes socket.timeout
        print(f"krb-get: cannot reach krb-credd at {path}: {e}", file=sys.stderr)
        return 2
    if resp.startswith("OK "):
        # The output is eval'd by the caller's shell: quote the value.
        print("export KRB5CCNAME=" + shlex.quote(f"FILE:{resp[3:]}"))
        return 0
    print(f"krb-get: {resp.removeprefix('ERR ').strip() or 'no answer from krb-credd'}",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
