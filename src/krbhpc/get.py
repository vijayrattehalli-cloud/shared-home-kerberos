#!/usr/bin/env python3
"""
krb-get -- ask krb-credd to (re)install your service tickets in ~/.krb5 and print
the export. (You get service tickets for the allow-listed backends, not a TGT.)

    eval "$(krb-get)"      # sets KRB5CCNAME=FILE:$HOME/.krb5/krb5cc_hpc

Never blocks for long: /etc/profile.d runs this at every login, so a stuck
daemon must not hang the login. Override the limit with KRB_HPC_TIMEOUT
(seconds, default 30).
"""
from __future__ import annotations

import os
import shlex
import socket
import sys


def main(argv: list[str] | None = None) -> int:
    path = os.environ.get("KRB_HPC_SOCKET", "/run/krb-hpc/credd.sock")
    try:
        timeout = float(os.environ.get("KRB_HPC_TIMEOUT", "30"))
    except ValueError:
        timeout = 30.0
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(path)
            s.sendall(b"GET\n")
            with s.makefile("r", encoding="utf-8", errors="replace") as f:
                resp = f.readline(4096).strip()
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
