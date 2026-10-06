#!/usr/bin/env python3
"""
krb-get -- ask krb-credd to (re)install your TGT in ~/.krb5 and print the export.

    eval "$(krb-get)"      # sets KRB5CCNAME=FILE:$HOME/.krb5/krb5cc_hpc
"""
from __future__ import annotations

import os
import socket
import sys


def main(argv: list[str] | None = None) -> int:
    sock = os.environ.get("KRB_HPC_SOCKET", "/run/krb-hpc/credd.sock")
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(sock)
        s.sendall(b"GET\n")
        resp = s.makefile().readline().strip()
    except OSError as e:
        print(f"krb-get: cannot reach krb-credd at {sock}: {e}", file=sys.stderr)
        return 2
    if resp.startswith("OK "):
        print(f"export KRB5CCNAME=FILE:{resp[3:]}")
        return 0
    print(f"krb-get: {resp.removeprefix('ERR ').strip()}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
