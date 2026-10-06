#!/usr/bin/env python3
"""
krb-install-ccache DEST

Invoked by krb-credd through `setpriv --reuid=<user>`, so it runs WITH THE
USER'S identity. It therefore works on root-squashed NFS/GPFS/Lustre homes and
can never write anywhere the user could not. Reads a ccache on stdin and
installs it atomically at DEST (parent dir mode 0700, file mode 0600).

Pure Python, standard library only. Equivalent to the shell helper of the same
name; provided in Python so the whole package is one language.
"""
from __future__ import annotations

import os
import sys
import tempfile


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: krb-install-ccache DEST", file=sys.stderr)
        return 2
    dest = argv[0]
    data = sys.stdin.buffer.read()
    if not data:
        print("krb-install-ccache: empty ccache on stdin", file=sys.stderr)
        return 1

    os.umask(0o077)
    d = os.path.dirname(dest) or "."
    os.makedirs(d, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass  # may be a pre-existing home dir we don't own the mode of

    fd, tmp = tempfile.mkstemp(dir=d, prefix=".krb5cc.")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(tmp, 0o600)
        os.replace(tmp, dest)  # atomic: readers on any node see old or new, never partial
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return 0


if __name__ == "__main__":
    sys.exit(main())
