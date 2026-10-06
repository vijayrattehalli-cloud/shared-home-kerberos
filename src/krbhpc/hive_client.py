#!/usr/bin/env python3
"""
Hive access in pure Python over Kerberos, using the SERVICE ticket that
krb-credd minted (by constrained delegation) into the shared home
($KRB5CCNAME -> FILE:$HOME/.krb5/krb5cc_hpc).

The cache holds the hive/_HOST service ticket directly (no TGT); GSSAPI uses the
cached service ticket as-is. The requested service name must match the SPN of
the minted ticket -- watch _HOST / hostname canonicalization.

Why this is simpler than the Java path: Python's GSSAPI stack (via impyla/
PyHive + pure-sasl, or requests-kerberos for HTTP) uses the FILE ccache
directly. There is NO Security Manager, no Subject.callAs, and no Hive driver
shim to maintain -- the JDK-24 problem the Java edition worked around does not
exist here.

Dependencies (install on the login/compute image, not in this repo):
    pip install 'impyla[kerberos]'        # pulls thrift_sasl, pure-sasl, kerberos
  or
    pip install 'pyhive[hive]' thrift_sasl

Usage:
    export KRB5CCNAME=FILE:$HOME/.krb5/krb5cc_hpc     # done by krb-get / TaskProlog
    python -m krbhpc.hive_client \
        --host hs2.hadoop.example.mil --port 10000 \
        --service hive --realm CORP.EXAMPLE.MIL \
        --sql "SELECT current_user(), count(*) FROM sales.orders"
"""
from __future__ import annotations

import argparse
import os
import sys


def connect(host: str, port: int, service: str, database: str = "default"):
    """Open a Kerberos (GSSAPI) connection to HiveServer2 using the ccache in
    $KRB5CCNAME. Returns an impyla/DB-API connection."""
    cc = os.environ.get("KRB5CCNAME", "")
    if cc.startswith(("KEYRING:", "KCM:", "API:", "DIR:")):
        # Not fatal for Python GSSAPI the way it is for Java, but FILE: is what
        # krb-credd writes and what the whole design standardizes on.
        print(f"warning: KRB5CCNAME={cc} is not a FILE cache", file=sys.stderr)
    try:
        from impala.dbapi import connect as impala_connect  # type: ignore
    except ImportError as e:
        raise SystemExit(
            "impyla is required: pip install 'impyla[kerberos]'") from e
    # auth_mechanism GSSAPI uses the Kerberos ticket in the ccache; kerberos_service_name
    # is the service portion of the HS2 SPN (hive/_HOST@REALM -> 'hive').
    return impala_connect(
        host=host, port=port, database=database,
        auth_mechanism="GSSAPI", kerberos_service_name=service,
        use_ssl=True,
    )


def run_query(host: str, port: int, service: str, sql: str,
              database: str = "default") -> list[tuple]:
    conn = connect(host, port, service, database)
    try:
        cur = conn.cursor()
        cur.execute(sql)
        rows = cur.fetchall()
        desc = [d[0] for d in (cur.description or [])]
        if desc:
            print("\t".join(desc))
        for r in rows:
            print("\t".join("" if v is None else str(v) for v in r))
        return rows
    finally:
        conn.close()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="krbhpc.hive_client")
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=10000)
    ap.add_argument("--service", default="hive",
                    help="service part of the HS2 SPN (hive/_HOST@REALM -> hive)")
    ap.add_argument("--database", default="default")
    ap.add_argument("--sql", required=True)
    a = ap.parse_args(argv)
    if not os.environ.get("KRB5CCNAME"):
        print("KRB5CCNAME is not set -- run `eval $(krb-get)` or submit via Slurm",
              file=sys.stderr)
        return 2
    run_query(a.host, a.port, a.service, a.sql, a.database)
    return 0


if __name__ == "__main__":
    sys.exit(main())
