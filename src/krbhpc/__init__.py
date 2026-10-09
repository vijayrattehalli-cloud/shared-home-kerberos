"""krbhpc -- shared-home Kerberos for a CAC / UID-GID HPC cluster.

A root daemon (krb-credd) authenticates once as a single broker service account
and uses Kerberos constrained delegation (S4U2Self + S4U2Proxy) to mint each
enrolled user's backend SERVICE tickets, writing them into the user's home
directory on the shared filesystem; every compute node already sees them. No
per-user keytabs. Pure Python; MIT krb5 (1.19+) client tools + setpriv at runtime.
"""
__version__ = "2.1.0"
