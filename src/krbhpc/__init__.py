"""krbhpc -- shared-home Kerberos for a CAC / UID-GID HPC cluster.

A root daemon (krb-credd) obtains each user's AD TGT from an escrowed keytab and
writes it into the user's home directory on the shared filesystem; every compute
node already sees it. Pure Python; MIT krb5 client tools + setpriv at runtime.
"""
__version__ = "1.0.0"
