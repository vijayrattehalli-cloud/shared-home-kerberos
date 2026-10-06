#!/bin/bash
# Slurm TaskProlog (runs as the job user on every node, before every task).
# The TGT lives in the user's home on the shared filesystem and krb-credd keeps
# it fresh while the job is pending or running, so "forwarding" is just
# pointing every task at it. Lines "export X=Y" go into the task environment.
cc="${HOME}/.krb5/krb5cc_hpc"
if [[ -s "$cc" ]]; then
    echo "export KRB5CCNAME=FILE:${cc}"
    echo "export KRB5_CONFIG=/etc/krb5.conf"
else
    echo "print krb-hpc: no Kerberos ticket in ${cc} (run 'krb-get' on a login node or ask to be enrolled)"
fi
