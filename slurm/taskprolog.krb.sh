#!/bin/bash
# Slurm TaskProlog (runs as the job user on every node, before every task).
# The service tickets are in the user's shared home; krb-credd keeps them fresh while the job
# is pending/running. "Forwarding" is just pointing each task at it.
cc="${HOME}/.krb5/krb5cc_hpc"
if [[ -s "$cc" ]]; then
    echo "export KRB5CCNAME=FILE:${cc}"
    echo "export KRB5_CONFIG=/etc/krb5.conf"
else
    echo "print krb-hpc: no Kerberos ticket in ${cc} (run 'krb-get' on a login node or ask to be enrolled)"
fi
