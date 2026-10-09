#!/bin/bash
# Slurm TaskProlog (runs as the job user on every node, before every task).
# The service tickets are in the user's shared home; krb-credd keeps them fresh
# while the job is pending/running. "Forwarding" is just pointing each task at it.
# HOME can be unset (e.g. sbatch --export=NONE), so fall back to the passwd entry.
home=${HOME:-$(getent passwd "$(id -u)" | cut -d: -f6)}
cc="${home}/.krb5/krb5cc_hpc"
if [[ -n "$home" && -s "$cc" ]]; then
    echo "export KRB5CCNAME=FILE:${cc}"
    echo "export KRB5_CONFIG=/etc/krb5.conf"
else
    echo "print krb-hpc: no Kerberos tickets in ${cc} (run 'krb-get' on a login node or ask to be enrolled)"
fi
