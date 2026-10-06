#!/bin/bash
# OPTIONAL Slurm Prolog (root, every allocated node). Only logs whether the
# job owner's ticket is visible on this node; root cannot read it on a
# root-squashed home, so it checks as the user. Never fails the job.
[[ "${SLURM_JOB_UID:-}" =~ ^[0-9]+$ ]] || exit 0
home=$(getent passwd "$SLURM_JOB_UID" | cut -d: -f6)
if ! setpriv --reuid="$SLURM_JOB_UID" --regid="${SLURM_JOB_GID:-$SLURM_JOB_UID}" --init-groups \
        test -s "$home/.krb5/krb5cc_hpc"; then
    logger -t krb-hpc "job $SLURM_JOB_ID: no ticket for uid $SLURM_JOB_UID on $(hostname -s)"
fi
exit 0
