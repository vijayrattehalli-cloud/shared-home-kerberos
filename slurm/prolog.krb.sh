#!/bin/bash
# OPTIONAL Slurm Prolog (root, every allocated node). Logs whether the job
# owner's ticket is visible on this node (checked AS the user, since home may
# be root-squashed). Never fails the job.
[[ "${SLURM_JOB_UID:-}" =~ ^[0-9]+$ ]] || exit 0
home=$(getent passwd "$SLURM_JOB_UID" | cut -d: -f6)
if ! setpriv --reuid="$SLURM_JOB_UID" --regid="${SLURM_JOB_GID:-$SLURM_JOB_UID}" --init-groups \
        test -s "$home/.krb5/krb5cc_hpc"; then
    logger -t krb-hpc "job ${SLURM_JOB_ID}: no ticket for uid ${SLURM_JOB_UID} on $(hostname -s)"
fi
exit 0
