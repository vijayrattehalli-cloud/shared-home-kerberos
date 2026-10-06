#!/bin/bash
# Rotate every escrowed AD key (run monthly from a systemd timer on the broker).
# msktutil changes the AD password to a new random value and rewrites the keytab.
# Outstanding TGTs stay valid until they expire; krb-credd re-acquires on next refresh.
set -euo pipefail
for kt in /etc/krb-hpc/keytabs/*.keytab; do
    sam=$(basename "$kt" .keytab)
    msktutil --update --use-service-account --account-name "$sam" --keytab "$kt" \
             --enctypes 0x10 --server "${AD_DC:-dc1.example.mil}" --auto-update \
      && logger -t krb-hpc "rotated key for $sam" \
      || logger -t krb-hpc -p auth.err "rotation FAILED for $sam"
done
