#!/bin/bash
# Rotate the ONE broker key (run on a schedule from a systemd timer on the
# broker). There is a single credential for the whole cluster now, not one per
# user. Prefer a gMSA so AD rotates automatically and this script is unnecessary.
#
# msktutil changes the broker account's AD password to a new random value and
# rewrites the keytab in place. Outstanding tickets stay valid until they
# expire; krb-credd re-kinit's the broker TGT with the new key on next refresh.
set -euo pipefail
KT="${BROKER_KEYTAB:-/etc/krb-hpc/broker.keytab}"
SAM="${BROKER_SAM:-hpc-broker}"
msktutil --update --use-service-account --account-name "$SAM" --keytab "$KT" \
         --enctypes 0x10 --server "${AD_DC:-dc1.example.mil}" --auto-update \
  && { chmod 0600 "$KT"; logger -t krb-hpc "rotated broker key ($SAM)"; \
       systemctl reload-or-restart krb-credd 2>/dev/null || true; } \
  || { logger -t krb-hpc -p auth.err "broker key rotation FAILED ($SAM)"; exit 1; }
