#!/bin/bash
# Enroll an HPC user against Active Directory.
#
#   enroll_user.sh <hpc-username> <ad-sAMAccountName>
#
# Recommended model: a DEDICATED AD account per HPC user in an HPC OU
# (e.g. hpc-jdoe) rather than the person's CAC-bound account. CAC/SCRIL
# accounts have AD-managed random passwords that the domain can roll, which
# would silently invalidate an escrowed keytab.
#
# AD account settings (done by AD admins, once per account):
#   - "This account supports Kerberos AES 256 bit encryption" = on
#     (msDS-SupportedEncryptionTypes includes 0x10)
#   - "Account is sensitive and cannot be delegated" = OFF  (TGT must be forwardable)
#   - Not a member of "Protected Users" (that group blocks delegation and caps TGT lifetime at 4h)
#   - Password never expires, or let krb-credd rotation (below) own it
set -euo pipefail
user="$1"; sam="$2"
REALM="${REALM:-$(awk '$1=="default_realm"{print $3}' /etc/krb5.conf)}"
KT="/etc/krb-hpc/keytabs/${sam}.keytab"
install -d -m 0700 -o root -g root /etc/krb-hpc/keytabs
id "$user" >/dev/null

# Option A (Linux broker, delegated OU rights): msktutil sets a random password
# on the account and writes the keytab in one step.
msktutil --update --use-service-account --account-name "$sam" \
         --keytab "$KT" --enctypes 0x10 --dont-expire-password \
         --server "${AD_DC:-dc1.example.mil}" --realm "$REALM"

# Option B (Windows, run by an AD admin, then copy the keytab over a secure channel):
#   ktpass /princ <sam>@<REALM> /mapuser <DOMAIN>\<sam> /crypto AES256-SHA1 ^
#          /ptype KRB5_NT_PRINCIPAL /pass +rndPass /out <sam>.keytab

chmod 0600 "$KT"
# Verify: the escrowed key works and AD issues a forwardable, renewable TGT.
chk=$(mktemp); trap 'rm -f "$chk"' EXIT
kinit -f -r 7d -k -t "$KT" -c "FILE:$chk" "${sam}@${REALM}"
flags=$(LC_ALL=C klist -f -c "FILE:$chk" | sed -n 's/.*Flags: //p' | head -1)
[[ "$flags" == *F* ]] || echo "WARNING: TGT not forwardable (flags=$flags) -- check 'sensitive and cannot be delegated' / Protected Users"
[[ "$flags" == *R* ]] || echo "WARNING: TGT not renewable (flags=$flags) -- check the domain Kerberos policy"
grep -qE "^${user}[[:space:]]" /etc/krb-hpc/uidmap.conf || echo "${user}  ${sam}" >> /etc/krb-hpc/uidmap.conf
echo "enrolled ${user} -> ${sam}@${REALM}"
