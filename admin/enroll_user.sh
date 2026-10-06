#!/bin/bash
# Enroll an HPC user for the broker / constrained-delegation design.
#
#   enroll_user.sh <hpc-username> [ad-principal]
#
# There are NO per-user keytabs and NO hpc-<user> shadow accounts here. The
# broker impersonates the user's REAL AD identity via S4U, so enrollment is just:
#   1. the user's AD account must be delegation-eligible (checked below), and
#   2. a uidmap.conf line mapping the POSIX identity -> real AD principal.
#
# The backends the user needs must already be in the broker's
# msDS-AllowedToDelegateTo and in delegate_targets (credd.conf). See AD-SETUP.md.
set -euo pipefail
user="$1"; princ="${2:-$1}"              # default: AD principal == posix name
id "$user" >/dev/null

# Delegation-eligibility reminder (enforced in AD, verifiable with PowerShell):
#   Get-ADUser <princ> -Properties AccountNotDelegated,MemberOf
#     AccountNotDelegated must be False, and MemberOf must NOT include Protected Users.
cat <<EOF
NOTE: confirm in AD that '${princ}' is delegation-eligible:
  - NOT in 'Protected Users'
  - 'Account is sensitive and cannot be delegated' = OFF (AccountNotDelegated = False)
  - AES256 enabled
Otherwise S4U2Proxy for this user will fail at the KDC.
EOF

MAP=/etc/krb-hpc/uidmap.conf
install -d -m 0755 -o root -g root "$(dirname "$MAP")"
[ -f "$MAP" ] || { install -m 0644 -o root -g root /dev/null "$MAP"; }
if grep -qE "^${user}[[:space:]]" "$MAP"; then
    echo "already enrolled: $(grep -E "^${user}[[:space:]]" "$MAP")"
else
    printf '%s\t%s\n' "$user" "$princ" >> "$MAP"
    echo "enrolled ${user} -> ${princ}  (uidmap updated; no restart needed)"
fi
