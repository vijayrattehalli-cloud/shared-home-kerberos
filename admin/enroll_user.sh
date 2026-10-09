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
[ $# -ge 1 ] || { echo "usage: $0 <hpc-username> [ad-principal]" >&2; exit 2; }
user="$1"; princ="${2:-$1}"              # default: AD principal == posix name
uid=$(id -u "$user")                     # fails (and exits) if the user doesn't exist
case "$user$princ" in *[[:space:]]*|*'#'*) echo "names may not contain spaces or '#'" >&2; exit 2;; esac

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
# Already enrolled under the name OR the numeric UID? (Exact first-field match,
# no regular expressions, so unusual characters in a name can't misfire.)
existing=$(awk -v u="$user" -v n="$uid" '{sub(/#.*/,"")} NF && ($1==u || $1==n)' "$MAP")
if [ -n "$existing" ]; then
    echo "already enrolled: $existing"
else
    printf '%s\t%s\n' "$user" "$princ" >> "$MAP"
    echo "enrolled ${user} -> ${princ}  (uidmap updated; no restart needed)"
fi
