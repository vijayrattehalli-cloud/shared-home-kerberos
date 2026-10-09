#!/bin/bash
# Revoke an HPC user's Kerberos access.
#   revoke_user.sh <hpc-username>
# Removing the mapping stops the daemon from minting or refreshing tickets for
# this user (the map is re-read on change). Service tickets already in the
# user's home stay valid until they expire (short-lived; the daemon re-mints),
# so for a hard cutoff ALSO remove the user from the backends' authorization
# (Ranger/HDFS) and/or disable their AD account.
#
# To revoke EVERYONE at once, rotate or disable the single broker account.
set -euo pipefail
[ $# -eq 1 ] || { echo "usage: $0 <hpc-username>" >&2; exit 2; }
user="$1"
uid=$(id -u "$user"); gid=$(id -g "$user"); home=$(getent passwd "$user" | cut -d: -f6)
MAP=/etc/krb-hpc/uidmap.conf
# Drop lines whose FIRST FIELD is exactly the name or the UID (no regex, so a
# name containing '.', '*' etc. can't match other users), then replace the map
# atomically with the same owner and mode. The daemon re-reads it on change.
tmp=$(mktemp "${MAP}.XXXXXX")
awk -v u="$user" -v n="$uid" '{line=$0; sub(/#.*/,"",line); split(line,f)} !(f[1]==u || f[1]==n)' "$MAP" > "$tmp"
chown root:root "$tmp"; chmod 0644 "$tmp"; mv -f "$tmp" "$MAP"
shred -u "/var/lib/krb-hpc/ccache/krb5cc_${uid}" 2>/dev/null || true       # master copy
# the copy in $HOME, removed as the user (root may be squashed on shared homes)
setpriv --reuid="$uid" --regid="$gid" --init-groups \
    sh -c 'f="$1/.krb5/krb5cc_hpc"; [ -f "$f" ] && { shred -u "$f" 2>/dev/null || rm -f "$f"; }; true' _ "$home"
echo "revoked ${user}; for a hard cutoff, drop their backend authorization and/or disable the AD account."
