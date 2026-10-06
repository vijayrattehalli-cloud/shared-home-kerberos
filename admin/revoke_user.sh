#!/bin/bash
# Revoke an HPC user's Kerberos access (works for both solutions).
#   revoke_user.sh <hpc-username> <ad-sAMAccountName>
# Removing the mapping stops both daemons from issuing or refreshing tickets
# (the map is re-read on change). Tickets already issued stay valid until they
# expire, so ALSO disable the AD account (Disable-ADAccount) to block renewals.
set -euo pipefail
user="$1"; sam="$2"
uid=$(id -u "$user"); gid=$(id -g "$user"); home=$(getent passwd "$user" | cut -d: -f6)
sed -i "/^${user}[[:space:]]/d;/^${uid}[[:space:]]/d" /etc/krb-hpc/uidmap.conf
shred -u "/etc/krb-hpc/keytabs/${sam}.keytab" 2>/dev/null || true
shred -u "/var/lib/krb-hpc/ccache/krb5cc_${uid}" 2>/dev/null || true      # solution A master copy
# the copy in $HOME, removed as the user (root may be squashed on shared homes)
setpriv --reuid="$uid" --regid="$gid" --init-groups \
    sh -c 'f="$1/.krb5/krb5cc_hpc"; [ -f "$f" ] && { shred -u "$f" 2>/dev/null || rm -f "$f"; }; true' _ "$home"
echo "revoked ${user}; now disable AD account ${sam} so outstanding TGTs cannot be renewed."
