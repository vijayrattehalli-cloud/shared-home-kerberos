#!/bin/bash
# ============================================================================
# verify-shared-home.sh  --  end-to-end test of the PYTHON shared-home package.
#
#   1. krb-credd (Python) issues a FORWARDABLE TGT from an escrowed keytab into
#      the user's home dir ($HOME/.krb5/krb5cc_hpc), written AS THE USER.
#   2. Every "compute node" (simulated: readers of that SAME shared-home path)
#      uses the ticket to reach the service -- the whole propagation mechanism.
#   3. A service accepts it over GSSAPI and auth_to_local maps the account.
#   4. The squeue-watch refresh loop renews the in-home ticket live.
#
# A single MIT realm stands in for enterprise AD. No JDK, no Sybil, no KCM.
# Requires: MIT krb5 tools, python3, setpriv, and root (setpriv + runuser).
# ============================================================================
set -uo pipefail
command -v krb5kdc >/dev/null || { echo "need MIT krb5 tools on PATH"; exit 1; }
[ "$(id -u)" = 0 ] || { echo "run as root (needs setpriv/runuser)"; exit 1; }
REPO=$(cd "$(dirname "$0")/.." && pwd)
CREDD="$REPO/bin/krb-credd"; GET="$REPO/bin/krb-get"; HELPER="$REPO/bin/krb-install-ccache"
pass(){ echo "PASS  $*"; }; fail(){ echo "FAIL  $*"; exit 1; }

REALM=ENT.TEST; P=$(( (RANDOM%2000)+27000 )); GP=$((P+2)); H=$(hostname)
R=$(mktemp -d "${TMPDIR:-/tmp}/shpy.XXXX"); chmod 755 "$R"
mkdir -p "$R/home"; chmod 755 "$R/home"
id shuser >/dev/null 2>&1 || useradd -u 24070 -m -d "$R/home/shuser" shuser
HOMEDIR=$(getent passwd shuser | cut -d: -f6); mkdir -p "$HOMEDIR"; chown shuser:shuser "$HOMEDIR"; chmod 700 "$HOMEDIR"
rm -f "$HOMEDIR/.krb5/krb5cc_hpc"
mkdir -p "$R/kt" "$R/run" "$R/bin" "$R/state" "$R/db"; chmod 700 "$R/kt"; chmod 755 "$R/run" "$R/state"

cat > "$R/krb5.conf" <<EOC
[libdefaults]
  default_realm = $REALM
  dns_lookup_kdc = false
  rdns = false
  forwardable = true
  noaddresses = true
  udp_preference_limit = 1
[realms]
  $REALM = {
    kdc = 127.0.0.1:$P
    auth_to_local = RULE:[1:\$1@\$0](^hpc-.*@$REALM\$)s/^hpc-//s/@$REALM\$//
    auth_to_local = DEFAULT
  }
EOC
cat > "$R/kdc.conf" <<EOC
[kdcdefaults]
  kdc_listen = $P
  kdc_tcp_listen = $P
[realms]
  $REALM = {
    database_name = $R/db/principal
    key_stash_file = $R/db/stash
    max_life = 10h
    max_renewable_life = 7d
    supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
  }
EOC
export KRB5_CONFIG=$R/krb5.conf KRB5_KDC_PROFILE=$R/kdc.conf
kdb5_util create -s -r $REALM -P m >/dev/null 2>&1
kadmin.local -q "addprinc -randkey -maxrenewlife 7d hpc-shuser" >/dev/null 2>&1
kadmin.local -q "ktadd -k $R/kt/hpc-shuser.keytab hpc-shuser" >/dev/null 2>&1
kadmin.local -q "addprinc -randkey hive/$H" >/dev/null 2>&1
kadmin.local -q "ktadd -k $R/hive.keytab hive/$H" >/dev/null 2>&1
krb5kdc -n -r $REALM >/dev/null 2>&1 & KDCPID=$!
printf '#!/bin/sh\nid -u shuser\n' > "$R/bin/squeue"; chmod +x "$R/bin/squeue"
install -D -m755 "$HELPER" "$R/bin/krb-install-ccache"
printf 'shuser hpc-shuser\n' > "$R/uidmap"; chmod 644 "$R/uidmap"
cat > "$R/credd.conf" <<EOC
[broker]
realm = $REALM
krb5_conf = $KRB5_CONFIG
keytab_dir = $R/kt
state_dir = $R/state
map_file = $R/uidmap
unix_socket = $R/run/sock
ccache_path = {home}/.krb5/krb5cc_hpc
install_helper = $R/bin/krb-install-ccache
refresh_interval = 3s
renew_margin = 11h
watch_slurm = true
squeue = $R/bin/squeue
EOC
python3 "$CREDD" -c "$R/credd.conf" >"$R/daemon.log" 2>&1 & DPID=$!
trap 'kill $KDCPID $DPID 2>/dev/null; pkill -f "gss-server -port $GP" 2>/dev/null; userdel -r shuser 2>/dev/null; rm -rf "$R"' EXIT
sleep 2

as(){ runuser -u shuser -- env KRB5_CONFIG="$KRB5_CONFIG" KRB_HPC_SOCKET="$R/run/sock" "$@"; }

out=$(as python3 "$GET" 2>&1)
[ "$out" = "export KRB5CCNAME=FILE:$HOMEDIR/.krb5/krb5cc_hpc" ] \
  && pass "krb-credd (Python) issued TGT into shared home: $HOMEDIR/.krb5/krb5cc_hpc" || fail "krb-get: $out"
[ "$(stat -c '%U %a' "$HOMEDIR/.krb5/krb5cc_hpc")" = "shuser 600" ] \
  && pass "ticket owned by shuser, mode 600" || fail "ownership/mode"
as env LC_ALL=C klist -f -c "FILE:$HOMEDIR/.krb5/krb5cc_hpc" | grep -q "Flags:.*F" \
  && pass "TGT is forwardable (F)" || fail "not forwardable"

ok=0
for n in 1 2 3 4; do
  as env KRB5CCNAME="FILE:$HOMEDIR/.krb5/krb5cc_hpc" kvno hive/$H@$REALM >/dev/null 2>&1 && ok=$((ok+1))
done
[ "$ok" = 4 ] && pass "all 4 simulated compute nodes used the in-home ticket to reach the service" \
  || fail "only $ok/4 nodes succeeded"

gss-server -port $GP -keytab $R/hive.keytab hive@$H >"$R/gss.log" 2>&1 & sleep 2
OUT=$(as env KRB5CCNAME="FILE:$HOMEDIR/.krb5/krb5cc_hpc" sh -c "/opt/mitkrb5/bin/gss-client -port $GP $H hive q 2>/dev/null || gss-client -port $GP $H hive q" 2>&1 || true)
OUT="$OUT$(cat "$R/gss.log" 2>/dev/null)"
echo "$OUT" | grep -qi "localname: shuser" && pass "service accepted ticket; auth_to_local -> 'shuser'" || fail "gss accept/map"

t1=$(as env LC_ALL=C klist -c "FILE:$HOMEDIR/.krb5/krb5cc_hpc" | awk '/krbtgt/{print $1,$2}')
sleep 7
t2=$(as env LC_ALL=C klist -c "FILE:$HOMEDIR/.krb5/krb5cc_hpc" | awk '/krbtgt/{print $1,$2}')
[ "$t1" != "$t2" ] && pass "squeue-watch renewed the in-home ticket ($t1 -> $t2)" || fail "no renewal ($t1)"

echo
echo "ALL CHECKS PASSED -- Python shared-home: one continuously-fresh ticket, visible on every node."
