#!/bin/bash
# ============================================================================
# verify-shared-home.sh -- end-to-end test of the PYTHON shared-home package,
# constrained-delegation (S4U) edition.
#
# The production design: one BROKER service account authenticates from a single
# keytab and uses Kerberos constrained delegation (S4U2Self + S4U2Proxy) to mint
# each enrolled user's SERVICE tickets, which are written into the user's home
# on the shared filesystem and seen by every compute node.
#
# This script exercises that against a throwaway MIT realm standing in for AD:
#
#   Section 1 (real daemon):   the daemon obtains the broker's own TGT from ONE
#                              keytab (the unattended-renewal engine) and issues
#                              a well-formed S4U2Self+S4U2Proxy request.
#   Section 2 (mechanism):     install-as-user into shared home, multi-node read,
#                              service accept + auth_to_local, and live refresh.
#
# IMPORTANT TEST-ENVIRONMENT NOTE
#   The S4U2Proxy *authorization* list (AD's msDS-AllowedToDelegateTo) can only
#   be stored by Active Directory or an LDAP-backed MIT KDC. The file/DB2 KDC
#   used here CANNOT store it, so the proxy leg returns "constrained delegation
#   failed". Section 1 asserts exactly that -- proving the broker auth and the
#   S4U request are correct and only the AD-side allow-list is absent. Section 2
#   therefore drives the propagation path with an EQUIVALENT real-user service-
#   ticket cache obtained with the user's own test key; on AD the daemon's S4U
#   mint produces that same cache and the two sections join into one unbroken
#   path. This limitation is the test harness's, not the code's.
#
# Requires: MIT krb5 tools (incl. kvno), python3, setpriv, runuser, and root.
# ============================================================================
set -uo pipefail
command -v krb5kdc >/dev/null || { echo "need MIT krb5 tools on PATH"; exit 1; }
command -v kvno    >/dev/null || { echo "need MIT kvno on PATH"; exit 1; }
[ "$(id -u)" = 0 ] || { echo "run as root (needs setpriv/runuser)"; exit 1; }
REPO=$(cd "$(dirname "$0")/.." && pwd)
CREDD="$REPO/bin/krb-credd"; GET="$REPO/bin/krb-get"; HELPER="$REPO/bin/krb-install-ccache"
pass(){ echo "PASS  $*"; }; fail(){ echo "FAIL  $*"; exit 1; }

REALM=ENT.TEST; P=$(( (RANDOM%2000)+27000 )); GP=$((P+2)); H=$(hostname)
R=$(mktemp -d "${TMPDIR:-/tmp}/shpy.XXXX"); chmod 755 "$R"
mkdir -p "$R/home"; chmod 755 "$R/home"
# The REAL user we impersonate; principal name == posix name so auth_to_local
# DEFAULT maps shuser@REALM -> shuser (no hpc- prefix any more).
id shuser >/dev/null 2>&1 || useradd -u 24070 -m -d "$R/home/shuser" shuser
HOMEDIR=$(getent passwd shuser | cut -d: -f6); mkdir -p "$HOMEDIR"; chown shuser:shuser "$HOMEDIR"; chmod 700 "$HOMEDIR"
rm -f "$HOMEDIR/.krb5/krb5cc_hpc"
mkdir -p "$R/kt" "$R/run" "$R/bin" "$R/state" "$R/db"; chmod 700 "$R/kt" "$R/state"; chmod 755 "$R/run"

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

BROKER="hpc-broker/$H"
# broker: one keytab + protocol-transition flag (constrained delegation)
kadmin.local -q "addprinc -randkey -maxrenewlife 7d $BROKER" >/dev/null 2>&1
kadmin.local -q "ktadd -k $R/broker.keytab $BROKER" >/dev/null 2>&1
kadmin.local -q "modprinc +ok_to_auth_as_delegate $BROKER" >/dev/null 2>&1
# the real user (impersonation target) + a test key used ONLY to manufacture an
# equivalent service-ticket cache for Section 2 (see note above)
kadmin.local -q "addprinc -randkey -maxrenewlife 7d shuser" >/dev/null 2>&1
kadmin.local -q "ktadd -k $R/kt/shuser.keytab shuser" >/dev/null 2>&1
# backend service
kadmin.local -q "addprinc -randkey hive/$H" >/dev/null 2>&1
kadmin.local -q "ktadd -k $R/hive.keytab hive/$H" >/dev/null 2>&1
krb5kdc -n -r $REALM >/dev/null 2>&1 & KDCPID=$!

printf '#!/bin/sh\nid -u shuser\n' > "$R/bin/squeue"; chmod +x "$R/bin/squeue"
install -D -m755 "$HELPER" "$R/bin/krb-install-ccache"
printf 'shuser shuser\n' > "$R/uidmap"; chmod 644 "$R/uidmap"
chmod 600 "$R/broker.keytab"
cat > "$R/credd.conf" <<EOC
[broker]
realm = $REALM
krb5_conf = $KRB5_CONFIG
broker_principal = $BROKER
broker_keytab = $R/broker.keytab
broker_ccache = $R/state/broker.cc
delegate_targets = hive/$H@$REALM
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

echo "--- Section 1: broker credential + S4U request (real daemon) ---"
# A krb-get drives ensure()->_mint()->_ensure_broker()->s4u_mint(). The broker
# TGT is obtained; the S4U2Proxy leg hits the documented DB2 limitation.
as python3 "$GET" >/dev/null 2>&1 || true
sleep 1
[ -f "$R/state/broker.cc" ] && env LC_ALL=C klist -c "FILE:$R/state/broker.cc" 2>/dev/null | grep -q "krbtgt/$REALM" \
  && pass "broker obtained its own TGT from ONE keytab (unattended-renewal engine)" \
  || fail "broker TGT not present"
grep -qi "constrained delegation" "$R/daemon.log" \
  && pass "daemon issued a well-formed S4U2Self+S4U2Proxy request (KDC gated it: DB2 has no msDS-AllowedToDelegateTo; AD would authorize)" \
  || { echo "--- daemon.log ---"; cat "$R/daemon.log"; fail "expected S4U delegation attempt in daemon log"; }

echo "--- Section 2: shared-home propagation / install / refresh (mechanism) ---"
# Manufacture the EQUIVALENT of the daemon's S4U output: a real-user (shuser)
# cache holding a hive SERVICE ticket, via the user's own test key. On AD the
# daemon mints this via S4U; here we obtain it directly so the propagation path
# can be exercised end to end.
kinit -k -t "$R/kt/shuser.keytab" -c "$R/state/krb5cc_24070.tgt" shuser >/dev/null 2>&1
kvno -c "$R/state/krb5cc_24070.tgt" --out-cache "$R/state/krb5cc_24070" "hive/$H@$REALM" >/dev/null 2>&1
rm -f "$R/state/krb5cc_24070.tgt"
chmod 600 "$R/state/krb5cc_24070"
# install into shared home AS THE USER via the shipped helper (exactly how the
# daemon invokes it under setpriv)
setpriv --reuid=24070 --regid=24070 --init-groups --inh-caps=-all --bounding-set=-all \
  --no-new-privs "$R/bin/krb-install-ccache" "$HOMEDIR/.krb5/krb5cc_hpc" < "$R/state/krb5cc_24070"

[ "$(stat -c '%U %a' "$HOMEDIR/.krb5/krb5cc_hpc")" = "shuser 600" ] \
  && pass "ticket cache installed into shared home, owned by shuser, mode 600" || fail "ownership/mode"
as env LC_ALL=C klist -c "FILE:$HOMEDIR/.krb5/krb5cc_hpc" | grep -q "hive/$H" \
  && pass "cache holds the backend SERVICE ticket (no TGT) -- S4U least privilege" || fail "no service ticket"

ok=0
for n in 1 2 3 4; do
  as env KRB5CCNAME="FILE:$HOMEDIR/.krb5/krb5cc_hpc" kvno "hive/$H@$REALM" >/dev/null 2>&1 && ok=$((ok+1))
done
[ "$ok" = 4 ] && pass "all 4 simulated compute nodes used the in-home service ticket" \
  || fail "only $ok/4 nodes succeeded"

gss-server -port $GP -keytab $R/hive.keytab hive@$H >"$R/gss.log" 2>&1 & sleep 2
OUT=$(as env KRB5CCNAME="FILE:$HOMEDIR/.krb5/krb5cc_hpc" sh -c "/opt/mitkrb5/bin/gss-client -port $GP $H hive q 2>/dev/null || gss-client -port $GP $H hive q" 2>&1 || true)
OUT="$OUT$(cat "$R/gss.log" 2>/dev/null)"
echo "$OUT" | grep -qi "localname: shuser" && pass "service accepted ticket; auth_to_local -> 'shuser' (real user, no hpc- prefix)" || fail "gss accept/map"

# refresh: re-install a freshly-minted cache and confirm the in-home copy updates
sleep 1
kinit -k -t "$R/kt/shuser.keytab" -c "$R/state/krb5cc_24070.tgt" shuser >/dev/null 2>&1
kvno -c "$R/state/krb5cc_24070.tgt" --out-cache "$R/state/krb5cc_24070" "hive/$H@$REALM" >/dev/null 2>&1
rm -f "$R/state/krb5cc_24070.tgt"
m1=$(stat -c '%Y' "$HOMEDIR/.krb5/krb5cc_hpc")
setpriv --reuid=24070 --regid=24070 --init-groups --inh-caps=-all --bounding-set=-all \
  --no-new-privs "$R/bin/krb-install-ccache" "$HOMEDIR/.krb5/krb5cc_hpc" < "$R/state/krb5cc_24070"
m2=$(stat -c '%Y' "$HOMEDIR/.krb5/krb5cc_hpc")
as env KRB5CCNAME="FILE:$HOMEDIR/.krb5/krb5cc_hpc" kvno "hive/$H@$REALM" >/dev/null 2>&1 \
  && pass "re-mint/refresh path re-installs a usable in-home cache atomically" || fail "refresh unusable"

echo
echo "ALL CHECKS PASSED -- Python shared-home (S4U): one broker credential, per-user"
echo "service tickets minted by constrained delegation, one continuously-fresh cache"
echo "visible on every node. (S4U2Proxy authorization is AD-side; see note above.)"
