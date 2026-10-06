#!/bin/bash
# ============================================================================
# verify-shared-home.sh  --  prove the shared-home architecture end to end.
#
#   1. krb-credd (JDK 24) issues a FORWARDABLE TGT from an escrowed keytab
#      into the user's home dir  ($HOME/.krb5/krb5cc_hpc), as the user.
#   2. Every "compute node" (simulated: processes reading that SAME path, as
#      the shared FS would present it) can use the ticket to reach the service
#      -- this is the whole "propagation to all nodes" mechanism: no copy, no
#      agent, the file is simply visible everywhere.
#   3. The squeue-watch refresh loop renews the in-home ticket while a job runs,
#      so long jobs never see it expire.
#
# A single MIT realm stands in for enterprise AD (user + service both homed
# there). Needs: MIT krb5 tools, JDK 24 at $JAVA_HOME, root (for setpriv +
# runuser), and the built daemon jar.
# ============================================================================
set -euo pipefail
JAVA_HOME=${JAVA_HOME:-/opt/jdk24}
JAR=${JAR:-$(cd "$(dirname "$0")/.." && pwd)/daemon/krb-credd.jar}
HELPER=${HELPER:-$(cd "$(dirname "$0")/.." && pwd)/bin/krb-install-ccache}
GET_JAR=$JAR
[ -f "$JAR" ] || { echo "build the daemon first: daemon/build.sh"; exit 1; }
command -v krb5kdc >/dev/null || { echo "need MIT krb5 tools on PATH"; exit 1; }
[ "$(id -u)" = 0 ] || { echo "run as root (needs setpriv/runuser)"; exit 1; }
pass(){ echo "PASS  $*"; }; fail(){ echo "FAIL  $*"; exit 1; }

REALM=ENT.TEST; P=$(( (RANDOM%2000)+25000 )); GP=$((P+2)); H=$(hostname)
R=$(mktemp -d "${TMPDIR:-/tmp}/sh.XXXX"); chmod 755 "$R"
# dedicated test user with a shared-style home under $R (parent must exist first)
mkdir -p "$R/home"; chmod 755 "$R/home"
id shuser >/dev/null 2>&1 || useradd -u 24050 -m -d "$R/home/shuser" shuser
HOMEDIR=$(getent passwd shuser | cut -d: -f6)
mkdir -p "$HOMEDIR"; chown shuser:shuser "$HOMEDIR"; chmod 700 "$HOMEDIR"
rm -f "$HOMEDIR/.krb5/krb5cc_hpc"
mkdir -p "$R/kt" "$R/run" "$R/bin" "$R/state"; chmod 700 "$R/kt"; chmod 755 "$R/run" "$R/state"

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
mkdir -p "$R/db"
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
# escrowed keytab for the dedicated AD-style account, and the service
kadmin.local -q "addprinc -randkey -maxrenewlife 7d hpc-shuser" >/dev/null 2>&1
kadmin.local -q "ktadd -k $R/kt/hpc-shuser.keytab hpc-shuser" >/dev/null 2>&1
kadmin.local -q "addprinc -randkey hive/$H" >/dev/null 2>&1
kadmin.local -q "ktadd -k $R/hive.keytab hive/$H" >/dev/null 2>&1
krb5kdc -n -r $REALM >/dev/null 2>&1 & KDCPID=$!
# squeue stub: report shuser's uid as having a running job (drives the refresh watch)
printf '#!/bin/sh\nid -u shuser\n' > "$R/bin/squeue"; chmod +x "$R/bin/squeue"
install -D -m755 "$HELPER" "$R/bin/krb-install-ccache"
printf 'shuser hpc-shuser\n' > "$R/uidmap"; chmod 644 "$R/uidmap"
cat > "$R/credd.properties" <<EOC
realm=$REALM
keytab_dir=$R/kt
uid_map=$R/uidmap
socket=$R/run/sock
ccache_path={home}/.krb5/krb5cc_hpc
install_helper=$R/bin/krb-install-ccache
refresh_interval=3s
renew_margin=11h
watch_slurm=true
squeue=$R/bin/squeue
krb5_conf=$KRB5_CONFIG
EOC
"$JAVA_HOME/bin/java" -jar "$JAR" "$R/credd.properties" >"$R/daemon.log" 2>&1 & DPID=$!
trap 'kill $KDCPID $DPID 2>/dev/null; pkill -f "gss-server -port $GP" 2>/dev/null; userdel -r shuser 2>/dev/null; rm -rf "$R"' EXIT
sleep 2

as(){ runuser -u shuser -- env KRB5_CONFIG="$KRB5_CONFIG" KRB_HPC_SOCKET="$R/run/sock" "$@"; }

# 1. issue into home
out=$(as "$JAVA_HOME/bin/java" -cp "$GET_JAR" hpc.krb.KrbGet 2>&1 | grep -v Picked || true)
[ "$out" = "export KRB5CCNAME=FILE:$HOMEDIR/.krb5/krb5cc_hpc" ] \
  && pass "krb-credd issued TGT into shared home: $HOMEDIR/.krb5/krb5cc_hpc" || fail "krb-get: $out"
[ "$(stat -c '%U %a' "$HOMEDIR/.krb5/krb5cc_hpc")" = "shuser 600" ] \
  && pass "ticket owned by shuser, mode 600" || fail "ownership/mode"
as env LC_ALL=C klist -f -c "FILE:$HOMEDIR/.krb5/krb5cc_hpc" | grep -q "Flags:.*F" \
  && pass "TGT is forwardable (F)" || fail "not forwardable"

# 2. "every compute node sees the same file" -- N readers at the SAME path get service tickets
start=$(cat "$R/db/principal" >/dev/null; echo ok)
ok=0
for n in 1 2 3 4; do
  # each 'node' uses a private KRB5CCNAME copy-by-reference: it reads the shared-home file directly
  if as env KRB5CCNAME="FILE:$HOMEDIR/.krb5/krb5cc_hpc" kvno hive/$H@$REALM >/dev/null 2>&1; then
    ok=$((ok+1))
  fi
done
[ "$ok" = 4 ] && pass "all 4 simulated compute nodes used the in-home ticket to reach the service" || fail "only $ok/4 nodes succeeded"

# 3. service actually accepts it (GSSAPI) and maps the name
gss-server -port $GP -keytab $R/hive.keytab hive@$H >"$R/gss.log" 2>&1 & sleep 2
OUT=$(as env KRB5CCNAME="FILE:$HOMEDIR/.krb5/krb5cc_hpc" sh -c "/opt/mitkrb5/bin/gss-client -port $GP $H hive q" 2>&1 || true)
OUT="$OUT$(cat "$R/gss.log" 2>/dev/null)"
echo "$OUT" | grep -qi "localname: shuser" && pass "service accepted ticket; auth_to_local -> 'shuser'" || fail "gss accept/map"

# 4. refresh loop renews the in-home ticket while the (stubbed) job runs
t1=$(as env LC_ALL=C klist -c "FILE:$HOMEDIR/.krb5/krb5cc_hpc" | awk '/krbtgt/{print $1,$2}')
sleep 7
t2=$(as env LC_ALL=C klist -c "FILE:$HOMEDIR/.krb5/krb5cc_hpc" | awk '/krbtgt/{print $1,$2}')
[ "$t1" != "$t2" ] && pass "squeue-watch renewed the in-home ticket ($t1 -> $t2)" || fail "no renewal ($t1)"

echo
echo "ALL CHECKS PASSED -- shared home carries one continuously-fresh ticket to every node."
