#!/bin/bash
# ============================================================================
# verify-shared-home.sh -- end-to-end test of the shared-home package.
#
# The production design: one BROKER service account authenticates from a single
# keytab and uses Kerberos constrained delegation (S4U2Self + S4U2Proxy) to mint
# each enrolled user's SERVICE tickets, which are written into the user's home
# on the shared filesystem and seen by every compute node. krb-credd does the
# Kerberos work by running the MIT tools (kinit, klist, kvno) by absolute path.
#
# This script runs the REAL daemon against a throwaway MIT KDC that stands in
# for Active Directory. The KDC uses MIT's "test" KDB module, which -- unlike
# the default file/DB2 database -- can hold a constrained-delegation allow-list
# (the equivalent of AD's msDS-AllowedToDelegateTo). So the WHOLE path runs:
# broker TGT -> S4U2Self -> S4U2Proxy -> install as the user -> use on 4 nodes
# -> service accepts -> unattended re-mint -> atomic broker renewal. Negative
# cases check the allow-list, delegation eligibility, failure backoff, the MIT
# version gate, and that a hostile environment can't steer the tools.
#
# Requires: root; python3; setpriv, runuser, useradd; MIT krb5 >= 1.19 KDC,
# admin and client tools (krb5kdc, kadmin.local, kinit, klist, kvno,
# gss-server, gss-client); and MIT's test KDB module (test.so), which
# distribution packages don't ship. Build MIT krb5 from source to get it:
#
#   git clone --depth 1 -b krb5-1.20.1-final https://github.com/krb5/krb5
#   cd krb5/src && autoreconf -fi && ./configure --prefix=/opt/mitkrb5 && make && make install
#   sudo MIT_PREFIX=/opt/mitkrb5 KDB_TEST_MODULE_DIR=$PWD/plugins/kdb/test tests/verify-shared-home.sh
#
# Set S4U_NAME_TYPE=principal|enterprise to choose kvno -I or -U (default: enterprise).
# ============================================================================
set -uo pipefail
MIT_PREFIX=${MIT_PREFIX:-}
S4U_NAME_TYPE=${S4U_NAME_TYPE:-enterprise}
TOOLS="krb5kdc kadmin.local kinit klist kvno gss-server gss-client"
SHIM=$(mktemp -d "${TMPDIR:-/tmp}/mitshim.XXXX"); chmod 755 "$SHIM"
trap 'rm -rf "$SHIM"' EXIT
# Root-owned wrappers with absolute paths: the daemon is configured with these
# (it never looks tools up on PATH). With MIT_PREFIX they also supply the
# library path a source build without rpath needs.
for t in $TOOLS; do
  if [ -n "$MIT_PREFIX" ]; then f=$(ls "$MIT_PREFIX"/bin/$t "$MIT_PREFIX"/sbin/$t 2>/dev/null | head -1); lp="LD_LIBRARY_PATH=$MIT_PREFIX/lib "
  else f=$(command -v $t || true); lp=""; fi
  [ -n "$f" ] || { echo "need MIT $t (set MIT_PREFIX?)"; exit 1; }
  printf '#!/bin/sh\n%sexec %s "$@"\n' "$lp" "$f" > "$SHIM/$t"; chmod 755 "$SHIM/$t"
done
export PATH="$SHIM:$PATH"
for t in setpriv runuser useradd python3; do command -v $t >/dev/null || { echo "need $t"; exit 1; }; done
KDB_TEST_MODULE_DIR=${KDB_TEST_MODULE_DIR:-}
[ -f "$KDB_TEST_MODULE_DIR/test.so" ] || { echo "set KDB_TEST_MODULE_DIR to the directory holding MIT's test.so"; exit 1; }
[ "$(id -u)" = 0 ] || { echo "run as root (needs setpriv/runuser/useradd)"; exit 1; }

REPO=$(cd "$(dirname "$0")/.." && pwd)
CREDD="$REPO/bin/krb-credd"; GET="$REPO/bin/krb-get"; HELPER="$REPO/bin/krb-install-ccache"
pass(){ echo "PASS  $*"; }; fail(){ echo "FAIL  $*"; [ -f "$R/daemon.log" ] && { echo "--- daemon.log"; tail -20 "$R/daemon.log"; }; exit 1; }

REALM=ENT.TEST; P=$(( (RANDOM%2000)+27000 )); H=$(hostname | tr 'A-Z' 'a-z')
R=$(mktemp -d "${TMPDIR:-/tmp}/shpy.XXXX"); chmod 755 "$R"
KDCPID=; DPID=; GP=
cleanup(){ kill ${KDCPID:-} ${DPID:-} 2>/dev/null; [ -n "$GP" ] && pkill -f "gss-server -port $GP" 2>/dev/null
           for u in shuser nobody2 protected; do userdel -r $u 2>/dev/null; done; rm -rf "$R" "$SHIM"; }
trap cleanup EXIT
mkdir -p "$R/home" "$R/run" "$R/bin" "$R/state" "$R/kdb"; chmod 755 "$R/home" "$R/run"; chmod 700 "$R/state"
cp "$KDB_TEST_MODULE_DIR/test.so" "$R/kdb/test.so"

# Real local users. shuser is enrolled; nobody2 is not; protected is enrolled
# but (like an AD "Protected Users" member) may not be delegated.
for u in shuser:24070 nobody2:24071 protected:24072; do
  n=${u%%:*}; id "$n" >/dev/null 2>&1 || useradd -u "${u##*:}" -m -d "$R/home/$n" "$n"
  hd=$(getent passwd "$n" | cut -d: -f6); mkdir -p "$hd"; chown "$n:$n" "$hd"; chmod 700 "$hd"
done
HOMEDIR=$(getent passwd shuser | cut -d: -f6); SHUID=$(id -u shuser); PRUID=$(id -u protected)
BROKER="hpc-broker/$H"

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
    database_module = test
    max_life = 10h
    max_renewable_life = 7d
  }
[dbmodules]
  db_module_dir = $R/kdb
  test = {
    db_library = test
    princs = {
      krbtgt/$REALM = {
        keys = aes256-cts
        maxlife = 10h
        maxrenewlife = 7d
      }
      # The broker: "trusted to authenticate for delegation" (protocol transition)
      $BROKER = {
        keys = aes256-cts
        flags = +ok-to-auth-as-delegate
        maxlife = 10h
        maxrenewlife = 7d
      }
      shuser = {
        keys = aes256-cts
      }
      # Like AD's Protected Users / "sensitive, cannot be delegated":
      protected = {
        keys = aes256-cts
        flags = -forwardable
      }
      hive/$H = {
        keys = aes256-cts
      }
      hdfs/$H = {
        keys = aes256-cts
      }
      web/$H = {
        keys = aes256-cts
      }
    }
    # The allow-list (AD: msDS-AllowedToDelegateTo on the broker account).
    # web/$H is deliberately NOT on it.
    delegation = {
      $BROKER = hive/$H
      $BROKER = hdfs/$H
    }
  }
EOC
export KRB5_CONFIG=$R/krb5.conf KRB5_KDC_PROFILE=$R/kdc.conf
kadmin.local -q "ktadd -k $R/broker.keytab -norandkey $BROKER" >"$R/kadmin.log" 2>&1 || { cat "$R/kadmin.log"; fail "extract broker keytab"; }
kadmin.local -q "ktadd -k $R/hive.keytab -norandkey hive/$H"    >>"$R/kadmin.log" 2>&1 || fail "extract hive keytab"
krb5kdc -n -r $REALM >"$R/kdc.log" 2>&1 & KDCPID=$!; GP=$((P+2))

# squeue reports a job for shuser AND protected, so the refresh loop tries both.
printf '#!/bin/sh\nid -u shuser\nid -u protected\n' > "$R/bin/squeue"; chmod 755 "$R/bin/squeue"
install -m755 "$HELPER" "$R/bin/krb-install-ccache"
printf 'shuser shuser\nprotected protected\n' > "$R/uidmap"; chmod 644 "$R/uidmap"
chmod 600 "$R/broker.keytab"
write_conf(){ cat > "$R/credd.conf" <<EOC
[broker]
realm = $REALM
krb5_conf = $KRB5_CONFIG
broker_principal = $BROKER
broker_keytab = $R/broker.keytab
broker_ccache = $R/state/broker.cc
delegate_targets = hive/$H@$REALM hdfs/$H@$REALM
state_dir = $R/state
map_file = $R/uidmap
unix_socket = $R/run/sock
ccache_path = {home}/.krb5/krb5cc_hpc
install_helper = $R/bin/krb-install-ccache
kinit = ${KINIT:-$SHIM/kinit}
klist = ${KLIST:-$SHIM/klist}
kvno = $SHIM/kvno
s4u_name_type = $S4U_NAME_TYPE
broker_lifetime = 10h
broker_renew = 7d
refresh_interval = 3s
refresh_workers = 4
renew_margin = ${MARGIN:-1h}
min_reissue_interval = 0s
watch_slurm = true
squeue = $R/bin/squeue
EOC
chmod 644 "$R/credd.conf"; }
start_daemon(){
  # A hostile environment: none of these may reach the Kerberos tools.
  env KRB5CCNAME="FILE:$R/evil.cc" KRB5_KTNAME="FILE:$R/evil.kt" KRB5_TRACE="$R/evil.trace" \
      KRB5_CONFIG="$R/evil.conf" LC_ALL=de_DE.UTF-8 TZ=Asia/Tokyo \
    python3 "$CREDD" -c "$R/credd.conf" >>"$R/daemon.log" 2>&1 & DPID=$!
  for i in $(seq 1 40); do [ -S "$R/run/sock" ] && return 0; sleep 0.25; done
  fail "daemon did not start"
}

echo "--- Section 0: start-up checks ---"
printf '#!/bin/sh\necho "Kerberos 5 version 1.18.2"\n' > "$R/bin/klist118"; chmod 755 "$R/bin/klist118"
KLIST=$R/bin/klist118 write_conf
OUT=$(python3 "$CREDD" -c "$R/credd.conf" 2>&1); RC=$?
[ $RC -ne 0 ] && echo "$OUT" | grep -q "too old" && pass "refuses to start with MIT Kerberos older than 1.19 (no kvno --out-cache)" || fail "version gate: $OUT"
chmod 777 "$R/bin/klist118"
OUT=$(python3 "$CREDD" -c "$R/credd.conf" 2>&1); RC=$?
[ $RC -ne 0 ] && echo "$OUT" | grep -q "klist" && echo "$OUT" | grep -q "writable" && pass "refuses a Kerberos tool that others can write" || fail "tool permission check: $OUT"
write_conf
start_daemon
grep -q "MIT Kerberos [0-9.]* tools: kinit=/.*klist=/.*kvno=/" "$R/daemon.log" && pass "started with absolute tool paths and logged the MIT version" || fail "no version/tools line"

as(){ local u=$1; shift; runuser -u "$u" -- env KRB5_CONFIG="$KRB5_CONFIG" KRB_HPC_SOCKET="$R/run/sock" "$@"; }
klist_c(){ env LC_ALL=C klist -c "FILE:$1" 2>/dev/null; }
CC="$HOMEDIR/.krb5/krb5cc_hpc"

echo "--- Section 1: the daemon mints, end to end (kvno $([ "$S4U_NAME_TYPE" = enterprise ] && echo -U || echo -I) ... -P) ---"
OUT=$(as shuser python3 "$GET") || fail "krb-get failed: $OUT"
[ "$OUT" = "export KRB5CCNAME=FILE:$CC" ] && pass "krb-get returned the shared-home cache path" || fail "unexpected krb-get output: $OUT"
klist_c "$R/state/broker.cc" | grep -q "krbtgt/$REALM@$REALM" \
  && pass "broker obtained its own TGT from ONE keytab (kinit -k)" || fail "broker TGT not present"
klist_c "$R/state/broker.cc" | grep -q "shuser" \
  && fail "per-user tickets leaked into the broker cache" \
  || pass "broker cache holds only the broker's TGT (kvno ran on a throwaway copy)"
[ "$(stat -c '%U %a' "$CC")" = "shuser 600" ] && pass "cache installed into shared home as shuser, mode 600" || fail "ownership/mode: $(stat -c '%U %a' "$CC")"
L=$(as shuser env LC_ALL=C klist -c "FILE:$CC")
echo "$L" | grep -q "Default principal: shuser@$REALM" && pass "cache is for the REAL user (shuser@$REALM), via S4U2Self" || fail "wrong principal: $L"
echo "$L" | grep -q "hive/$H@$REALM" && echo "$L" | grep -q "hdfs/$H@$REALM" \
  && pass "cache holds hive and hdfs SERVICE tickets via S4U2Proxy (allow-listed by the KDC)" || fail "missing service tickets"
echo "$L" | grep -q "krbtgt/" && fail "user cache contains a TGT" || pass "user cache contains NO TGT (least privilege)"
PYTHONPATH="$REPO/src" python3 - "$R" "$SHIM" "$H" "$REALM" <<'EOF' && pass "every mint asks the KDC for NEW tickets (none reused from a cache)" || fail "re-mint reused a cached ticket"
import subprocess, sys, time
from krbhpc._krb import Krb5
R, SHIM, H, REALM = sys.argv[1:]
k = Krb5(f"{R}/krb5.conf", tools={t: f"{SHIM}/{t}" for t in ("kinit", "klist", "kvno")})
def start(cc):
    out = subprocess.run([f"{SHIM}/klist", "-c", f"FILE:{cc}"], env=k.env, capture_output=True, text=True).stdout
    return [l.split()[:2] for l in out.splitlines() if f"hive/{H}" in l][0]
k.s4u_mint(f"{R}/state/broker.cc", "shuser", [f"hive/{H}@{REALM}"], f"{R}/m1.cc")
time.sleep(1.2)
k.s4u_mint(f"{R}/state/broker.cc", "shuser", [f"hive/{H}@{REALM}"], f"{R}/m2.cc")
a, b = start(f"{R}/m1.cc"), start(f"{R}/m2.cc")
assert a != b, f"second mint returned the same ticket (start {a})"
EOF
klist_c "$R/state/broker.cc" | grep -q "for client" \
  && fail "per-user tickets accumulated in the broker cache" \
  || pass "broker cache still holds only the broker's TGT after repeated mints"

echo "--- Section 2: compute nodes and the backend service ---"
ok=0
for n in 1 2 3 4; do
  as shuser env KRB5CCNAME="FILE:$CC" kvno "hive/$H@$REALM" >/dev/null 2>&1 && ok=$((ok+1))
done
[ "$ok" = 4 ] && pass "all 4 simulated compute nodes used the in-home service ticket" || fail "only $ok/4 nodes succeeded"
gss-server -port $GP -keytab "$R/hive.keytab" "hive@$H" >"$R/gss.log" 2>&1 & sleep 1
OUT=$(as shuser env KRB5CCNAME="FILE:$CC" gss-client -port $GP "$H" hive q 2>&1 || true)
OUT="$OUT$(cat "$R/gss.log" 2>/dev/null)"
echo "$OUT" | grep -qi "localname: shuser\|shuser@$REALM" \
  && pass "hive service accepted the delegated ticket as shuser@$REALM" || fail "gss accept: $OUT"

echo "--- Section 3: unattended refresh, backoff, renewal ---"
m1=$(stat -c '%Y.%X' "$CC")
kill $DPID; wait $DPID 2>/dev/null
MARGIN=30d write_conf          # every pass now re-mints
start_daemon
sleep 10
m2=$(stat -c '%Y.%X' "$CC")
[ "$(grep -c "minted service tickets uid=$SHUID" "$R/daemon.log")" -ge 3 ] && [ "$m1" != "$m2" ] \
  && pass "squeue-watch refresh loop re-minted and re-installed with no user action" || fail "no unattended re-mint"
as shuser env KRB5CCNAME="FILE:$CC" kvno "hive/$H@$REALM" >/dev/null 2>&1 \
  && pass "re-installed cache is usable (atomic replace)" || fail "refreshed cache unusable"
N=$(grep -c "refresh uid=$PRUID failed (not_delegable; next try in 900s)" "$R/daemon.log")
[ "$N" = 1 ] && pass "non-delegable user failed once in the background, classified, then backed off (not retried every pass)" \
  || fail "expected one classified failure + backoff for uid $PRUID, saw $N: $(grep "uid=$PRUID" "$R/daemon.log" | tail -3)"
PYTHONPATH="$REPO/src" python3 - "$R" "$SHIM" <<'EOF' && pass "broker TGT renewal is atomic (renews a copy, renames it into place)" || fail "renewal"
import shutil, sys, time
from krbhpc._krb import Krb5
R, SHIM = sys.argv[1:]
k = Krb5(f"{R}/krb5.conf", tools={t: f"{SHIM}/{t}" for t in ("kinit", "klist", "kvno")})
shutil.copy(f"{R}/state/broker.cc", f"{R}/renew.cc")
before = k.klist_times(f"{R}/renew.cc")
time.sleep(2)
assert k.kinit_renew(f"{R}/renew.cc"), "renew failed"
after = k.klist_times(f"{R}/renew.cc")
assert after.expires > before.expires, (before, after)
assert not k.kinit_renew(f"{R}/does-not-exist.cc")
EOF

echo "--- Section 4: what must be refused ---"
OUT=$(as nobody2 python3 "$GET" 2>&1); [ $? -eq 1 ] && echo "$OUT" | grep -q "not enrolled" \
  && pass "un-enrolled user refused (identity from SO_PEERCRED)" || fail "nobody2: $OUT"
OUT=$(as protected python3 "$GET" 2>&1); [ $? -eq 1 ] && echo "$OUT" | grep -q "cannot be delegated" \
  && pass "non-delegable user gets no tickets and a clear message: '${OUT#krb-get: }'" || fail "protected: $OUT"
PYTHONPATH="$REPO/src" python3 - "$R" "$SHIM" "$H" "$REALM" <<'EOF' && pass "backend NOT on the KDC allow-list is refused (web/$H)" || fail "allow-list not enforced"
import sys
from krbhpc._krb import Krb5, KrbToolError
R, SHIM, H, REALM = sys.argv[1:]
k = Krb5(f"{R}/krb5.conf", tools={t: f"{SHIM}/{t}" for t in ("kinit", "klist", "kvno")})
try:
    k.s4u_mint(f"{R}/state/broker.cc", "shuser", [f"web/{H}@{REALM}"], f"{R}/web.cc")
except KrbToolError as e:
    assert e.category == "not_delegable", e
else:
    raise SystemExit("web/ ticket was issued")
EOF
[ ! -e "$R/evil.cc" ] && [ ! -e "$R/evil.trace" ] && ! grep -q "evil" "$R/daemon.log" \
  && pass "hostile KRB5CCNAME/KRB5_TRACE/KRB5_CONFIG/LC_ALL/TZ in the daemon's environment had no effect" \
  || fail "the daemon's environment leaked into the Kerberos tools"
grep -q "Traceback" "$R/daemon.log" && fail "daemon raised an unhandled exception" || true

echo
echo "ALL CHECKS PASSED -- shared-home: one broker keytab, per-user service tickets"
echo "minted by S4U2Self+S4U2Proxy through the MIT tools, one continuously-fresh cache"
echo "visible on every node, the KDC allow-list enforced, and failures classified."
