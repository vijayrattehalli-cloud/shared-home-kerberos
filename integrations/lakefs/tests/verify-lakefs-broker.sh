#!/bin/bash
# ============================================================================
# verify-lakefs-broker.sh -- end-to-end test of the lakeFS credential broker.
#
#   Part 1 (mint path, HTTP):   the broker authenticates a principal (as
#       mod_auth_gssapi would, via REMOTE_USER), maps it to a lakeFS user, and
#       mints a short-lived lakeFS access key through the lakeFS Auth API
#       (stood up here as a stdlib mock). Asserts the returned key and that the
#       broker called lakeFS for the correctly mapped user with admin auth.
#
#   Part 2 (Kerberos SPN auth): a user's ticket authenticates to the broker's
#       HTTP/<host> service principal and resolves to the right local name --
#       exactly the identity mod_auth_gssapi hands the broker as REMOTE_USER.
#       Proven with MIT gss-server/gss-client against a throwaway KDC.
#
# Together these cover the whole bridge; the only piece not run here is Apache
# wiring Part 2's SPNEGO to Part 1's REMOTE_USER (see apache-mod-auth-gssapi.conf).
#
# Requires: python3 (Flask, requests), MIT krb5 tools (incl. gss-server), and
# a free TCP port range. No root required.
# ============================================================================
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
BROKER="$HERE/../broker/lakefs_cred_broker.py"
MOCK="$HERE/mock_lakefs.py"
pass(){ echo "PASS  $*"; }
fail(){ echo "FAIL  $*"; exit 1; }
python3 -c "import flask, requests" 2>/dev/null || { echo "need python3 Flask + requests"; exit 1; }
command -v gss-server >/dev/null || { echo "need MIT gss-server on PATH"; exit 1; }

R=$(mktemp -d "${TMPDIR:-/tmp}/lakefsb.XXXX")
LP=$(( (RANDOM%2000)+18000 )); BP=$((LP+1))      # mock-lakeFS and broker ports
REC="$R/mock_last.json"
ADMIN_KEY="AKIAADMINTEST"; ADMIN_SECRET="s3cr3t-admin"
PIDS=()
cleanup(){ for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
           pkill -f "gss-server -port" 2>/dev/null; rm -rf "$R"; }
trap cleanup EXIT

echo "--- Part 1: Kerberos identity -> short-lived lakeFS key (mint path) ---"
MOCK_LAKEFS_LISTEN="127.0.0.1:$LP" MOCK_LAKEFS_RECORD="$REC" MOCK_LAKEFS_ADMIN_KEY="$ADMIN_KEY" \
  python3 "$MOCK" >"$R/mock.log" 2>&1 & PIDS+=($!)
BROKER_LISTEN="127.0.0.1:$BP" \
BROKER_REMOTE_USER_SOURCE="header:X-Remote-User" \
BROKER_TRUSTED_PROXIES="127.0.0.1" \
BROKER_REALM="ENT.TEST" \
LAKEFS_ENDPOINT="http://127.0.0.1:$LP" \
LAKEFS_ADMIN_ACCESS_KEY_ID="$ADMIN_KEY" LAKEFS_ADMIN_SECRET_ACCESS_KEY="$ADMIN_SECRET" \
KEY_TTL_SECONDS="900" \
  python3 "$BROKER" >"$R/broker.log" 2>&1 & PIDS+=($!)

# wait for both to listen
for i in $(seq 1 40); do
  curl -fsS "http://127.0.0.1:$LP/healthz" >/dev/null 2>&1 && \
  curl -fsS "http://127.0.0.1:$BP/healthz" >/dev/null 2>&1 && break
  sleep 0.25
done

# a request WITHOUT an authenticated principal must be rejected (401)
code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://127.0.0.1:$BP/credentials")
[ "$code" = "401" ] && pass "unauthenticated request rejected (401 -- needs mod_auth_gssapi/REMOTE_USER)" \
  || fail "expected 401 for no principal, got $code"

# a spoofed header from an untrusted peer: covered by BROKER_TRUSTED_PROXIES
# (here the client IS 127.0.0.1, the trusted proxy, so this models Apache).
RESP=$(curl -fsS -X POST -H "X-Remote-User: jdoe@ENT.TEST" "http://127.0.0.1:$BP/credentials")
echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['access_key_id'].startswith('AKIAMOCK'); assert d['secret_access_key']; assert d['lakefs_user']=='jdoe'; assert d['principal']=='jdoe@ENT.TEST'; assert d['expiry']" \
  && pass "broker minted a short-lived lakeFS key for principal jdoe@ENT.TEST (user=jdoe, has expiry)" \
  || { echo "$RESP"; fail "broker response malformed"; }

# the broker must have called lakeFS for the MAPPED user, with admin auth
python3 -c "import json;d=json.load(open('$REC'));assert d['user']=='jdoe',d;assert d['admin']=='$ADMIN_KEY',d" \
  && pass "lakeFS Auth API called for mapped user 'jdoe' with broker admin auth" \
  || { cat "$REC"; fail "lakeFS mock did not record the expected call"; }

echo "--- Part 2: a user's ticket authenticates to the broker's HTTP/<host> SPN ---"
export PATH=/opt/mitkrb5/sbin:/opt/mitkrb5/bin:$PATH
REALM=ENT.TEST; P=$(( (RANDOM%2000)+26000 )); GP=$((P+2)); Hn=$(hostname)
mkdir -p "$R/db"
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
kadmin.local -q "addprinc -randkey jdoe" >/dev/null 2>&1
kadmin.local -q "ktadd -k $R/jdoe.keytab jdoe" >/dev/null 2>&1
kadmin.local -q "addprinc -randkey HTTP/$Hn" >/dev/null 2>&1
kadmin.local -q "ktadd -k $R/http.keytab HTTP/$Hn" >/dev/null 2>&1
krb5kdc -n -r $REALM >/dev/null 2>&1 & PIDS+=($!)
# jdoe obtains a ticket (stands in for the krb-credd-minted HTTP/<host> ticket)
for i in $(seq 1 30); do kinit -k -t "$R/jdoe.keytab" -c "$R/jdoe.cc" jdoe >/dev/null 2>&1 && break; sleep 0.3; done

# the broker's HTTP/<host> acceptor:
gss-server -port $GP -keytab "$R/http.keytab" HTTP@$Hn >"$R/gss.log" 2>&1 & sleep 1
# the job authenticates to it with its ticket (service ticket for HTTP/<host>):
OUT=$(KRB5CCNAME="FILE:$R/jdoe.cc" sh -c "/opt/mitkrb5/bin/gss-client -port $GP $Hn HTTP hi 2>/dev/null || gss-client -port $GP $Hn HTTP hi" 2>&1 || true)
OUT="$OUT$(cat "$R/gss.log" 2>/dev/null)"
echo "$OUT" | grep -qiE "localname: jdoe|\"jdoe@$REALM\"|jdoe@$REALM" \
  && pass "ticket authenticated to HTTP/$Hn and resolved to 'jdoe' (= REMOTE_USER mod_auth_gssapi sets)" \
  || { echo "$OUT"; fail "GSSAPI auth to the broker SPN did not resolve the expected identity"; }

echo
echo "ALL CHECKS PASSED -- Kerberos identity bridged to a short-lived lakeFS key."
echo "(Production wires Part 2's SPNEGO to Part 1's REMOTE_USER via mod_auth_gssapi.)"
