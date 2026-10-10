#!/bin/bash
# ============================================================================
# verify-ad.sh -- acceptance test of krb-credd against a REAL Active Directory.
#
# Run as root on the broker/login node (hpclogin01 in the test-lab runbook)
# after the runbook's sections 5-9 are done. It exercises the parts no local
# test can: how your AD issues the broker TGT, resolves and names users in
# S4U2Self, enforces msDS-AllowedToDelegateTo and Protected Users, which
# encryption types it uses, and how long tickets last. It then drives the
# installed daemon end to end.
#
# It is NON-DESTRUCTIVE: it reads /etc/krb-hpc/credd.conf, works in a private
# temporary directory, and changes nothing in AD, uidmap.conf or anyone's
# home -- except that --kill-switch briefly creates the kill-switch file
# (stopping issuance for a few seconds) and the end-to-end step refreshes the
# test users' own ticket caches exactly as a login would.
#
#   sudo tests/verify-ad.sh --user jdoe --refused ptest \
#        [--user asmith] [--upn jdoe=john.doe@test.lab] \
#        [--url http://svc01.test.lab/whoami/] [--kill-switch] \
#        [--not-allowed host/dc01.test.lab] [--config /etc/krb-hpc/credd.conf]
#
#   --user NAME      an enrolled, delegable Linux/AD user (repeatable)
#   --refused NAME   an enrolled user AD must refuse (Protected Users or
#                    "sensitive and cannot be delegated"); optional
#   --upn U=UPN      also send user U's UPN as the enterprise name and report
#                    which name AD puts in the tickets (repeatable)
#   --url URL        a Kerberos-protected URL on a delegation target; the test
#                    fetches it with curl --negotiate as each --user
#   --kill-switch    also test the kill switch (stops issuance ~5 seconds)
#   --not-allowed SPN  an existing SPN that is NOT in msDS-AllowedToDelegateTo
#                    (default: host/<first kdc in krb5.conf>)
#
# Exit status: 0 if nothing FAILed (WARNs are allowed), 1 otherwise. A report
# is saved to /var/tmp/krb-hpc-ad-test-<timestamp>.txt.
# ============================================================================
set -uo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
CONF=/etc/krb-hpc/credd.conf; USERS=(); REFUSED=""; UPNS=(); URL=""; KILL=0; NOTALLOWED=""
while [ $# -gt 0 ]; do
  case "$1" in
    --user) USERS+=("$2"); shift 2;;
    --refused) REFUSED="$2"; shift 2;;
    --upn) UPNS+=("$2"); shift 2;;
    --url) URL="$2"; shift 2;;
    --kill-switch) KILL=1; shift;;
    --not-allowed) NOTALLOWED="$2"; shift 2;;
    --config) CONF="$2"; shift 2;;
    -h|--help) sed -n '2,38p' "$0"; exit 0;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
[ ${#USERS[@]} -gt 0 ] || { echo "give at least one --user (see --help)" >&2; exit 2; }

REPORT=/var/tmp/krb-hpc-ad-test-$(date +%Y%m%d-%H%M%S).txt
exec > >(tee "$REPORT") 2>&1
T=$(mktemp -d /var/tmp/krb-hpc-ad-test.XXXXXX); chmod 700 "$T"
trap 'rm -rf "$T"' EXIT
NPASS=0; NFAIL=0; NWARN=0
pass(){ echo "PASS  $*"; NPASS=$((NPASS+1)); }
fail(){ echo "FAIL  $*"; NFAIL=$((NFAIL+1)); }
warn(){ echo "WARN  $*"; NWARN=$((NWARN+1)); }
info(){ echo "INFO  $*"; }
section(){ echo; echo "--- $* ---"; }

echo "krb-credd Active Directory acceptance test -- $(date -u '+%Y-%m-%d %H:%M UTC') on $(hostname -f 2>/dev/null || hostname)"
echo "config: $CONF   repository: $REPO ($(grep -m1 '^version' "$REPO/pyproject.toml" 2>/dev/null))"

# ---- read the daemon's own configuration (same parser, same defaults) ----
PY="python3 -I"
eval "$($PY - "$REPO/src" "$CONF" <<'EOF'
import shlex, sys
sys.path.insert(0, sys.argv[1])
from krbhpc.credd import Config
c = Config.load(sys.argv[2])
out = dict(REALM=c.realm, KRB5CONF=c.krb5_conf, BROKER=c.broker_principal,
           KEYTAB=str(c.broker_keytab), SOCK=str(c.unix_socket), DISABLE=str(c.disable_file),
           MAP=str(c.map_file), KINIT=c.tools["kinit"], KLIST=c.tools["klist"], KVNO=c.tools["kvno"],
           S4UFLAG="-U" if c.s4u_enterprise else "-I", TARGETS=" ".join(c.delegate_targets),
           MINUID=str(c.min_uid), ENFORCE="enforce" if c.ticket_checks_enforce else "warn")
for k, v in out.items():
    print(f"{k}={shlex.quote(v)}")
EOF
)" || { echo "cannot read $CONF"; exit 1; }
export KRB5_CONFIG="$KRB5CONF" LC_ALL=C TZ=UTC0
unset KRB5CCNAME KRB5_KTNAME KRB5_CLIENT_KTNAME KRB5_TRACE
case "$BROKER" in *@*) BROKERP=$BROKER;; *) BROKERP=$BROKER@$REALM;; esac
read -r -a TGTS <<< "$TARGETS"
info "realm $REALM; broker $BROKERP; targets: $TARGETS; s4u $S4UFLAG; ticket_checks $ENFORCE; min_uid $MINUID"

# Inspect a cache with the daemon's own parser and checks; prints one line per
# finding and exits non-zero on a fatal problem.
inspect(){  # cache  accepted-principal...
  local cc=$1; shift
  $PY - "$REPO/src" "$KLIST" "$cc" "$REALM" "$TARGETS" "$@" <<'EOF'
import subprocess, sys, time
sys.path.insert(0, sys.argv[1])
from krbhpc._krb import parse_klist_details, validate_user_cache, KrbToolError, MIN_TICKET_VALID_S
klist, cc, realm, targets, *accepted = sys.argv[2:]
r = subprocess.run([klist, "-e", "-f", "-c", f"FILE:{cc}"], capture_output=True, text=True)
info = parse_klist_details(r.stdout)
print(f"  default principal: {info.default_principal}")
for t in info.tickets:
    print(f"  {t.server}: session key {t.skey_etype}, ticket {t.tkt_etype}, "
          f"{(t.expires - time.time()) / 3600:.1f} h left")
try:
    for w in validate_user_cache(info, accepted, realm, targets.split(), MIN_TICKET_VALID_S):
        print(f"  warning: {w}")
except KrbToolError as e:
    print(f"  rejected: {e.detail}")
    sys.exit(1)
EOF
}

# ============================================================================
section "1. Prerequisites on this node"
V=$("$KLIST" -V 2>&1 | head -1)
if [[ "$V" =~ ([0-9]+)\.([0-9]+) ]] && { [ "${BASH_REMATCH[1]}" -gt 1 ] || [ "${BASH_REMATCH[2]}" -ge 19 ]; }; then
  pass "MIT Kerberos: $V"
else
  fail "MIT Kerberos 1.19+ required, found: $V"
fi
KDCSPEC=$(awk -v r="$REALM" '$1==r && $2=="=" {inr=1} inr && $1=="kdc" {print $3; exit} inr && /}/ {inr=0}' "$KRB5CONF")
KDC=${KDCSPEC%%:*}; KPORT=88; [ "$KDCSPEC" != "$KDC" ] && KPORT=${KDCSPEC##*:}
if [ -n "$KDC" ]; then
  info "first KDC in $KRB5CONF: $KDC"
  if timeout 5 bash -c "exec 3<>/dev/tcp/$KDC/$KPORT" 2>/dev/null; then pass "KDC $KDC reachable on TCP port $KPORT"
  else fail "cannot reach $KDC on TCP port $KPORT (DNS, firewall, or the DC is down)"; fi
else
  warn "no kdc line for $REALM in $KRB5CONF (DNS lookup of KDCs is off in the runbook's krb5.conf)"
fi
perm=$(stat -c '%U %a' "$KEYTAB" 2>/dev/null)
[ "$perm" = "root 600" ] && pass "broker keytab $KEYTAB is root 0600" || fail "broker keytab $KEYTAB is '$perm' (must be root 600)"
KT=$("$KLIST" -kte "$KEYTAB" 2>&1)
if echo "$KT" | grep -qi "$BROKERP"; then
  pass "keytab holds $BROKERP"
  echo "$KT" | grep -i "$BROKERP" | grep -q "aes256-cts" && pass "keytab key is AES256" || warn "no AES256 key for $BROKERP in the keytab: $(echo "$KT" | grep -i "$BROKERP" | head -2 | tr -s ' ')"
  info "keytab key version(s): $(echo "$KT" | grep -i "$BROKERP" | awk '{print $1}' | sort -u | tr '\n' ' ')(compare with msDS-KeyVersionNumber of the broker account)"
else
  fail "keytab does not contain $BROKERP: $(echo "$KT" | tail -3 | tr '\n' ' ')"
fi

# ============================================================================
section "2. The broker's own login (AS request with the keytab)"
B=$T/broker.cc
if OUT=$("$KINIT" -f -r 7d -l 10h -k -t "$KEYTAB" -c "FILE:$B" "$BROKER" 2>&1); then
  pass "kinit -k as $BROKERP"
  L=$("$KLIST" -e -f -c "FILE:$B")
  echo "$L" | grep -A2 "krbtgt/" | sed 's/^/  /'
  echo "$L" | grep -A2 "krbtgt/" | grep -q "Flags: [A-Za-z]*F" && pass "broker TGT is forwardable" || fail "broker TGT is not forwardable (S4U2Proxy needs it)"
  echo "$L" | grep -A2 "krbtgt/" | grep -q "Flags: [A-Za-z]*R" && pass "broker TGT is renewable" || warn "broker TGT is not renewable: the daemon will re-kinit from the keytab instead of renewing (harmless)"
  echo "$L" | grep -A2 "krbtgt/" | grep -q "Etype (skey, tkt): aes" && pass "broker TGT uses AES" || warn "broker TGT session key is not AES: $(echo "$L" | grep Etype | head -1 | tr -s ' ')"
else
  fail "kinit -k as $BROKERP failed: $OUT"
  echo "   Preauthentication failed -> keytab key/salt does not match AD (rerun ktpass; compare KVNO)"
  echo "   Client not found -> the account's UPN is not $BROKERP (ktpass -mapOp set sets it)"
  echo; echo "Cannot continue without the broker TGT. Report: $REPORT"; exit 1
fi

# kvno's error message (stderr lines start with "kvno:"), not its progress lines.
why(){ echo "$1" | grep -m1 '^kvno:' || echo "$1" | tail -1; }

# One S4U mint, exactly as the daemon does it (kvno on a private copy).
mint(){  # name-as-sent  flag  out
  cp "$B" "$T/copy.cc"; chmod 600 "$T/copy.cc"
  "$KVNO" -c "FILE:$T/copy.cc" --out-cache "FILE:$3" "$2" "$1" -P "${TGTS[@]}" 2>&1
}

# ============================================================================
section "3. Constrained delegation for each delegable user"
for u in "${USERS[@]}"; do
  princ=$(awk -v u="$u" -v n="$(id -u "$u" 2>/dev/null)" '{sub(/#.*/,"")} NF && ($1==u || $1==n) {print $2; exit}' "$MAP")
  if [ -z "$princ" ]; then fail "$u is not in $MAP (enroll with admin/enroll_user.sh $u)"; continue; fi
  uid=$(id -u "$u" 2>/dev/null) || { fail "$u is not a Linux user here"; continue; }
  [ "$uid" -ge "$MINUID" ] && pass "$u: uid $uid, enrolled as $princ" || fail "$u: uid $uid is below min_uid $MINUID and will be refused"
  for flag in -U -I; do
    out=$T/$u$flag.cc
    if OUT=$(mint "$princ" "$flag" "$out"); then
      mode=$([ "$flag" = -U ] && echo "enterprise name (kvno -U)" || echo "plain principal (kvno -I)")
      tag=$([ "$flag" = "$S4UFLAG" ] && echo " [the configured mode]" || echo "")
      if inspect "$out" "$princ" "$u" > "$T/insp" ; then
        pass "$u via $mode$tag: AD issued tickets that pass the daemon's checks"
      else
        fail "$u via $mode$tag: tickets fail the daemon's checks"
      fi
      cat "$T/insp"
      cn=$(grep -m1 "default principal:" "$T/insp" | awk '{print $3}')
      [ -n "$cn" ] && info "AD names $u in tickets as: $cn"
    else
      if [ "$flag" = "$S4UFLAG" ]; then fail "$u: S4U mint with $flag failed: $(why "$OUT")"
      else warn "$u: S4U with $flag (not the configured mode) failed: $(why "$OUT")"; fi
    fi
  done
done

for pair in "${UPNS[@]}"; do
  u=${pair%%=*}; upn=${pair#*=}
  out=$T/upn-$u.cc
  if OUT=$(mint "$upn" -U "$out"); then
    if inspect "$out" "$upn" "$u" > "$T/insp"; then
      pass "UPN $upn sent as enterprise name: tickets accepted (named $(grep -m1 'default principal:' "$T/insp" | awk '{print $3}'))"
    else
      fail "UPN $upn: tickets would be rejected -- enroll $u by its sAMAccountName or set ticket_checks = warn"
    fi
    cat "$T/insp"
  else
    fail "UPN $upn as enterprise name: S4U failed: $(why "$OUT")"
  fi
done

# ============================================================================
section "4. What AD must refuse"
if [ -n "$REFUSED" ]; then
  rp=$(awk -v u="$REFUSED" '{sub(/#.*/,"")} NF && $1==u {print $2; exit}' "$MAP"); rp=${rp:-$REFUSED}
  if OUT=$(mint "$rp" "$S4UFLAG" "$T/refused.cc"); then
    fail "$REFUSED received delegated tickets -- check Protected Users / 'Account is sensitive and cannot be delegated'"
  else
    pass "$REFUSED refused by AD: $(why "$OUT")"
  fi
else
  info "no --refused user given; skipping"
fi
NA=${NOTALLOWED:-${KDC:+host/$KDC}}
if [ -n "$NA" ]; then
  case "$NA" in *@*) ;; *) NA=$NA@$REALM;; esac
  cp "$B" "$T/copy.cc"
  if OUT=$("$KVNO" -c "FILE:$T/copy.cc" --out-cache "FILE:$T/na.cc" "$S4UFLAG" "${USERS[0]}" -P "$NA" 2>&1); then
    fail "AD delegated to $NA, which should not be in msDS-AllowedToDelegateTo"
  else
    pass "AD refused delegation to $NA (not on the allow-list): $(why "$OUT")"
  fi
fi

# ============================================================================
section "5. krb-credd --check"
CHK=$(command -v krb-credd || echo "$REPO/bin/krb-credd")
OUT=$("$CHK" -c "$CONF" --check --user "${USERS[0]}" 2>&1); RC=$?
echo "$OUT" | sed 's/^/  /'
[ $RC -eq 0 ] && pass "--check --user ${USERS[0]}: all checks passed" || fail "--check --user ${USERS[0]} reported failures (above)"
if [ -n "$REFUSED" ]; then
  OUT=$("$CHK" -c "$CONF" --check --user "$REFUSED" 2>&1)
  echo "$OUT" | grep -q "FAIL  constrained delegation for $REFUSED" \
    && pass "--check pinpoints $REFUSED: $(echo "$OUT" | grep "FAIL  constrained" | cut -c1-110)" \
    || fail "--check did not flag $REFUSED: $(echo "$OUT" | tail -2 | tr '\n' ' ')"
fi

# ============================================================================
section "6. End to end through the running daemon"
GET=$(command -v krb-get || echo "$REPO/bin/krb-get")
if [ ! -S "$SOCK" ]; then
  fail "daemon socket $SOCK not found (systemctl status krb-credd)"
else
  for u in "${USERS[@]}"; do
    OUT=$(runuser -u "$u" -- env KRB_HPC_SOCKET="$SOCK" "$GET" 2>&1); RC=$?
    if [ $RC -ne 0 ]; then fail "$u: krb-get failed: $OUT"; continue; fi
    cc=${OUT#export KRB5CCNAME=}; cc=${cc//\'/}; cc=${cc#FILE:}
    pass "$u: krb-get -> $cc"
    st=$(runuser -u "$u" -- stat -c '%U %a' "$cc" 2>/dev/null)
    [ "$st" = "$u 600" ] && pass "$u: cache owned by $u, mode 600" || fail "$u: cache is '$st'"
    runuser -u "$u" -- env LC_ALL=C klist -c "FILE:$cc" 2>/dev/null | grep -q "krbtgt/" \
      && fail "$u: home cache contains a TGT" || pass "$u: home cache has service tickets only"
    S=$(runuser -u "$u" -- env KRB_HPC_SOCKET="$SOCK" "$GET" --status 2>&1)
    echo "$S" | grep -q "enrolled: *True" && pass "$u: krb-get --status: $(echo "$S" | grep 'tickets expire' | tr -s ' ')" || fail "$u: krb-get --status: $S"
    if [ -n "$URL" ]; then
      R=$(runuser -u "$u" -- env KRB5CCNAME="FILE:$cc" KRB5_CONFIG="$KRB5CONF" curl -s --negotiate -u : -w ' HTTP %{http_code}' "$URL" 2>&1)
      echo "$R" | grep -qi "$u" && pass "$u: $URL accepted the delegated ticket ($R)" || fail "$u: $URL answered: $R"
    fi
  done
  if [ -n "$REFUSED" ] && id "$REFUSED" >/dev/null 2>&1; then
    OUT=$(runuser -u "$REFUSED" -- env KRB_HPC_SOCKET="$SOCK" "$GET" 2>&1); RC=$?
    [ $RC -eq 1 ] && pass "$REFUSED: krb-get refused: ${OUT#krb-get: }" || fail "$REFUSED: krb-get returned $RC: $OUT"
  fi
fi

# ============================================================================
if [ $KILL -eq 1 ] && [ -S "$SOCK" ]; then
  section "7. Kill switch (issuance stops for a few seconds)"
  if [ -e "$DISABLE" ]; then
    warn "$DISABLE already exists; leaving it alone"
  else
    touch "$DISABLE"
    OUT=$(runuser -u "${USERS[0]}" -- env KRB_HPC_SOCKET="$SOCK" "$GET" 2>&1)
    rm -f "$DISABLE"
    echo "$OUT" | grep -q "disabled by the HPC administrators" && pass "kill switch refuses krb-get at once" || fail "kill switch: $OUT"
    OUT=$(runuser -u "${USERS[0]}" -- env KRB_HPC_SOCKET="$SOCK" "$GET" 2>&1) \
      && pass "service resumes when $DISABLE is removed" || fail "after removing the kill switch: $OUT"
  fi
fi

# ============================================================================
echo
echo "SUMMARY: $NPASS passed, $NWARN warning(s), $NFAIL failed"
echo "Report saved to $REPORT"
sleep 0.3   # let tee finish writing the report
[ $NFAIL -eq 0 ]
