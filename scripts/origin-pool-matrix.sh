#!/usr/bin/env bash
# xcsh_origin_pool (LPC-5b) live coverage-matrix harness.
#
# Cycles the LIVE origin pool through the origin_pool_pairs variant set and verifies
# each variant (a) applies, (b) is idempotent (immediate plan = No changes), and (c) is
# round-trip-import clean for xcsh_origin_pool.origin (state rm -> import -> plan clean). Ends
# on canonical-restore so the live pool is left at ROUND_ROBIN / DISTRIBUTED / no advanced_options.
# Results append to reports/origin-pool-matrix.txt.
#
# Only the load-balancing algorithm, endpoint selection, and advanced_options timeouts vary;
# origin_servers (public_ip) and TLS (no_tls) are fixed, so the LB keeps serving www/api
# throughout. Sequential — no concurrent terraform against the shared azurerm state.
#
# Usage: origin-pool-matrix.sh [START [END]]  (inclusive 0-based index range).
set -uo pipefail

umask 077
trap 'rm -rf /tmp/lpc5b-variants 2>/dev/null; rm -f /tmp/lpc5b-*.log 2>/dev/null' EXIT

cd "$(dirname "$0")/../terraform" || exit 1
ARM_ACCESS_KEY=$(az storage account keys list -n f5salesdemotfstate -g f5-sales-demo-tfstate --query "[0].value" -o tsv)
export ARM_ACCESS_KEY

NS="webapp-api-protection"
POOL_ADDR="module.http_lb.xcsh_origin_pool.origin"
POOL_ID="${NS}/origin-pool"
COMMON=(-input=false -lock=true
  -var 'lb_domains=["www.f5-sales-demo.com","api.f5-sales-demo.com"]'
  -var 'subscription_id=75f86c46-9cbc-4f6c-85ea-195e3d3c8ac0')
VARDIR=/tmp/lpc5b-variants
REPORT=../reports/origin-pool-matrix.txt
mkdir -p ../reports

START="${1:-0}"
END="${2:-9999}"

[ "$#" -eq 0 ] && : >"$REPORT"

count=$(python3 ../scripts/origin_pool_pairs.py --emit "$VARDIR")
echo "generated $count variants into $VARDIR (running [$START..$END])"

round_trip() {
  local label="$1" vf="$2"
  terraform state rm "$POOL_ADDR" >/dev/null 2>&1 || {
    echo "FAIL $label state-rm" >>"$REPORT"
    return
  }
  terraform import "${COMMON[@]}" -var-file="$vf" "$POOL_ADDR" "$POOL_ID" >/tmp/lpc5b-import.log 2>&1 || {
    echo "FAIL $label import ($(grep -iE 'error' /tmp/lpc5b-import.log | head -1 | cut -c1-60))" >>"$REPORT"
    return
  }
  terraform plan -detailed-exitcode "${COMMON[@]}" -var-file="$vf" >/tmp/lpc5b-rt-plan.log 2>&1
  case $? in
  0) echo "PASS $label" >>"$REPORT" ;;
  2) echo "FAIL $label import-drift" >>"$REPORT" ;;
  *) echo "FAIL $label rt-plan-error" >>"$REPORT" ;;
  esac
}

while read -r idx name vf _flag; do
  [ "$idx" -lt "$START" ] && continue
  [ "$idx" -gt "$END" ] && continue
  label="$idx-$name"
  echo "--- $label ---"
  varfile="${VARDIR}/${vf}"
  if ! terraform apply -auto-approve "${COMMON[@]}" -var-file="$varfile" >/tmp/lpc5b-apply.log 2>&1; then
    echo "FAIL $label apply ($(grep -iE 'error' /tmp/lpc5b-apply.log | head -1 | cut -c1-80))" >>"$REPORT"
    continue
  fi
  terraform plan -detailed-exitcode "${COMMON[@]}" -var-file="$varfile" >/tmp/lpc5b-plan.log 2>&1
  case $? in
  0) round_trip "$label" "$varfile" ;;
  2) echo "FAIL $label not-idempotent" >>"$REPORT" ;;
  *) echo "FAIL $label plan-error" >>"$REPORT" ;;
  esac
done <"${VARDIR}/manifest.txt"

echo "===== ORIGIN POOL MATRIX RESULTS ($START..$END) ====="
cat "$REPORT"
echo "PASS=$(grep -c '^PASS ' "$REPORT") FAIL=$(grep -c '^FAIL ' "$REPORT") SKIP=$(grep -c '^SKIP ' "$REPORT")"
