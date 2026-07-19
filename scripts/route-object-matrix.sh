#!/usr/bin/env bash
# Standalone route object (CR-5) live coverage-matrix harness.
#
# Verifies the standalone xcsh_route resource and the LB custom_route (route_ref) arm. Per
# variant: apply -> idempotent -> round-trip import (the route object always; plus the whole LB
# for ROUTE_LB variants where it is attached via custom_route). Ends on canonical-restore so the
# live LB is left with no custom routes. Results append to reports/route-object-matrix.txt.
#
# Custom routes are additive to default_route_pools, so the LB keeps serving throughout.
# Sequential — no concurrent terraform against the shared azurerm state.
#
# Usage: route-object-matrix.sh [START [END]]  (inclusive 0-based index range).
set -uo pipefail

umask 077
trap 'rm -rf /tmp/cr5-variants 2>/dev/null; rm -f /tmp/cr5-*.log 2>/dev/null' EXIT

cd "$(dirname "$0")/../terraform" || exit 1
ARM_ACCESS_KEY=$(az storage account keys list -n f5salesdemotfstate -g f5-sales-demo-tfstate --query "[0].value" -o tsv)
export ARM_ACCESS_KEY

NS="webapp-api-protection"
LB_ADDR="module.http_lb.xcsh_http_loadbalancer.this"
LB_ID="${NS}/${NS}"
RO_ADDR='module.http_lb.xcsh_route.this["cr5-ro"]'
RO_ID="${NS}/cr5-ro"
COMMON=(-input=false -lock=true
  -var 'lb_domains=["www.f5-sales-demo.com","api.f5-sales-demo.com"]'
  -var 'subscription_id=75f86c46-9cbc-4f6c-85ea-195e3d3c8ac0')
VARDIR=/tmp/cr5-variants
REPORT=../reports/route-object-matrix.txt
mkdir -p ../reports

START="${1:-0}"
END="${2:-9999}"

[ "$#" -eq 0 ] && : >"$REPORT"

count=$(python3 ../scripts/route_object_pairs.py --emit "$VARDIR")
echo "generated $count variants into $VARDIR (running [$START..$END])"

reimport_clean() {
  local label="$1" vf="$2" addr="$3" id="$4"
  terraform state rm "$addr" >/dev/null 2>&1 || { echo "FAIL $label state-rm ($addr)" >>"$REPORT"; return 1; }
  terraform import "${COMMON[@]}" -var-file="$vf" "$addr" "$id" >/tmp/cr5-import.log 2>&1 || {
    echo "FAIL $label import ($(grep -iE 'error' /tmp/cr5-import.log | head -1 | cut -c1-60))" >>"$REPORT"
    return 1
  }
  return 0
}

round_trip() {
  local label="$1" vf="$2" flag="$3"
  if [ "$flag" = "NONE" ]; then
    echo "PASS $label" >>"$REPORT"
    return
  fi
  reimport_clean "$label" "$vf" "$RO_ADDR" "$RO_ID" || return
  if [ "$flag" = "ROUTE_LB" ]; then
    reimport_clean "$label" "$vf" "$LB_ADDR" "$LB_ID" || return
  fi
  terraform plan -detailed-exitcode "${COMMON[@]}" -var-file="$vf" >/tmp/cr5-rt-plan.log 2>&1
  case $? in
  0) echo "PASS $label" >>"$REPORT" ;;
  2) echo "FAIL $label import-drift" >>"$REPORT" ;;
  *) echo "FAIL $label rt-plan-error" >>"$REPORT" ;;
  esac
}

while read -r idx name vf flag; do
  [ "$idx" -lt "$START" ] && continue
  [ "$idx" -gt "$END" ] && continue
  label="$idx-$name"
  echo "--- $label ($flag) ---"
  varfile="${VARDIR}/${vf}"
  if ! terraform apply -auto-approve "${COMMON[@]}" -var-file="$varfile" >/tmp/cr5-apply.log 2>&1; then
    echo "FAIL $label apply ($(grep -iE 'error' /tmp/cr5-apply.log | head -1 | cut -c1-80))" >>"$REPORT"
    continue
  fi
  terraform plan -detailed-exitcode "${COMMON[@]}" -var-file="$varfile" >/tmp/cr5-plan.log 2>&1
  case $? in
  0) round_trip "$label" "$varfile" "$flag" ;;
  2) echo "FAIL $label not-idempotent" >>"$REPORT" ;;
  *) echo "FAIL $label plan-error" >>"$REPORT" ;;
  esac
done <"${VARDIR}/manifest.txt"

echo "===== ROUTE OBJECT MATRIX RESULTS ($START..$END) ====="
cat "$REPORT"
echo "PASS=$(grep -c '^PASS ' "$REPORT") FAIL=$(grep -c '^FAIL ' "$REPORT") SKIP=$(grep -c '^SKIP ' "$REPORT")"
