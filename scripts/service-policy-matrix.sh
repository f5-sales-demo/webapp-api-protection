#!/usr/bin/env bash
# service_policy (SPol-1) live coverage-matrix harness.
#
# Cycles a LIVE standalone xcsh_service_policy ("matrix-spol") and the LB
# service_policies_choice wiring through the all-pairs + canonical variant set
# (scripts/service_policy_pairs.py) and verifies each variant (a) applies,
# (b) is idempotent (immediate plan = No changes), and (c) is round-trip-import
# clean (state rm -> import -> plan clean) for the service policy. Entitlement/
# permission-rejected arms are recorded SKIP (not FAIL). Ends on the
# canonical-restore variant so the live LB is left at the server default (no
# service policy attached; nothing created). Results append to
# reports/service-policy-matrix.txt.
#
# Requires the provider release carrying the SPol-1 import-suppression seed
# (>= v3.72.4) so the server-default empty markers do not drift on import.
#
# Pre-prod tenant, in-place on the live LB (per the approved spec). Sequential —
# no concurrent terraform against the shared azurerm state.
#
# Usage: service-policy-matrix.sh [START [END]]  (inclusive 0-based index range).
set -uo pipefail

cd "$(dirname "$0")/../terraform" || exit 1
ARM_ACCESS_KEY=$(az storage account keys list -n f5salesdemotfstate -g f5-sales-demo-tfstate --query "[0].value" -o tsv)
export ARM_ACCESS_KEY

NS="webapp-api-protection"
SPOL_ADDR="module.http_lb.xcsh_service_policy.this[\"matrix-spol\"]"
SPOL_ID="${NS}/matrix-spol"
COMMON=(-input=false -lock=true
  -var 'lb_domains=["www.f5-sales-demo.com","api.f5-sales-demo.com"]'
  -var 'subscription_id=75f86c46-9cbc-4f6c-85ea-195e3d3c8ac0')
VARDIR=/tmp/service-policy-variants
REPORT=../reports/service-policy-matrix.txt
mkdir -p ../reports

START="${1:-0}"
END="${2:-9999}"

GATED_RE='entitlement|not subscribed|not entitled|not enabled for|permission denied|unauthorized|AS_NOT_SUBSCRIBED|status: 401|status: 403'

count=$(python3 ../scripts/service_policy_pairs.py --emit "$VARDIR")
echo "generated $count variants into $VARDIR (running [$START..$END])"

round_trip() {
  local label="$1" vf="$2"
  # Skip variants that create no service policy (canonical-restore): nothing to import.
  if ! terraform state list | grep -qF "$SPOL_ADDR"; then
    echo "PASS $label (no-policy variant, nothing to import)" >>"$REPORT"
    return
  fi
  terraform state rm "$SPOL_ADDR" >/dev/null 2>&1 || {
    echo "FAIL $label state-rm" >>"$REPORT"
    return
  }
  terraform import "${COMMON[@]}" -var-file="$vf" "$SPOL_ADDR" "$SPOL_ID" >/tmp/spol-import.log 2>&1 || {
    echo "FAIL $label import ($(grep -iE 'error' /tmp/spol-import.log | head -1 | cut -c1-80))" >>"$REPORT"
    return
  }
  terraform plan -detailed-exitcode "${COMMON[@]}" -var-file="$vf" >/tmp/spol-rt-plan.log 2>&1
  case $? in
  0) echo "PASS $label" >>"$REPORT" ;;
  2) echo "FAIL $label import-drift" >>"$REPORT" ;;
  *) echo "FAIL $label rt-plan-error" >>"$REPORT" ;;
  esac
}

while read -r idx name vf; do
  [ "$idx" -lt "$START" ] && continue
  [ "$idx" -gt "$END" ] && continue
  label="$idx-$name"
  echo "--- $label ---"
  if ! terraform apply -auto-approve "${COMMON[@]}" -var-file="${VARDIR}/${vf}" >/tmp/spol-apply.log 2>&1; then
    if grep -qiE "$GATED_RE" /tmp/spol-apply.log; then
      echo "SKIP $label gated-arm ($(grep -oiE "$GATED_RE" /tmp/spol-apply.log | head -1))" >>"$REPORT"
    else
      echo "FAIL $label apply ($(grep -iE 'error' /tmp/spol-apply.log | head -1 | cut -c1-80))" >>"$REPORT"
    fi
    continue
  fi
  terraform plan -detailed-exitcode "${COMMON[@]}" -var-file="${VARDIR}/${vf}" >/tmp/spol-plan.log 2>&1
  case $? in
  0) round_trip "$label" "${VARDIR}/${vf}" ;;
  2) echo "FAIL $label not-idempotent" >>"$REPORT" ;;
  *) echo "FAIL $label plan-error" >>"$REPORT" ;;
  esac
done <"${VARDIR}/manifest.txt"

echo "===== SERVICE POLICY MATRIX RESULTS ($START..$END) ====="
cat "$REPORT"
echo "PASS=$(grep -c '^PASS ' "$REPORT") FAIL=$(grep -c '^FAIL ' "$REPORT") SKIP=$(grep -c '^SKIP ' "$REPORT")"
