#!/usr/bin/env bash
# Standalone WAF exclusion policy (LPC-4b) live coverage-matrix harness.
#
# Verifies the standalone xcsh_waf_exclusion_policy resource and the LB waf_exclusion_policy
# ref arm. Per variant: (a) apply, (b) idempotent (immediate plan = No changes), (c) round-trip
# import — the policy resource always, plus the whole LB for LB_REF variants (the ref arm is
# LB-nested). Ends on canonical-restore so the live LB is left healthy (no policy, no ref).
# Results append to reports/waf-exclusion-policy-matrix.txt.
#
# Exclusions only reduce WAF strictness on a narrow match; the env is NON-PRODUCTION/
# destructive-OK and each variant is transient. Sequential — no concurrent terraform against
# the shared azurerm state.
#
# Usage: waf-exclusion-policy-matrix.sh [START [END]]  (inclusive 0-based index range).
set -uo pipefail

umask 077
trap 'rm -rf /tmp/lpc4b-variants 2>/dev/null; rm -f /tmp/lpc4b-*.log 2>/dev/null' EXIT

cd "$(dirname "$0")/../terraform" || exit 1
ARM_ACCESS_KEY=$(az storage account keys list -n f5salesdemotfstate -g f5-sales-demo-tfstate --query "[0].value" -o tsv)
export ARM_ACCESS_KEY

NS="webapp-api-protection"
LB_ADDR="module.http_lb.xcsh_http_loadbalancer.this"
LB_ID="${NS}/${NS}"
POL_ADDR='module.http_lb.xcsh_waf_exclusion_policy.this["excl-pol"]'
POL_ID="${NS}/excl-pol"
COMMON=(-input=false -lock=true
  -var 'lb_domains=["www.f5-sales-demo.com","api.f5-sales-demo.com"]'
  -var 'subscription_id=75f86c46-9cbc-4f6c-85ea-195e3d3c8ac0')
VARDIR=/tmp/lpc4b-variants
REPORT=../reports/waf-exclusion-policy-matrix.txt
mkdir -p ../reports

START="${1:-0}"
END="${2:-9999}"

[ "$#" -eq 0 ] && : >"$REPORT"

count=$(python3 ../scripts/waf_exclusion_policy_pairs.py --emit "$VARDIR")
echo "generated $count variants into $VARDIR (running [$START..$END])"

# Re-import a state-removed resource and confirm a clean plan (exit 0). Echoes a FAIL line and
# returns 1 on any failure so the caller can stop the round-trip for this variant.
reimport_clean() {
  local label="$1" vf="$2" addr="$3" id="$4"
  terraform state rm "$addr" >/dev/null 2>&1 || {
    echo "FAIL $label state-rm ($addr)" >>"$REPORT"
    return 1
  }
  terraform import "${COMMON[@]}" -var-file="$vf" "$addr" "$id" >/tmp/lpc4b-import.log 2>&1 || {
    echo "FAIL $label import ($(grep -iE 'error' /tmp/lpc4b-import.log | head -1 | cut -c1-60))" >>"$REPORT"
    return 1
  }
  return 0
}

round_trip() {
  local label="$1" vf="$2" flag="$3"
  if [ "$flag" = "NONE" ]; then
    # canonical: nothing created, so no resource to round-trip; idempotency already confirmed.
    echo "PASS $label" >>"$REPORT"
    return
  fi
  reimport_clean "$label" "$vf" "$POL_ADDR" "$POL_ID" || return
  if [ "$flag" = "LB_REF" ]; then
    reimport_clean "$label" "$vf" "$LB_ADDR" "$LB_ID" || return
  fi
  terraform plan -detailed-exitcode "${COMMON[@]}" -var-file="$vf" >/tmp/lpc4b-rt-plan.log 2>&1
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
  if ! terraform apply -auto-approve "${COMMON[@]}" -var-file="$varfile" >/tmp/lpc4b-apply.log 2>&1; then
    echo "FAIL $label apply ($(grep -iE 'error' /tmp/lpc4b-apply.log | head -1 | cut -c1-80))" >>"$REPORT"
    continue
  fi
  terraform plan -detailed-exitcode "${COMMON[@]}" -var-file="$varfile" >/tmp/lpc4b-plan.log 2>&1
  case $? in
  0) round_trip "$label" "$varfile" "$flag" ;;
  2) echo "FAIL $label not-idempotent" >>"$REPORT" ;;
  *) echo "FAIL $label plan-error" >>"$REPORT" ;;
  esac
done <"${VARDIR}/manifest.txt"

echo "===== WAF EXCLUSION POLICY MATRIX RESULTS ($START..$END) ====="
cat "$REPORT"
echo "PASS=$(grep -c '^PASS ' "$REPORT") FAIL=$(grep -c '^FAIL ' "$REPORT") SKIP=$(grep -c '^SKIP ' "$REPORT")"
