#!/usr/bin/env bash
# Inline WAF exclusion (LPC-4a) live coverage-matrix harness.
#
# Cycles the LIVE webapp-api-protection LB through the waf_exclusion_pairs variant set and
# verifies each variant (a) applies, (b) is idempotent (immediate plan = No changes), and
# (c) is round-trip-import clean for the LB (state rm -> import -> plan clean). waf_exclusion is
# an LB-nested feature, so the import target is the http_loadbalancer itself. Ends on
# canonical-restore so the live LB is left healthy (no exclusion rules). Results append to
# reports/waf-exclusion-matrix.txt.
#
# Exclusions only REDUCE WAF strictness on a narrow match (specific sig/violation/attack/bot)
# or skip WAF for a matched request; the env is NON-PRODUCTION/destructive-OK and each variant
# is transient (canonical-restore clears all rules at the end). An arm F5 XC rejects for
# entitlement is recorded SKIP (word signals; a bare status number is not matched) rather than
# FAIL. Sequential — no concurrent terraform against the shared azurerm state.
#
# Usage: waf-exclusion-matrix.sh [START [END]]  (inclusive 0-based index range).
set -uo pipefail

umask 077
trap 'rm -rf /tmp/lpc4-variants 2>/dev/null; rm -f /tmp/lpc4-*.log 2>/dev/null' EXIT

cd "$(dirname "$0")/../terraform" || exit 1
ARM_ACCESS_KEY=$(az storage account keys list -n f5salesdemotfstate -g f5-sales-demo-tfstate --query "[0].value" -o tsv)
export ARM_ACCESS_KEY

NS="webapp-api-protection"
LB_ADDR="module.http_lb.xcsh_http_loadbalancer.this"
LB_ID="${NS}/${NS}"
COMMON=(-input=false -lock=true
  -var 'lb_domains=["www.f5-sales-demo.com","api.f5-sales-demo.com"]'
  -var 'subscription_id=75f86c46-9cbc-4f6c-85ea-195e3d3c8ac0')
VARDIR=/tmp/lpc4-variants
REPORT=../reports/waf-exclusion-matrix.txt
mkdir -p ../reports

START="${1:-0}"
END="${2:-9999}"
GATED_RE='entitlement|not subscribed|not entitled|not enabled for|permission denied|unauthorized|AS_NOT_SUBSCRIBED|status: 401|status: 403'

[ "$#" -eq 0 ] && : >"$REPORT"

count=$(python3 ../scripts/waf_exclusion_pairs.py --emit "$VARDIR")
echo "generated $count variants into $VARDIR (running [$START..$END])"

round_trip() {
  local label="$1" vf="$2"
  terraform state rm "$LB_ADDR" >/dev/null 2>&1 || {
    echo "FAIL $label lb-state-rm" >>"$REPORT"
    return
  }
  terraform import "${COMMON[@]}" -var-file="$vf" "$LB_ADDR" "$LB_ID" >/tmp/lpc4-import.log 2>&1 || {
    echo "FAIL $label lb-import ($(grep -iE 'error' /tmp/lpc4-import.log | head -1 | cut -c1-70))" >>"$REPORT"
    return
  }
  terraform plan -detailed-exitcode "${COMMON[@]}" -var-file="$vf" >/tmp/lpc4-rt-plan.log 2>&1
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
  if ! terraform apply -auto-approve "${COMMON[@]}" -var-file="$varfile" >/tmp/lpc4-apply.log 2>&1; then
    if grep -qiE "$GATED_RE" /tmp/lpc4-apply.log; then
      echo "SKIP $label gated-arm ($(grep -oiE "$GATED_RE" /tmp/lpc4-apply.log | head -1))" >>"$REPORT"
    else
      echo "FAIL $label apply ($(grep -iE 'error' /tmp/lpc4-apply.log | head -1 | cut -c1-80))" >>"$REPORT"
    fi
    continue
  fi
  terraform plan -detailed-exitcode "${COMMON[@]}" -var-file="$varfile" >/tmp/lpc4-plan.log 2>&1
  case $? in
  0) round_trip "$label" "$varfile" ;;
  2) echo "FAIL $label not-idempotent" >>"$REPORT" ;;
  *) echo "FAIL $label plan-error" >>"$REPORT" ;;
  esac
done <"${VARDIR}/manifest.txt"

echo "===== WAF EXCLUSION MATRIX RESULTS ($START..$END) ====="
cat "$REPORT"
echo "PASS=$(grep -c '^PASS ' "$REPORT") FAIL=$(grep -c '^FAIL ' "$REPORT") SKIP=$(grep -c '^SKIP ' "$REPORT")"
