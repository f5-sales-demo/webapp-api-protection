#!/usr/bin/env bash
# WAF (app_firewall) live coverage-matrix harness.
#
# Cycles the LIVE webapp-api-protection app_firewall through the all-pairs +
# enum + min/max + maximal variant set (scripts/waf-pairs.py) and verifies each
# variant is (a) applies, (b) idempotent (immediate plan = No changes), and
# (c) round-trip-import clean (state rm -> import -> plan clean) for
# module.http_lb.xcsh_app_firewall.this. Entitlement/permission-rejected arms are
# recorded as SKIP (not FAIL). Ends on the canonical-restore variant so the live
# WAF is left healthy (blocking + server defaults). Results append to
# reports/waf-matrix.txt.
#
# Pre-prod tenant, in-place on the live app_firewall (per the approved spec).
# Sequential — no concurrent terraform against the shared azurerm state.
#
# Usage: waf-matrix.sh [START [END]]   (inclusive 0-based variant index range;
# run in short batches to survive long runs, e.g. `waf-matrix.sh 0 9`).
set -uo pipefail

cd "$(dirname "$0")/../terraform" || exit 1
ARM_ACCESS_KEY=$(az storage account keys list -n f5salesdemotfstate -g f5-sales-demo-tfstate --query "[0].value" -o tsv)
export ARM_ACCESS_KEY

NS="webapp-api-protection"
WAF_ADDR="module.http_lb.xcsh_app_firewall.this"
WAF_ID="${NS}/${NS}-waf"
COMMON=(-input=false -lock=true
  -var 'lb_domains=["www.f5-sales-demo.com","api.f5-sales-demo.com"]'
  -var 'subscription_id=75f86c46-9cbc-4f6c-85ea-195e3d3c8ac0')
VARDIR=/tmp/waf-variants
REPORT=../reports/waf-matrix.txt
mkdir -p ../reports

START="${1:-0}"
END="${2:-9999}"

# entitlement/permission rejection signatures -> record SKIP, not FAIL. Word/phrase
# signals only: bare status numbers like "403" are NOT matched (they false-match
# response-code values such as allowed_response_codes=[...,403] or a "Forbidden"
# blocking-page code). A 400 BAD_REQUEST (invalid arm combination) is a real FAIL.
GATED_RE='entitlement|not subscribed|not entitled|not enabled for|permission denied|unauthorized|AS_NOT_SUBSCRIBED|status: 401|status: 403'

count=$(python3 ../scripts/waf-pairs.py --emit "$VARDIR")
echo "generated $count variants into $VARDIR (running [$START..$END])"

round_trip() {
  local label="$1" vf="$2"
  terraform state rm "$WAF_ADDR" >/dev/null 2>&1 || {
    echo "FAIL $label state-rm" >>"$REPORT"
    return
  }
  terraform import "${COMMON[@]}" -var-file="$vf" "$WAF_ADDR" "$WAF_ID" >/tmp/waf-import.log 2>&1 || {
    echo "FAIL $label import" >>"$REPORT"
    return
  }
  terraform plan -detailed-exitcode "${COMMON[@]}" -var-file="$vf" >/tmp/waf-rt-plan.log 2>&1
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
  if ! terraform apply -auto-approve "${COMMON[@]}" -var-file="${VARDIR}/${vf}" >/tmp/waf-apply.log 2>&1; then
    if grep -qiE "$GATED_RE" /tmp/waf-apply.log; then
      echo "SKIP $label gated-arm ($(grep -oiE "$GATED_RE" /tmp/waf-apply.log | head -1))" >>"$REPORT"
    else
      echo "FAIL $label apply ($(grep -iE 'error' /tmp/waf-apply.log | head -1 | cut -c1-80))" >>"$REPORT"
    fi
    continue
  fi
  terraform plan -detailed-exitcode "${COMMON[@]}" -var-file="${VARDIR}/${vf}" >/tmp/waf-plan.log 2>&1
  case $? in
  0) round_trip "$label" "${VARDIR}/${vf}" ;;
  2)
    echo "FAIL $label not-idempotent" >>"$REPORT"
    ;;
  *)
    echo "FAIL $label plan-error" >>"$REPORT"
    ;;
  esac
done <"${VARDIR}/manifest.txt"

echo "===== WAF MATRIX RESULTS ($START..$END) ====="
cat "$REPORT"
echo "PASS=$(grep -c '^PASS ' "$REPORT") FAIL=$(grep -c '^FAIL ' "$REPORT") SKIP=$(grep -c '^SKIP ' "$REPORT")"
