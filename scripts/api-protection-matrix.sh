#!/usr/bin/env bash
# API Protection (SP3) live coverage-matrix harness.
#
# Cycles the LIVE webapp-api-protection LB through the api_protection_pairs variant
# set and verifies each variant (a) applies, (b) is idempotent (immediate plan =
# No changes), and (c) is round-trip-import clean for the LB and, when present, the
# standalone xcsh_sensitive_data_policy and xcsh_api_definition. Ends on
# canonical-restore so the live LB is left healthy (all SP3 features off). Results
# append to reports/api-protection-matrix.txt.
#
# No secrets are involved (unlike SP2's access_token), so there is no injection and
# no write-only-secret re-apply gate — every variant must import 0-change. An arm
# that F5 XC rejects on staging (400/500) is recorded SKIP (word/phrase signals; a
# bare status number is not matched) rather than FAIL. Sequential — no concurrent
# terraform against the shared azurerm state.
#
# Usage: api-protection-matrix.sh [START [END]]  (inclusive 0-based index range).
set -uo pipefail

umask 077
trap 'rm -rf /tmp/apiprot-variants 2>/dev/null; rm -f /tmp/apiprot-*.log 2>/dev/null' EXIT

cd "$(dirname "$0")/../terraform" || exit 1
ARM_ACCESS_KEY=$(az storage account keys list -n f5salesdemotfstate -g f5-sales-demo-tfstate --query "[0].value" -o tsv)
export ARM_ACCESS_KEY

NS="webapp-api-protection"
LB_ADDR="module.http_lb.xcsh_http_loadbalancer.this"
LB_ID="${NS}/${NS}"
SDP_ADDR="module.http_lb.xcsh_sensitive_data_policy.this[0]"
SDP_ID="${NS}/${NS}-sensitive-data"
DEF_ADDR="module.http_lb.xcsh_api_definition.this[0]"
DEF_ID="${NS}/${NS}-api-def"
COMMON=(-input=false -lock=true
  -var 'lb_domains=["www.f5-sales-demo.com","api.f5-sales-demo.com"]'
  -var 'subscription_id=75f86c46-9cbc-4f6c-85ea-195e3d3c8ac0')
VARDIR=/tmp/apiprot-variants
REPORT=../reports/api-protection-matrix.txt
mkdir -p ../reports

START="${1:-0}"
END="${2:-9999}"
GATED_RE='entitlement|not subscribed|not entitled|not enabled for|permission denied|unauthorized|AS_NOT_SUBSCRIBED|status: 401|status: 403'

# Truncate the report on a full run; a batched range run (args given) appends.
[ "$#" -eq 0 ] && : >"$REPORT"

count=$(python3 ../scripts/api_protection_pairs.py --emit "$VARDIR")
echo "generated $count variants into $VARDIR (running [$START..$END])"

import_one() {
  local addr="$1" id="$2" vf="$3" label="$4"
  terraform state list 2>/dev/null | grep -qxF "$addr" || return 0
  terraform state rm "$addr" >/dev/null 2>&1 || return 0
  terraform import "${COMMON[@]}" -var-file="$vf" "$addr" "$id" >>/tmp/apiprot-import.log 2>&1 || {
    echo "FAIL $label import($addr)" >>"$REPORT"
    return 1
  }
}

round_trip() {
  local label="$1" vf="$2"
  # Import the LB first (always in state), then any standalone resources present.
  terraform state rm "$LB_ADDR" >/dev/null 2>&1 || {
    echo "FAIL $label lb-state-rm" >>"$REPORT"
    return
  }
  terraform import "${COMMON[@]}" -var-file="$vf" "$LB_ADDR" "$LB_ID" >/tmp/apiprot-import.log 2>&1 || {
    echo "FAIL $label lb-import" >>"$REPORT"
    return
  }
  import_one "$SDP_ADDR" "$SDP_ID" "$vf" "$label" || return
  import_one "$DEF_ADDR" "$DEF_ID" "$vf" "$label" || return
  terraform plan -detailed-exitcode "${COMMON[@]}" -var-file="$vf" >/tmp/apiprot-rt-plan.log 2>&1
  case $? in
  0) echo "PASS $label" >>"$REPORT" ;;
  2) echo "FAIL $label import-drift (no-secret variant must import clean)" >>"$REPORT" ;;
  *) echo "FAIL $label rt-plan-error" >>"$REPORT" ;;
  esac
}

while read -r idx name vf _flag; do
  [ "$idx" -lt "$START" ] && continue
  [ "$idx" -gt "$END" ] && continue
  label="$idx-$name"
  echo "--- $label ---"
  varfile="${VARDIR}/${vf}"
  if ! terraform apply -auto-approve "${COMMON[@]}" -var-file="$varfile" >/tmp/apiprot-apply.log 2>&1; then
    if grep -qiE "$GATED_RE" /tmp/apiprot-apply.log; then
      echo "SKIP $label gated-arm ($(grep -oiE "$GATED_RE" /tmp/apiprot-apply.log | head -1))" >>"$REPORT"
    else
      echo "FAIL $label apply ($(grep -iE 'error' /tmp/apiprot-apply.log | head -1 | cut -c1-80))" >>"$REPORT"
    fi
    continue
  fi
  terraform plan -detailed-exitcode "${COMMON[@]}" -var-file="$varfile" >/tmp/apiprot-plan.log 2>&1
  case $? in
  0) round_trip "$label" "$varfile" ;;
  2) echo "FAIL $label not-idempotent" >>"$REPORT" ;;
  *) echo "FAIL $label plan-error" >>"$REPORT" ;;
  esac
done <"${VARDIR}/manifest.txt"

echo "===== API PROTECTION MATRIX RESULTS ($START..$END) ====="
cat "$REPORT"
echo "PASS=$(grep -c '^PASS ' "$REPORT") FAIL=$(grep -c '^FAIL ' "$REPORT") SKIP=$(grep -c '^SKIP ' "$REPORT")"
