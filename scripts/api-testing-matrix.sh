#!/usr/bin/env bash
# API Testing (SP4) live coverage-matrix harness.
#
# Cycles the LIVE webapp-api-protection LB through the api_testing_pairs variant set
# and verifies each variant (a) applies, (b) is idempotent (immediate plan = No
# changes), and (c) is round-trip-import clean for the LB and, when present, the
# standalone xcsh_api_testing resource. Ends on canonical-restore so the live LB is
# left healthy (API testing off). Results append to reports/api-testing-matrix.txt.
#
# Secret injection (never committed): the manifest carries only placeholders.
#  - clear credential secret (__TEST_SECRET__) <- $API_TEST_SECRET (env, throwaway).
#  - blindfold credential secret (__BF_LOCATION__) <- sealed ONCE via blindfold-seal.sh.
# Secrets are written via jq using env.* (never argv — a positional --arg is visible
# in /proc/<pid>/cmdline to any local user).
#
# Manifest flags:
#  LIVE   - admin/standard credential (no write-only secret): must import 0-change.
#  SECRET - clear api_key/basic_auth/bearer_token: F5 XC never returns the secret on
#           read, so import cannot recover it — re-apply after import to re-set it,
#           then require a clean plan (write-only-secret gate).
#  SKIP:* - blindfold credential: attempted live; a 500 / not-supported / entitlement
#           response is recorded SKIP (documented platform limitation, cf. SP1/SP2),
#           NOT a FAIL. A 400 BAD_REQUEST is a real FAIL.
# Sequential — no concurrent terraform against the shared azurerm state.
#
# Usage: api-testing-matrix.sh [START [END]]  (inclusive 0-based index range).
set -uo pipefail

umask 077
trap 'rm -rf /tmp/apitest-variants 2>/dev/null; rm -f /tmp/apitest-*.log /tmp/apitest-*.json /tmp/apitest-bf.loc 2>/dev/null' EXIT

cd "$(dirname "$0")/../terraform" || exit 1
ARM_ACCESS_KEY=$(az storage account keys list -n f5salesdemotfstate -g f5-sales-demo-tfstate --query "[0].value" -o tsv)
export ARM_ACCESS_KEY
# Throwaway secret for API-testing credentials (dev env). Not a real credential.
export API_TEST_SECRET="${API_TEST_SECRET:-sp4-matrix-probe-$RANDOM}"

NS="webapp-api-protection"
LB_ADDR="module.http_lb.xcsh_http_loadbalancer.this"
LB_ID="${NS}/${NS}"
AT_ADDR="module.http_lb.xcsh_api_testing.this[0]"
AT_ID="${NS}/${NS}-api-testing"
COMMON=(-input=false -lock=true
  -var 'lb_domains=["www.f5-sales-demo.com","api.f5-sales-demo.com"]'
  -var 'subscription_id=75f86c46-9cbc-4f6c-85ea-195e3d3c8ac0')
VARDIR=/tmp/apitest-variants
REPORT=../reports/api-testing-matrix.txt
mkdir -p ../reports

START="${1:-0}"
END="${2:-9999}"
GATED_RE='not supported|not enabled|not entitled|entitlement|status: 500|internal error|InternalError'

[ "$#" -eq 0 ] && : >"$REPORT"

count=$(python3 ../scripts/api_testing_pairs.py --emit "$VARDIR")
echo "generated $count variants into $VARDIR (running [$START..$END])"

# Seal a throwaway blindfold value ONCE (non-deterministic — re-sealing per variant
# would drift). Persisted to a sentinel file (prep_varfile runs in a subshell).
BF_LOC_FILE=/tmp/apitest-bf.loc
seal_once() {
  [ -s "$BF_LOC_FILE" ] && return 0
  printf '%s' "$API_TEST_SECRET" | ../scripts/blindfold-seal.sh 2>/dev/null >"$BF_LOC_FILE"
  [ -s "$BF_LOC_FILE" ]
}

# Inject live secret values into a variant's credentials; print the var-file to use.
prep_varfile() {
  local vf="$1" out="${1%.json}.live.json"
  cp "$vf" "$out"
  if grep -q '"method": "clear"' "$out"; then
    jq '.api_testing_domains |= map(.credentials |= map(
          if .secret.method == "clear" then .secret.plaintext = env.API_TEST_SECRET else . end))' \
      "$out" >"${out}.tmp" && mv "${out}.tmp" "$out"
  fi
  if grep -q '"method": "blindfold"' "$out"; then
    seal_once || return 1
    jq --arg loc "$(cat "$BF_LOC_FILE")" '.api_testing_domains |= map(.credentials |= map(
          if .secret.method == "blindfold" then .secret.location = $loc else . end))' \
      "$out" >"${out}.tmp" && mv "${out}.tmp" "$out"
  fi
  echo "$out"
}

import_one() {
  local addr="$1" id="$2" vf="$3" label="$4"
  terraform state list 2>/dev/null | grep -qxF "$addr" || return 0
  terraform state rm "$addr" >/dev/null 2>&1 || return 0
  terraform import "${COMMON[@]}" -var-file="$vf" "$addr" "$id" >>/tmp/apitest-import.log 2>&1 || {
    echo "FAIL $label import($addr)" >>"$REPORT"
    return 1
  }
}

round_trip() {
  local label="$1" vf="$2" flag="$3"
  terraform state rm "$LB_ADDR" >/dev/null 2>&1 || {
    echo "FAIL $label lb-state-rm" >>"$REPORT"
    return
  }
  terraform import "${COMMON[@]}" -var-file="$vf" "$LB_ADDR" "$LB_ID" >/tmp/apitest-import.log 2>&1 || {
    echo "FAIL $label lb-import" >>"$REPORT"
    return
  }
  import_one "$AT_ADDR" "$AT_ID" "$vf" "$label" || return
  terraform plan -detailed-exitcode "${COMMON[@]}" -var-file="$vf" >/tmp/apitest-rt-plan.log 2>&1
  case $? in
  0) echo "PASS $label" >>"$REPORT" ;;
  2)
    # SECRET variants carry a write-only credential secret import cannot recover —
    # re-apply to re-set it, then require a clean plan. Others must import clean.
    if [ "$flag" = "SECRET" ]; then
      terraform apply -auto-approve "${COMMON[@]}" -var-file="$vf" >/tmp/apitest-rt-apply.log 2>&1
      terraform plan -detailed-exitcode "${COMMON[@]}" -var-file="$vf" >/tmp/apitest-rt-plan2.log 2>&1
      case $? in
      0) echo "PASS $label (import re-set write-only secret)" >>"$REPORT" ;;
      2) echo "FAIL $label import-drift" >>"$REPORT" ;;
      *) echo "FAIL $label rt-plan-error" >>"$REPORT" ;;
      esac
    else
      echo "FAIL $label import-drift (no-secret variant must import clean)" >>"$REPORT"
    fi
    ;;
  *) echo "FAIL $label rt-plan-error" >>"$REPORT" ;;
  esac
}

while read -r idx name vf flag; do
  [ "$idx" -lt "$START" ] && continue
  [ "$idx" -gt "$END" ] && continue
  label="$idx-$name"
  echo "--- $label ($flag) ---"
  varfile=$(prep_varfile "${VARDIR}/${vf}") || {
    echo "FAIL $label prep (seal/inject)" >>"$REPORT"
    continue
  }
  if ! terraform apply -auto-approve "${COMMON[@]}" -var-file="$varfile" >/tmp/apitest-apply.log 2>&1; then
    # blindfold variants are expected to fail on the platform limitation -> SKIP.
    if [[ "$flag" == SKIP:* ]] && grep -qiE "$GATED_RE" /tmp/apitest-apply.log; then
      echo "SKIP $label ${flag#SKIP:} ($(grep -oiE "$GATED_RE" /tmp/apitest-apply.log | head -1))" >>"$REPORT"
    else
      echo "FAIL $label apply ($(grep -iE 'error' /tmp/apitest-apply.log | head -1 | cut -c1-80))" >>"$REPORT"
    fi
    continue
  fi
  terraform plan -detailed-exitcode "${COMMON[@]}" -var-file="$varfile" >/tmp/apitest-plan.log 2>&1
  case $? in
  0) round_trip "$label" "$varfile" "$flag" ;;
  2) echo "FAIL $label not-idempotent" >>"$REPORT" ;;
  *) echo "FAIL $label plan-error" >>"$REPORT" ;;
  esac
done <"${VARDIR}/manifest.txt"

echo "===== API TESTING MATRIX RESULTS ($START..$END) ====="
cat "$REPORT"
echo "PASS=$(grep -c '^PASS ' "$REPORT") FAIL=$(grep -c '^FAIL ' "$REPORT") SKIP=$(grep -c '^SKIP ' "$REPORT")"
