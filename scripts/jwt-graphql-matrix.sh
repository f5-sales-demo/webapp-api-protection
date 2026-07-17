#!/usr/bin/env bash
# JWT validation + GraphQL inspection (LPC-3) live coverage-matrix harness.
#
# Cycles the LIVE webapp-api-protection LB through the jwt_graphql_pairs variant set and
# verifies each variant (a) applies, (b) is idempotent (immediate plan = No changes), and
# (c) is round-trip-import clean for the LB (state rm -> import -> plan clean). Both features
# are LB-nested, so the import target is the http_loadbalancer itself. Ends on
# canonical-restore so the live LB is left healthy (jwt + graphql off). Results append to
# reports/jwt-graphql-matrix.txt.
#
# The JWKS is a public RSA key and the graphql rules only add inspection limits, so no real
# client traffic is ever blocked and the LB stays serving throughout. An arm F5 XC rejects for
# entitlement is recorded SKIP (word signals; a bare status number is not matched) rather than
# FAIL. Sequential — no concurrent terraform against the shared azurerm state.
#
# Usage: jwt-graphql-matrix.sh [START [END]]  (inclusive 0-based index range).
set -uo pipefail

umask 077
trap 'rm -rf /tmp/lpc3-variants 2>/dev/null; rm -f /tmp/lpc3-*.log 2>/dev/null' EXIT

cd "$(dirname "$0")/../terraform" || exit 1
ARM_ACCESS_KEY=$(az storage account keys list -n f5salesdemotfstate -g f5-sales-demo-tfstate --query "[0].value" -o tsv)
export ARM_ACCESS_KEY

NS="webapp-api-protection"
LB_ADDR="module.http_lb.xcsh_http_loadbalancer.this"
LB_ID="${NS}/${NS}"
COMMON=(-input=false -lock=true
  -var 'lb_domains=["www.f5-sales-demo.com","api.f5-sales-demo.com"]'
  -var 'subscription_id=75f86c46-9cbc-4f6c-85ea-195e3d3c8ac0')
VARDIR=/tmp/lpc3-variants
REPORT=../reports/jwt-graphql-matrix.txt
mkdir -p ../reports

START="${1:-0}"
END="${2:-9999}"
GATED_RE='entitlement|not subscribed|not entitled|not enabled for|permission denied|unauthorized|AS_NOT_SUBSCRIBED|status: 401|status: 403'

[ "$#" -eq 0 ] && : >"$REPORT"

count=$(python3 ../scripts/jwt_graphql_pairs.py --emit "$VARDIR")
echo "generated $count variants into $VARDIR (running [$START..$END])"

round_trip() {
  local label="$1" vf="$2" flag="$3"
  terraform state rm "$LB_ADDR" >/dev/null 2>&1 || {
    echo "FAIL $label lb-state-rm" >>"$REPORT"
    return
  }
  terraform import "${COMMON[@]}" -var-file="$vf" "$LB_ADDR" "$LB_ID" >/tmp/lpc3-import.log 2>&1 || {
    echo "FAIL $label lb-import ($(grep -iE 'error' /tmp/lpc3-import.log | head -1 | cut -c1-70))" >>"$REPORT"
    return
  }
  if [ "$flag" = "SECRET" ]; then
    # jwt_validation.jwks_config.cleartext is a write-only secret the API masks as "Redacted",
    # so import always re-applies it. PASS if that secret is the ONLY meaningful LB drift
    # (any other changed leaf is a real import bug); classified from the plan JSON.
    terraform plan -out=/tmp/lpc3-rt.tfplan "${COMMON[@]}" -var-file="$vf" >/tmp/lpc3-rt-plan.log 2>&1 || {
      echo "FAIL $label rt-plan-error" >>"$REPORT"
      return
    }
    terraform show -json /tmp/lpc3-rt.tfplan >/tmp/lpc3-rt.json 2>/dev/null
    if python3 ../scripts/lpc3_import_check.py /tmp/lpc3-rt.json >/tmp/lpc3-classify.log 2>&1; then
      echo "PASS $label (secret re-apply expected)" >>"$REPORT"
    else
      echo "FAIL $label import-drift ($(grep -v 'unexpected' /tmp/lpc3-classify.log | head -1 | tr -s ' '))" >>"$REPORT"
    fi
    return
  fi
  terraform plan -detailed-exitcode "${COMMON[@]}" -var-file="$vf" >/tmp/lpc3-rt-plan.log 2>&1
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
  echo "--- $label ---"
  varfile="${VARDIR}/${vf}"
  if ! terraform apply -auto-approve "${COMMON[@]}" -var-file="$varfile" >/tmp/lpc3-apply.log 2>&1; then
    if grep -qiE "$GATED_RE" /tmp/lpc3-apply.log; then
      echo "SKIP $label gated-arm ($(grep -oiE "$GATED_RE" /tmp/lpc3-apply.log | head -1))" >>"$REPORT"
    else
      echo "FAIL $label apply ($(grep -iE 'error' /tmp/lpc3-apply.log | head -1 | cut -c1-80))" >>"$REPORT"
    fi
    continue
  fi
  terraform plan -detailed-exitcode "${COMMON[@]}" -var-file="$varfile" >/tmp/lpc3-plan.log 2>&1
  case $? in
  0) round_trip "$label" "$varfile" "$flag" ;;
  2) echo "FAIL $label not-idempotent" >>"$REPORT" ;;
  *) echo "FAIL $label plan-error" >>"$REPORT" ;;
  esac
done <"${VARDIR}/manifest.txt"

echo "===== JWT + GRAPHQL MATRIX RESULTS ($START..$END) ====="
cat "$REPORT"
echo "PASS=$(grep -c '^PASS ' "$REPORT") FAIL=$(grep -c '^FAIL ' "$REPORT") SKIP=$(grep -c '^SKIP ' "$REPORT")"
