#!/usr/bin/env bash
# LB l7_ddos_protection (DDoS-1) live coverage-matrix harness.
#
# Cycles the LIVE webapp-api-protection LB through the ddos_pairs variant set and verifies
# each variant (a) applies, (b) is idempotent (immediate plan = No changes), and (c) is
# round-trip-import clean for the whole LB (state rm -> import -> plan clean). The challenge_type
# is an LB-nested oneof, so the import target is the http_loadbalancer itself. Ends on
# canonical-restore (challenge unset + MUD on -> the LB's normal enable+attach state). Results
# append to reports/ddos-matrix.txt.
#
# js/captcha challenge ALL traffic transiently; canonical-restore returns the LB to the MUD
# default so www/api serve normally afterward. Sequential — no concurrent terraform against the
# shared azurerm state.
#
# Usage: challenge-matrix.sh [START [END]]  (inclusive 0-based index range).
set -uo pipefail

umask 077
trap 'rm -rf /tmp/ddos-variants 2>/dev/null; rm -f /tmp/ddos-*.log 2>/dev/null' EXIT

cd "$(dirname "$0")/../terraform" || exit 1
ARM_ACCESS_KEY=$(az storage account keys list -n f5salesdemotfstate -g f5-sales-demo-tfstate --query "[0].value" -o tsv)
export ARM_ACCESS_KEY

NS="webapp-api-protection"
LB_ADDR="module.http_lb.xcsh_http_loadbalancer.this"
LB_ID="${NS}/${NS}"
COMMON=(-input=false -lock=true
  -var 'lb_domains=["www.f5-sales-demo.com","api.f5-sales-demo.com"]'
  -var 'subscription_id=75f86c46-9cbc-4f6c-85ea-195e3d3c8ac0')
VARDIR=/tmp/ddos-variants
REPORT=../reports/ddos-matrix.txt
mkdir -p ../reports

START="${1:-0}"
END="${2:-9999}"

[ "$#" -eq 0 ] && : >"$REPORT"

count=$(python3 ../scripts/ddos_pairs.py --emit "$VARDIR")
echo "generated $count variants into $VARDIR (running [$START..$END])"

round_trip() {
  local label="$1" vf="$2"
  terraform state rm "$LB_ADDR" >/dev/null 2>&1 || {
    echo "FAIL $label lb-state-rm" >>"$REPORT"
    return
  }
  terraform import "${COMMON[@]}" -var-file="$vf" "$LB_ADDR" "$LB_ID" >/tmp/ddos-import.log 2>&1 || {
    echo "FAIL $label lb-import ($(grep -iE 'error' /tmp/ddos-import.log | head -1 | cut -c1-70))" >>"$REPORT"
    return
  }
  terraform plan -detailed-exitcode "${COMMON[@]}" -var-file="$vf" >/tmp/ddos-rt-plan.log 2>&1
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
  if ! terraform apply -auto-approve "${COMMON[@]}" -var-file="$varfile" >/tmp/ddos-apply.log 2>&1; then
    echo "FAIL $label apply ($(grep -iE 'error' /tmp/ddos-apply.log | head -1 | cut -c1-80))" >>"$REPORT"
    continue
  fi
  terraform plan -detailed-exitcode "${COMMON[@]}" -var-file="$varfile" >/tmp/ddos-plan.log 2>&1
  case $? in
  0) round_trip "$label" "$varfile" ;;
  2) echo "FAIL $label not-idempotent" >>"$REPORT" ;;
  *) echo "FAIL $label plan-error" >>"$REPORT" ;;
  esac
done <"${VARDIR}/manifest.txt"

echo "===== DDOS MATRIX RESULTS ($START..$END) ====="
cat "$REPORT"
echo "PASS=$(grep -c '^PASS ' "$REPORT") FAIL=$(grep -c '^FAIL ' "$REPORT") SKIP=$(grep -c '^SKIP ' "$REPORT")"
