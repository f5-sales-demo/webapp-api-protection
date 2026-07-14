#!/usr/bin/env bash
# API Discovery + Crawler live coverage-matrix harness.
#
# Cycles the LIVE webapp-api-protection LB through the api_discovery_pairs variant
# set and verifies each variant is (a) applies, (b) idempotent (immediate plan =
# No changes), and (c) round-trip-import clean for the LB
# (module.http_lb.xcsh_http_loadbalancer.this) and, when present, the referenced
# xcsh_api_discovery. Ends on canonical-restore so the live LB is left healthy
# (bare enable_api_discovery {}). Results append to reports/api-discovery-matrix.txt.
#
# Write-only secrets: F5 XC does not return the crawler password on read, so an
# import cannot recover it (verified live; mirrors the provider's certificate
# blindfold test which ignores private_key on import). The round-trip therefore
# re-applies after import to re-set the write-only secret, then requires a clean
# plan. Variants without a crawler must import fully clean directly.
#
# Blindfold variants carry {method=blindfold} with no location; the harness seals
# a fixed plaintext ONCE (scripts/blindfold-seal.sh) and pins that location across
# the whole run (idempotent — provider::xcsh::blindfold is non-deterministic).
#
# Entitlement/permission-rejected arms are recorded SKIP (word/phrase signals only;
# a bare status number like 403 is NOT matched). A 400 BAD_REQUEST is a real FAIL.
# Sequential — no concurrent terraform against the shared azurerm state.
#
# Usage: api-discovery-matrix.sh [START [END]]  (inclusive 0-based index range).
set -uo pipefail

# Variant files hold credentials (clear plaintext in *.tfvars.json, Blindfold
# ciphertext in *.sealed.json) and refresh logs — create them owner-only and remove
# the whole variant dir + logs on exit.
umask 077
trap 'rm -rf /tmp/api-variants 2>/dev/null; rm -f /tmp/api-apply.log /tmp/api-plan.log /tmp/api-import.log /tmp/api-rt-plan.log /tmp/api-rt-plan2.log /tmp/api-rt-apply.log 2>/dev/null' EXIT

cd "$(dirname "$0")/../terraform" || exit 1
ARM_ACCESS_KEY=$(az storage account keys list -n f5salesdemotfstate -g f5-sales-demo-tfstate --query "[0].value" -o tsv)
export ARM_ACCESS_KEY

NS="webapp-api-protection"
LB_ADDR="module.http_lb.xcsh_http_loadbalancer.this"
LB_ID="${NS}/${NS}"
DISCO_ADDR="module.http_lb.xcsh_api_discovery.this[0]"
DISCO_ID="${NS}/${NS}-api-discovery"
COMMON=(-input=false -lock=true
  -var 'lb_domains=["www.f5-sales-demo.com","api.f5-sales-demo.com"]'
  -var 'subscription_id=75f86c46-9cbc-4f6c-85ea-195e3d3c8ac0')
VARDIR=/tmp/api-variants
REPORT=../reports/api-discovery-matrix.txt
mkdir -p ../reports

START="${1:-0}"
END="${2:-9999}"
SEAL_PLAINTEXT="Sp1-Cr@wl-Demo"
GATED_RE='entitlement|not subscribed|not entitled|not enabled for|permission denied|unauthorized|AS_NOT_SUBSCRIBED|status: 401|status: 403'

count=$(python3 ../scripts/api_discovery_pairs.py --emit "$VARDIR")
echo "generated $count variants into $VARDIR (running [$START..$END])"

BF_LOCATION=""
seal_once() {
  [ -n "$BF_LOCATION" ] && return 0
  BF_LOCATION=$(../scripts/blindfold-seal.sh "$SEAL_PLAINTEXT" 2>/dev/null)
  [ -n "$BF_LOCATION" ]
}

# Inject the pinned sealed location for blindfold variants; print the var-file to use.
prep_varfile() {
  local vf="$1" out
  if grep -q '"method": "blindfold"' "$vf" && ! grep -q '"location"' "$vf"; then
    seal_once || return 1
    out="${vf%.json}.sealed.json"
    jq --arg loc "$BF_LOCATION" '.api_crawler_password.location = $loc' "$vf" >"$out"
    echo "$out"
  else
    echo "$vf"
  fi
}

round_trip() {
  local label="$1" vf="$2"
  terraform state rm "$LB_ADDR" >/dev/null 2>&1 || {
    echo "FAIL $label lb-state-rm" >>"$REPORT"
    return
  }
  terraform import "${COMMON[@]}" -var-file="$vf" "$LB_ADDR" "$LB_ID" >/tmp/api-import.log 2>&1 || {
    echo "FAIL $label lb-import" >>"$REPORT"
    return
  }
  if terraform state list 2>/dev/null | grep -qxF "$DISCO_ADDR"; then
    terraform state rm "$DISCO_ADDR" >/dev/null 2>&1
    terraform import "${COMMON[@]}" -var-file="$vf" "$DISCO_ADDR" "$DISCO_ID" >>/tmp/api-import.log 2>&1 || {
      echo "FAIL $label disco-import" >>"$REPORT"
      return
    }
  fi
  terraform plan -detailed-exitcode "${COMMON[@]}" -var-file="$vf" >/tmp/api-rt-plan.log 2>&1
  case $? in
  0) echo "PASS $label" >>"$REPORT" ;;
  2)
    # The apply->idempotency gate already proved this variant is 0-change, so any
    # post-import drift is purely what import failed to recover. Import cannot recover
    # a WRITE-ONLY secret (F5 XC never returns it), so ONLY for variants that carry a
    # crawler password do we re-apply to re-set it and require a clean plan. Variants
    # with NO write-only secret must import 0-change; drift there is a real bug -> FAIL
    # (the re-apply escape hatch must not mask it).
    if grep -q 'api_crawler_password' "$vf"; then
      terraform apply -auto-approve "${COMMON[@]}" -var-file="$vf" >/tmp/api-rt-apply.log 2>&1
      terraform plan -detailed-exitcode "${COMMON[@]}" -var-file="$vf" >/tmp/api-rt-plan2.log 2>&1
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

while read -r idx name vf; do
  [ "$idx" -lt "$START" ] && continue
  [ "$idx" -gt "$END" ] && continue
  label="$idx-$name"
  echo "--- $label ---"
  varfile=$(prep_varfile "${VARDIR}/${vf}") || {
    echo "FAIL $label seal-prep" >>"$REPORT"
    continue
  }
  if ! terraform apply -auto-approve "${COMMON[@]}" -var-file="$varfile" >/tmp/api-apply.log 2>&1; then
    # Two documented, root-caused blockers are recorded SKIP (plan-tested, see
    # docs/superpowers/plans/sp1-findings.md) rather than FAIL:
    #  - custom_api_auth_discovery.api_discovery_ref.tenant unknown after apply
    #    (provider #1080-class object-ref-tenant bug), and
    #  - api_crawler password + blindfold_secret_info -> F5 XC 500 (platform-side;
    #    clear works). Everything else: gated -> SKIP; otherwise a real FAIL.
    if grep -qiE 'api_discovery_ref.tenant|invalid result object' /tmp/api-apply.log; then
      echo "SKIP $label known-provider-tenant-bug (api_discovery_ref.tenant; plan-tested)" >>"$REPORT"
    elif grep -q '"method": "blindfold"' "$varfile" && grep -qiE 'SERVER_ERROR|status: 500' /tmp/api-apply.log; then
      echo "SKIP $label known-blindfold-crawler-platform-500 (clear works; plan-tested)" >>"$REPORT"
    elif grep -qiE "$GATED_RE" /tmp/api-apply.log; then
      echo "SKIP $label gated-arm ($(grep -oiE "$GATED_RE" /tmp/api-apply.log | head -1))" >>"$REPORT"
    else
      echo "FAIL $label apply ($(grep -iE 'error' /tmp/api-apply.log | head -1 | cut -c1-80))" >>"$REPORT"
    fi
    continue
  fi
  terraform plan -detailed-exitcode "${COMMON[@]}" -var-file="$varfile" >/tmp/api-plan.log 2>&1
  case $? in
  0) round_trip "$label" "$varfile" ;;
  2) echo "FAIL $label not-idempotent" >>"$REPORT" ;;
  *) echo "FAIL $label plan-error" >>"$REPORT" ;;
  esac
done <"${VARDIR}/manifest.txt"

echo "===== API DISCOVERY MATRIX RESULTS ($START..$END) ====="
cat "$REPORT"
echo "PASS=$(grep -c '^PASS ' "$REPORT") FAIL=$(grep -c '^FAIL ' "$REPORT") SKIP=$(grep -c '^SKIP ' "$REPORT")"
