#!/usr/bin/env bash
# API Definition & spec-enforcement (SP2) live coverage-matrix harness.
#
# Cycles the LIVE webapp-api-protection LB through the api_definition_pairs variant
# set and verifies each LIVE variant (a) applies, (b) is idempotent (immediate plan
# = No changes), and (c) is round-trip-import clean for the LB and, when present,
# the referenced xcsh_api_definition and xcsh_code_base_integration. Ends on
# canonical-restore so the live LB is left healthy (all SP2 features off). Results
# append to reports/api-definition-matrix.txt.
#
# Secret injection (never committed): the manifest holds NO secret values.
#  - clear code_base_integration access_token  <- $GH_TOKEN (env),
#  - blindfold access_token location           <- sealed ONCE via blindfold-seal.sh,
#  - swagger_specs __SWAGGER_PATH__             <- one OpenAPI file uploaded ONCE via
#    scripts/swagger-upload.sh and pinned across the run (content-addressed).
#
# Write-only secrets: F5 XC never returns the access_token on read, so an import
# cannot recover it. Variants that create a code_base_integration therefore re-apply
# after import to re-set the write-only secret, then require a clean plan. Variants
# with no write-only secret (api_definition / LB only) must import 0-change.
#
# blindfold access_token 500s on F5 XC (documented platform limitation, see
# docs/superpowers/plans/sp2-findings.md); those variants are marked SKIP in the
# manifest and are plan-tested only. A 400 BAD_REQUEST is a real FAIL.
# Sequential — no concurrent terraform against the shared azurerm state.
#
# Usage: api-definition-matrix.sh [START [END]]  (inclusive 0-based index range).
set -uo pipefail

umask 077
trap 'rm -rf /tmp/apidef-variants /tmp/apidef-bf.loc /tmp/apidef-swagger.path 2>/dev/null; rm -f /tmp/apidef-*.log /tmp/apidef-*.json 2>/dev/null' EXIT

cd "$(dirname "$0")/../terraform" || exit 1
ARM_ACCESS_KEY=$(az storage account keys list -n f5salesdemotfstate -g f5-sales-demo-tfstate --query "[0].value" -o tsv)
export ARM_ACCESS_KEY
: "${GH_TOKEN:?GH_TOKEN must be set (clear code_base_integration access_token)}"
export GH_TOKEN # so jq can read it via env.GH_TOKEN (never passed on argv)

NS="webapp-api-protection"
LB_ADDR="module.http_lb.xcsh_http_loadbalancer.this"
LB_ID="${NS}/${NS}"
DEF_ADDR="module.http_lb.xcsh_api_definition.this[0]"
DEF_ID="${NS}/${NS}-api-def"
SCM_ADDR="module.http_lb.xcsh_code_base_integration.github[0]"
SCM_ID="${NS}/${NS}-api-catalog"
COMMON=(-input=false -lock=true
  -var 'lb_domains=["www.f5-sales-demo.com","api.f5-sales-demo.com"]'
  -var 'subscription_id=75f86c46-9cbc-4f6c-85ea-195e3d3c8ac0')
VARDIR=/tmp/apidef-variants
REPORT=../reports/api-definition-matrix.txt
mkdir -p ../reports

START="${1:-0}"
END="${2:-9999}"

# Truncate the report on a full run; a batched range run (args given) appends.
[ "$#" -eq 0 ] && : >"$REPORT"

count=$(python3 ../scripts/api_definition_pairs.py --emit "$VARDIR")
echo "generated $count variants into $VARDIR (running [$START..$END])"

# Seal/upload ONCE and persist to sentinel files. prep_varfile runs in a command
# substitution (a subshell), so in-memory globals would not survive between
# variants — the sentinel files do. Blindfold is non-deterministic, so re-sealing
# per variant would drift; the swagger store is content-addressed (re-upload is a
# no-op) but we still upload once. The token is piped via stdin (never argv).
BF_LOC_FILE=/tmp/apidef-bf.loc
seal_once() {
  [ -s "$BF_LOC_FILE" ] && return 0
  printf '%s' "$GH_TOKEN" | ../scripts/blindfold-seal.sh 2>/dev/null >"$BF_LOC_FILE"
  [ -s "$BF_LOC_FILE" ]
}

SWAGGER_PATH_FILE=/tmp/apidef-swagger.path
upload_swagger_once() {
  [ -s "$SWAGGER_PATH_FILE" ] && return 0
  # A tiny valid OpenAPI doc is enough to exercise the swagger_specs supply path.
  local spec=/tmp/apidef-spec.json
  printf '%s' '{"openapi":"3.0.0","info":{"title":"webapp-api-protection-matrix","version":"1.0.0"},"paths":{"/health":{"get":{"responses":{"200":{"description":"ok"}}}}}}' >"$spec"
  ../scripts/swagger-upload.sh matrix-probe "$spec" "$NS" 2>/dev/null >"$SWAGGER_PATH_FILE"
  [ -s "$SWAGGER_PATH_FILE" ]
}

# Inject live secret/path values; print the var-file to use.
prep_varfile() {
  local vf="$1" out="${1%.json}.live.json"
  cp "$vf" "$out"
  if grep -q '"method": "clear"' "$out"; then
    # Read the token from the environment (env.GH_TOKEN), never argv — a positional
    # --arg is visible in /proc/<pid>/cmdline to any local user; the environment is
    # readable only by the process owner and root.
    jq '.code_base_integration_access_token.plaintext = env.GH_TOKEN' "$out" >"${out}.tmp" && mv "${out}.tmp" "$out"
  fi
  if grep -q '"method": "blindfold"' "$out" && ! grep -q '"location"' "$out"; then
    seal_once || return 1
    jq --arg loc "$(cat "$BF_LOC_FILE")" '.code_base_integration_access_token.location = $loc' "$out" >"${out}.tmp" && mv "${out}.tmp" "$out"
  fi
  if grep -q '__SWAGGER_PATH__' "$out"; then
    upload_swagger_once || return 1
    jq --arg p "$(cat "$SWAGGER_PATH_FILE")" '.api_definition_swagger_specs = [$p]' "$out" >"${out}.tmp" && mv "${out}.tmp" "$out"
  fi
  echo "$out"
}

import_one() {
  local addr="$1" id="$2" vf="$3" label="$4"
  terraform state rm "$addr" >/dev/null 2>&1 || return 0
  terraform import "${COMMON[@]}" -var-file="$vf" "$addr" "$id" >>/tmp/apidef-import.log 2>&1 || {
    echo "FAIL $label import($addr)" >>"$REPORT"
    return 1
  }
}

round_trip() {
  local label="$1" vf="$2"
  import_one "$LB_ADDR" "$LB_ID" "$vf" "$label" || return
  if terraform state list 2>/dev/null | grep -qxF "$DEF_ADDR"; then
    import_one "$DEF_ADDR" "$DEF_ID" "$vf" "$label" || return
  fi
  if terraform state list 2>/dev/null | grep -qxF "$SCM_ADDR"; then
    import_one "$SCM_ADDR" "$SCM_ID" "$vf" "$label" || return
  fi
  terraform plan -detailed-exitcode "${COMMON[@]}" -var-file="$vf" >/tmp/apidef-rt-plan.log 2>&1
  case $? in
  0) echo "PASS $label" >>"$REPORT" ;;
  2)
    # Only a code_base_integration variant carries a write-only secret (access_token)
    # that import cannot recover — re-apply to re-set it, then require a clean plan.
    # Any other post-import drift is a real bug (no escape hatch).
    if grep -q '"code_base_integration_enabled": true' "$vf"; then
      terraform apply -auto-approve "${COMMON[@]}" -var-file="$vf" >/tmp/apidef-rt-apply.log 2>&1
      terraform plan -detailed-exitcode "${COMMON[@]}" -var-file="$vf" >/tmp/apidef-rt-plan2.log 2>&1
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
    echo "FAIL $label prep" >>"$REPORT"
    continue
  }
  # SKIP variants (blindfold access_token) are plan-tested only — verify they render.
  if [[ "$flag" == SKIP:* ]]; then
    if terraform plan "${COMMON[@]}" -var-file="$varfile" >/tmp/apidef-plan.log 2>&1; then
      echo "SKIP $label ${flag#SKIP:} (plan renders)" >>"$REPORT"
    else
      echo "FAIL $label skip-variant-plan-error" >>"$REPORT"
    fi
    continue
  fi
  if ! terraform apply -auto-approve "${COMMON[@]}" -var-file="$varfile" >/tmp/apidef-apply.log 2>&1; then
    echo "FAIL $label apply ($(grep -iE 'error' /tmp/apidef-apply.log | head -1 | cut -c1-80))" >>"$REPORT"
    continue
  fi
  terraform plan -detailed-exitcode "${COMMON[@]}" -var-file="$varfile" >/tmp/apidef-plan.log 2>&1
  case $? in
  0) round_trip "$label" "$varfile" ;;
  2) echo "FAIL $label not-idempotent" >>"$REPORT" ;;
  *) echo "FAIL $label plan-error" >>"$REPORT" ;;
  esac
done <"${VARDIR}/manifest.txt"

echo "===== API DEFINITION MATRIX RESULTS ($START..$END) ====="
cat "$REPORT"
echo "PASS=$(grep -c '^PASS ' "$REPORT") FAIL=$(grep -c '^FAIL ' "$REPORT") SKIP=$(grep -c '^SKIP ' "$REPORT")"
