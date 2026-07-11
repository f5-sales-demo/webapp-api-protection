#!/usr/bin/env bash
# MUD live config-matrix harness.
#
# Cycles the LIVE webapp-api-protection load balancer through every MUD option
# combination and verifies each is (a) applies, (b) idempotent (immediate plan =
# No changes), and (c) round-trip-import clean (state rm -> import -> plan clean)
# for the LB, the malicious_user_mitigation policy, and (when present) the
# user_identification policy. Results append to reports/mud-matrix.txt. Ends by
# applying the canonical full config so the live LB is left healthy.
#
# Pre-prod tenant, in-place on the live LB (per the approved spec). Sequential —
# no concurrent terraform against the shared state.
set -uo pipefail

cd "$(dirname "$0")/../terraform"
export ARM_ACCESS_KEY=$(az storage account keys list -n f5salesdemotfstate -g f5-sales-demo-tfstate --query "[0].value" -o tsv)

NS="webapp-api-protection"
COMMON=(-input=false -lock=true
  -var 'lb_domains=["www.f5-sales-demo.com","api.f5-sales-demo.com"]'
  -var 'subscription_id=75f86c46-9cbc-4f6c-85ea-195e3d3c8ac0')
REPORT=../reports/mud-matrix.txt
mkdir -p ../reports
: > "$REPORT"

# round_trip <label> -- for each managed MUD resource present in state, state rm +
# import, then a clean plan. Sets RT_FAIL on any failure.
round_trip() {
  local label="$1"
  local -a addrs=(
    "module.http_lb.xcsh_http_loadbalancer.this|${NS}/${NS}"
    "module.http_lb.xcsh_malicious_user_mitigation.mud[0]|${NS}/${NS}-mud"
  )
  # user_identification only exists for user_identification combos
  if terraform state list 2>/dev/null | grep -q 'xcsh_user_identification.mud\[0\]'; then
    addrs+=("module.http_lb.xcsh_user_identification.mud[0]|${NS}/${NS}-mud-userid")
  fi
  local a addr id
  for a in "${addrs[@]}"; do
    addr="${a%%|*}"; id="${a##*|}"
    terraform state rm "$addr" >/dev/null 2>&1 || { echo "FAIL $label state-rm($addr)" >>"$REPORT"; return; }
    terraform import "${COMMON[@]}" "${VARS[@]}" "$addr" "$id" >/tmp/mud-import.log 2>&1 || { echo "FAIL $label import($addr)" >>"$REPORT"; return; }
  done
  terraform plan -detailed-exitcode "${COMMON[@]}" "${VARS[@]}" >/tmp/mud-rt-plan.log 2>&1
  case $? in
    0) echo "PASS $label" >>"$REPORT" ;;
    2) echo "FAIL $label import-drift" >>"$REPORT" ;;
    *) echo "FAIL $label rt-plan-error" >>"$REPORT" ;;
  esac
}

# check <label> <var...> -- apply the combo, assert idempotent, then round-trip.
check() {
  local label="$1"; shift
  VARS=("$@")
  echo "--- $label ---"
  terraform apply -auto-approve "${COMMON[@]}" "${VARS[@]}" >/tmp/mud-apply.log 2>&1 || { echo "FAIL $label apply" >>"$REPORT"; return; }
  terraform plan -detailed-exitcode "${COMMON[@]}" "${VARS[@]}" >/tmp/mud-plan.log 2>&1
  case $? in
    0) : ;;
    2) echo "FAIL $label not-idempotent" >>"$REPORT"; return ;;
    *) echo "FAIL $label plan-error" >>"$REPORT"; return ;;
  esac
  round_trip "$label"
}

# --- challenge modes ---
for mode in enable_challenge policy_based_challenge none; do
  check "challenge-$mode" -var "mud_challenge_mode=$mode"
done

# --- mitigation action at every level (all-same-action covers 9 pairings) ---
for act in block_temporarily captcha_challenge javascript_challenge; do
  check "mitigation-all-$act" -var "mud_mitigation={low=\"$act\",medium=\"$act\",high=\"$act\"}"
done

# --- every user-identification rule type ---
for rule in cookie_name http_header_name ip_and_http_header_name jwt_claim_name \
            query_param_key client_asn client_city client_country client_ip \
            client_region tls_fingerprint ip_and_tls_fingerprint ja4_tls_fingerprint \
            ip_and_ja4_tls_fingerprint none; do
  check "userid-$rule" -var mud_user_id=user_identification -var "mud_user_id_rule=$rule"
done

# --- canonical end-state (leave the live LB healthy) ---
check "canonical" -var mud_user_id=client_ip -var mud_challenge_mode=enable_challenge \
  -var 'mud_mitigation={low="javascript_challenge",medium="captcha_challenge",high="block_temporarily"}'

echo "===== MUD MATRIX RESULTS ====="
cat "$REPORT"
echo "PASS=$(grep -c '^PASS ' "$REPORT") FAIL=$(grep -c '^FAIL ' "$REPORT")"
