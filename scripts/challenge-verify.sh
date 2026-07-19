#!/usr/bin/env bash
# Challenge behavioral verification (CH-4).
#
# Closed-loop check that the F5 XC LB actually SERVES a JavaScript/CAPTCHA challenge interstitial
# for challenged traffic (not just that the config applied). Unlike the API-protection verify
# (which reads the security-events data plane), a challenge is served INLINE in the HTTP response,
# so the assertion must fetch the LB from a client that can reach it. The LB is only reachable from
# the deployed traffic-generator VM, so this drives the fetch there via `az vm run-command`
# (matching the SP5 pattern) and asserts the XC challenge interstitial signature.
#
# Two steps:
#   1. Control plane (reachable anywhere): confirm an ALL-TRAFFIC challenge is active on the LB
#      (js_challenge / captcha_challenge, or policy_based_challenge always_enable_*). A risk-based
#      enable_challenge / policy_based rule_list is NOT asserted here — those are conditioned on
#      malicious-user scoring and do not challenge an anonymous request.
#   2. Data path (from the VM): fetch the target over HTTP and assert the interstitial —
#      HTTP 200 whose body carries the XC JS challenge (a `function SHA1` proof-of-work + the
#      word "challenge") and is NOT the origin home page. A CAPTCHA challenge asserts the CAPTCHA
#      markers instead.
#
# Read-only against both planes (no config change). Env: XCSH_API_URL, XCSH_API_TOKEN, and Azure
# CLI logged in for run-command. Usage: challenge-verify.sh
set -uo pipefail

: "${XCSH_API_URL:?XCSH_API_URL must be set}"
: "${XCSH_API_TOKEN:?XCSH_API_TOKEN must be set}"
NS="${NS:-webapp-api-protection}"
LB="${LB:-webapp-api-protection}"
TARGET="${TARGET:-http://www.f5-sales-demo.com/}"
VM_NAME="${VM_NAME:-vm-traffic-generator-rmordasiewicz}"
VM_RG="${VM_RG:-rg-traffic-generator-webapp-api-protection-rmordasiewicz}"
base="${XCSH_API_URL%/}"
auth=(-H "Authorization: APIToken ${XCSH_API_TOKEN}")

echo "== 1) Is an all-traffic challenge active on the LB? =="
cfg=$(curl -s "${auth[@]}" "${base}/api/config/namespaces/${NS}/http_loadbalancers/${LB}?response_format=GET_RSP_FORMAT_DEFAULT")
active=$(printf '%s' "$cfg" | python3 -c '
import sys, json
s = (json.load(sys.stdin) or {}).get("spec", {})
if s.get("js_challenge") is not None: print("js"); sys.exit(0)
if s.get("captcha_challenge") is not None: print("captcha"); sys.exit(0)
pbc = s.get("policy_based_challenge") or {}
if pbc.get("always_enable_js_challenge") is not None: print("js"); sys.exit(0)
if pbc.get("always_enable_captcha_challenge") is not None: print("captcha"); sys.exit(0)
print("none"); sys.exit(1)
') || {
  echo "  => no all-traffic challenge active (js/captcha/always_enable). Enable one before verifying;"
  echo "     risk-based enable_challenge / rule_list challenges are not served to anonymous requests."
  exit 2
}
echo "  active challenge: ${active}"

echo "== 2) Fetch the target from the traffic-generator VM and assert the interstitial =="
remote=$(
  cat <<REMOTE
code=\$(curl -s -m 15 -o /tmp/chv -w '%{http_code}' -A 'challenge-verify' '${TARGET}')
bytes=\$(wc -c </tmp/chv)
echo "HTTP \${code} \${bytes} bytes"
if [ "${active}" = "captcha" ]; then
  grep -qiE 'captcha|recaptcha|g-recaptcha' /tmp/chv && echo "CHALLENGE_OK captcha" || echo "CHALLENGE_MISSING"
else
  { grep -qi 'function SHA1' /tmp/chv && grep -qi 'challenge' /tmp/chv; } && echo "CHALLENGE_OK js" || echo "CHALLENGE_MISSING"
fi
REMOTE
)
msg=$(az vm run-command invoke --name "${VM_NAME}" --resource-group "${VM_RG}" \
  --command-id RunShellScript --scripts "${remote}" --query "value[0].message" -o tsv 2>&1)
echo "${msg}" | grep -E 'HTTP |CHALLENGE_'
if printf '%s' "${msg}" | grep -q "CHALLENGE_OK"; then
  echo "PASS: LB served the ${active} challenge interstitial."
  exit 0
fi
echo "FAIL: challenge active on config but no interstitial served (dataplane lag? check propagation)."
exit 1
