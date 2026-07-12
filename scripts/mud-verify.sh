#!/usr/bin/env bash
# MUD behavioral verification.
#
# 1) Confirms Malicious User Detection is ACTIVE on the load balancer
#    (enable_malicious_user_detection + a resolvable malicious_user_mitigation
#    reference) — a config check, always available.
# 2) Polls the F5 XC analytics API for FLAGGED malicious users (the suspicious-users
#    dataset MUD produces) under the enhanced traffic generator, until at least one
#    user is flagged or the budget elapses.
#
# Exit codes: 0 = MUD active AND ≥1 user flagged; 1 = MUD not active;
# 2 = MUD active but the tenant analytics backend (Elasticsearch) is unavailable, so
# flagged users cannot be confirmed here; 3 = MUD active but no flags within budget.
set -uo pipefail

: "${XCSH_API_URL:?XCSH_API_URL required}"
: "${XCSH_API_TOKEN:?XCSH_API_TOKEN required}"
base="${XCSH_API_URL%/}"
NS="${1:-webapp-api-protection}"
LB="${2:-webapp-api-protection}"
APP="ves-io-${NS}-${LB}"
auth=(-H "Authorization: APIToken ${XCSH_API_TOKEN}")
budget="${MUD_VERIFY_BUDGET:-1200}"
interval="${MUD_VERIFY_INTERVAL:-60}"

echo "== 1) MUD active on ${NS}/${LB} =="
lb=$(curl -s "${auth[@]}" "${base}/api/config/namespaces/${NS}/http_loadbalancers/${LB}")
read -r det mit < <(printf '%s' "$lb" | python3 -c '
import sys, json
s = (json.load(sys.stdin) or {}).get("spec", {})
det = "yes" if "enable_malicious_user_detection" in s else "no"
ec = s.get("enable_challenge") or s.get("policy_based_challenge") or {}
ref = (ec or {}).get("malicious_user_mitigation") or {}
print(det, ref.get("name", "none"))
')
echo "  enable_malicious_user_detection: ${det}"
echo "  active mitigation policy:        ${mit}"
if [ "${det}" != "yes" ] || [ "${mit}" = "none" ]; then
  echo "  => MUD NOT fully active"
  exit 1
fi
echo "  => MUD ACTIVE"

echo "== 2) Flagged malicious users (poll up to ${budget}s) =="
waited=0
while :; do
  resp=$(curl -s -w $'\n%{http_code}' "${auth[@]}" \
    "${base}/api/ml/data/namespaces/${NS}/app_settings/${APP}/suspicious_users?topn=20")
  code=$(printf '%s' "$resp" | tail -1)
  body=$(printf '%s' "$resp" | sed '$d')
  if [ "$code" = "200" ]; then
    n=$(printf '%s' "$body" | python3 -c '
import sys, json
d = json.load(sys.stdin) or {}
u = d.get("suspicious_users") or d.get("users") or d.get("data") or []
print(len(u) if isinstance(u, list) else 0)
' 2>/dev/null || echo 0)
    if [ "${n:-0}" -gt 0 ]; then
      echo "  FLAGGED users: ${n}"
      printf '%s' "$body" | python3 -m json.tool 2>/dev/null | head -40
      echo "  => DETECTION CONFIRMED"
      exit 0
    fi
    echo "  [${waited}s] MUD active, 0 users flagged yet"
  elif printf '%s' "$body" | grep -q "no Elasticsearch node available"; then
    echo "  ANALYTICS BACKEND UNAVAILABLE: the tenant Elasticsearch is down, so flagged"
    echo "  users cannot be read on this tenant. MUD is configured + active (step 1);"
    echo "  detection is blocked by tenant infra, not by config or traffic."
    exit 2
  else
    echo "  [${waited}s] unexpected HTTP ${code}: $(printf '%s' "$body" | head -c 160)"
  fi
  waited=$((waited + interval))
  if [ "${waited}" -ge "${budget}" ]; then
    echo "  no users flagged within ${budget}s (MUD active; increase traffic intensity/duration)"
    exit 3
  fi
  sleep "${interval}"
done
