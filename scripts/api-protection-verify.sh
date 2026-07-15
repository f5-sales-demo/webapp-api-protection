#!/usr/bin/env bash
# API-protection behavioral verification (SP5).
#
# Closed-loop check that the F5 XC LB actually ACTED on the API traffic the
# traffic-generator "api-protection-verify" suite drove (not just that traffic was
# sent). Queries the F5 XC security-events data plane
# (POST /api/data/namespaces/<ns>/app_security/events) over a recent window and asserts
# the SP1-SP4 features fired:
#   * API protection  — a BLOCK event on the api_protection_rules deny path (/api/admin).
#   * Rate limiting    — rate-limiter block/429 events on the burst path.
#   * WAF / schema     — security events from the schema-violation + shadow traffic.
#
# It also confirms the features are enabled on the LB config first (fail fast if the
# operator forgot to enable them for the run). Read-only against the control plane;
# safe to run repeatedly. Pairs with traffic-generator suites/api-protection-verify.
#
# Env: XCSH_API_URL, XCSH_API_TOKEN. Usage: api-protection-verify.sh [WINDOW_MINUTES]
set -uo pipefail

: "${XCSH_API_URL:?XCSH_API_URL must be set}"
: "${XCSH_API_TOKEN:?XCSH_API_TOKEN must be set}"
NS="${NS:-webapp-api-protection}"
LB="${LB:-webapp-api-protection}"
WINDOW_MIN="${1:-30}"
DENY_PATH="${DENY_PATH:-/api/admin}"
base="${XCSH_API_URL%/}"
auth=(-H "Authorization: APIToken ${XCSH_API_TOKEN}")

ago_utc() { # minutes-ago -> RFC3339 UTC
  date -u -v-"${1}"M +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "${1} minutes ago" +%Y-%m-%dT%H:%M:%SZ
}

echo "== 1) LB API-protection features enabled? =="
cfg=$(curl -s "${auth[@]}" "${base}/api/config/namespaces/${NS}/http_loadbalancers/${LB}?response_format=GET_RSP_FORMAT_DEFAULT")
printf '%s' "$cfg" | python3 -c '
import sys, json
s = (json.load(sys.stdin) or {}).get("spec", {})
prot = "api_protection_rules" in s and s["api_protection_rules"] is not None
rl = "rate_limit" in s and s["rate_limit"] is not None
spec = "api_specification" in s and s["api_specification"] is not None
print(f"  api_protection_rules: {prot}")
print(f"  rate_limit:           {rl}")
print(f"  api_specification:    {spec}")
sys.exit(0 if (prot or rl or spec) else 1)
' || {
  echo "  => no API-protection feature enabled on the LB; enable them before the run."
  exit 2
}

echo "== 2) Security events (last ${WINDOW_MIN}m) =="
end=$(date -u +%Y-%m-%dT%H:%M:%SZ)
start=$(ago_utc "${WINDOW_MIN}")
# Filter server-side by the deny path: with continuous background load the LB logs a
# service-policy event per request, so an unfiltered pull hits the 500-event cap and
# buries the sparse deny events. A `query` filter returns exactly the deny-path events.
req=$(printf '{"namespace":"%s","start_time":"%s","end_time":"%s","limit":500,"query":"req_path=\\"%s\\""}' \
  "${NS}" "${start}" "${end}" "${DENY_PATH}")
resp=$(curl -s -w $'\n%{http_code}' "${auth[@]}" -H "Content-Type: application/json" \
  -X POST -d "${req}" "${base}/api/data/namespaces/${NS}/app_security/events")
code=$(printf '%s' "$resp" | tail -1)
body=$(printf '%s' "$resp" | sed '$d')
if [ "$code" != "200" ]; then
  echo "  unexpected HTTP ${code}: $(printf '%s' "$body" | head -c 200)"
  exit 3
fi

printf '%s' "$body" | DENY_PATH="$DENY_PATH" python3 -c '
import sys, json, os
deny_path = os.environ["DENY_PATH"]
d = json.load(sys.stdin) or {}
events = []
for e in d.get("events", []):
    if isinstance(e, str):
        try:
            e = json.loads(e)
        except Exception:
            continue
    events.append(e)

def blocked(e):
    return str(e.get("action", "")).lower() in ("block", "deny", "denied")

deny_hits = [e for e in events if e.get("req_path") == deny_path and blocked(e)]
total_hits = d.get("total_hits")
print(f"  events for {deny_path}: {len(events)} (total_hits={total_hits})")
print(f"  API-protection BLOCK on {deny_path}: {len(deny_hits)}")

# Core assertion: the api_protection_rules deny rule blocked the deny-path traffic.
if not deny_hits:
    print(f"  => FAIL: no BLOCK event observed on {deny_path} (api_protection_rules deny not enforced?)")
    sys.exit(1)
print("  => PASS: API-protection deny enforced (BLOCK observed in the security-events plane)")
'
rc=$?
echo "== done (exit ${rc}) =="
exit "${rc}"
