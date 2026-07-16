#!/usr/bin/env bash
# service_policy behavioral verification (SPol-5).
#
# Closed-loop check that a service_policy DENY rule attached to the F5 XC LB actually
# blocks matching traffic (not just that the object applied). It:
#   1. confirms the LB has an active service policy attached (fail fast otherwise);
#   2. drives traffic itself — requests to the deny path (expect 403) plus an allowed
#      control request (expect non-403) — so the run is self-contained;
#   3. queries the F5 XC security-events data plane
#      (POST /api/data/namespaces/<ns>/app_security/events) and asserts a BLOCK/DENY
#      event on the deny path.
#
# Pairs with the traffic-generator suite suites/service-policy-verify (which can drive the
# same deny path continuously). Attach the deny policy first with the overlay
# terraform/service-policy-verify.tfvars.json (rule_list: DENY on DENY_PATH THEN a catch-all
# ALLOW rule — a rule_list has an implicit default DENY, so without the trailing allow the
# policy blocks everything; live-verified), attached active. Restore canonical afterwards
# with a two-phase teardown (detach: choice=omit + empty service_policy_active; then destroy)
# — the LB references the policy by name, not a resource dependency, so a one-shot destroy
# hits a 409 CONFLICT while it is still attached.
#
# Env: XCSH_API_URL, XCSH_API_TOKEN. Usage: service-policy-verify.sh [WINDOW_MINUTES]
set -uo pipefail

: "${XCSH_API_URL:?XCSH_API_URL must be set}"
: "${XCSH_API_TOKEN:?XCSH_API_TOKEN must be set}"
NS="${NS:-webapp-api-protection}"
LB="${LB:-webapp-api-protection}"
WINDOW_MIN="${1:-30}"
DENY_PATH="${DENY_PATH:-/spol-denied}"
TARGET="${TARGET:-www.f5-sales-demo.com}"
TARGET_PROTOCOL="${TARGET_PROTOCOL:-http}"
base="${XCSH_API_URL%/}"
auth=(-H "Authorization: APIToken ${XCSH_API_TOKEN}")

ago_utc() { date -u -v-"${1}"M +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "${1} minutes ago" +%Y-%m-%dT%H:%M:%SZ; }

echo "== 1) LB has an active service policy attached? =="
cfg=$(curl -s "${auth[@]}" "${base}/api/config/namespaces/${NS}/http_loadbalancers/${LB}?response_format=GET_RSP_FORMAT_DEFAULT")
printf '%s' "$cfg" | python3 -c '
import sys, json
s = (json.load(sys.stdin) or {}).get("spec", {})
active = s.get("active_service_policies")
n = len((active or {}).get("policies", [])) if active else 0
print(f"  active_service_policies: {active is not None} (policies={n})")
sys.exit(0 if active is not None and n > 0 else 1)
' || {
  echo "  => no active service policy on the LB; apply terraform/service-policy-verify.tfvars.json first."
  exit 2
}

echo "== 2) Drive traffic (deny path expect 403, control expect non-403) =="
url="${TARGET_PROTOCOL}://${TARGET}"
CURL=(curl -s --max-time 10 -o /dev/null -w '%{http_code}' -A "spol5-verify")
blocked=0
for i in 1 2 3; do
  code=$("${CURL[@]}" "${url}${DENY_PATH}" || echo "000")
  echo "  [$i] GET ${DENY_PATH} -> ${code}"
  [ "$code" = "403" ] && blocked=$((blocked + 1))
done
ctrl=$("${CURL[@]}" "${url}/" || echo "000")
echo "  control GET / -> ${ctrl}"
if [ "$blocked" -eq 0 ]; then
  echo "  => FAIL: deny path never returned 403 (service_policy DENY not enforced?)"
  exit 1
fi
if [ "$ctrl" = "403" ]; then
  echo "  => FAIL: control path also blocked (policy too broad)"
  exit 1
fi
echo "  live block on ${DENY_PATH}: ${blocked}/3; control not blocked (${ctrl})"

echo "== 3) Security events (last ${WINDOW_MIN}m) confirm the BLOCK =="
end=$(date -u +%Y-%m-%dT%H:%M:%SZ)
start=$(ago_utc "${WINDOW_MIN}")
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
print(f"  service_policy BLOCK on {deny_path}: {len(deny_hits)}")
if not deny_hits:
    print(f"  => FAIL: no BLOCK event observed on {deny_path} (service_policy deny not in the log?)")
    sys.exit(1)
print("  => PASS: service_policy deny enforced (BLOCK observed in the security-events plane)")
'
rc=$?
echo "== done (exit ${rc}) =="
exit "${rc}"
