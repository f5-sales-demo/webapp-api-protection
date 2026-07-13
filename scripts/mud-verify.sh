#!/usr/bin/env bash
# MUD behavioral verification.
#
# 1) Confirms Malicious User Detection is ACTIVE on the load balancer
#    (enable_malicious_user_detection + a resolvable malicious_user_mitigation
#    reference) — a config check, always available.
# 2) Queries the F5 XC security-log plane for the suspicious-user detection records
#    MUD produces, and reports flagged identities (threat_level != None) plus the
#    mitigation actions applied (mum_temporarily_blocking / mum_captcha_challenge /
#    mum_js_challenge). This is the same dataset the console's "Malicious Users" view
#    uses — POST /api/data/namespaces/{ns}/app_security/suspicious_user_logs — NOT the
#    ML dataset /api/ml/data/.../suspicious_users (which depends on a separate
#    Elasticsearch cluster and can be independently unavailable).
#
# Exit codes: 0 = MUD active AND >=1 detection record in the window; 1 = MUD not active;
# 3 = MUD active but no detection records within the window (increase traffic).
set -uo pipefail

: "${XCSH_API_URL:?XCSH_API_URL required}"
: "${XCSH_API_TOKEN:?XCSH_API_TOKEN required}"
base="${XCSH_API_URL%/}"
NS="${1:-webapp-api-protection}"
LB="${2:-webapp-api-protection}"
auth=(-H "Authorization: APIToken ${XCSH_API_TOKEN}")
window_min="${MUD_VERIFY_WINDOW_MIN:-60}"

# Portable UTC timestamp N minutes ago (BSD date -v on macOS, GNU date -d on Linux).
ago_utc() {
  date -u -v-"$1"M +%Y-%m-%dT%H:%M:%SZ 2>/dev/null ||
    date -u -d "$1 minutes ago" +%Y-%m-%dT%H:%M:%SZ
}

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

echo "== 2) Suspicious-user detection records (last ${window_min}m) =="
end=$(date -u +%Y-%m-%dT%H:%M:%SZ)
start=$(ago_utc "${window_min}")
req=$(printf '{"namespace":"%s","start_time":"%s","end_time":"%s","limit":500}' "${NS}" "${start}" "${end}")
resp=$(curl -s -w $'\n%{http_code}' "${auth[@]}" -H "Content-Type: application/json" \
  -X POST -d "${req}" \
  "${base}/api/data/namespaces/${NS}/app_security/suspicious_user_logs")
code=$(printf '%s' "$resp" | tail -1)
body=$(printf '%s' "$resp" | sed '$d')
if [ "$code" != "200" ]; then
  echo "  unexpected HTTP ${code}: $(printf '%s' "$body" | head -c 200)"
  exit 3
fi

printf '%s' "$body" | python3 -c '
import sys, json
from collections import Counter, defaultdict
d = json.load(sys.stdin) or {}
logs = []
for x in d.get("logs", []):
    try:
        logs.append(json.loads(x))
    except Exception:
        pass
print(f"  detection records: {len(logs)}")
if not logs:
    sys.exit(3)
per = defaultdict(lambda: {"n": 0, "threat": set(), "mit": Counter(), "susp": 0.0})
for l in logs:
    uid = l.get("user") or l.get("src_ip") or "unknown"
    e = per[uid]
    e["n"] += 1
    e["threat"].add(l.get("threat_level"))
    try:
        e["susp"] = max(e["susp"], float(l.get("suspicion_score") or 0))
    except Exception:
        pass
    mi = l.get("mitigation_activity_info")
    if isinstance(mi, str):
        try:
            mi = json.loads(mi)
        except Exception:
            mi = {}
    for k, v in (mi or {}).items():
        e["mit"][k] += int(v or 0)
flagged = 0
for uid, e in sorted(per.items(), key=lambda kv: -kv[1]["n"]):
    threats = sorted(t for t in e["threat"] if t and t != "None") or ["None"]
    mit = {k: v for k, v in e["mit"].items() if v} or {}
    if threats != ["None"] or mit:
        flagged += 1
    n = e["n"]
    susp = round(e["susp"], 2)
    print("    %s: records=%d max_suspicion=%s threat=%s mitigation=%s"
          % (uid, n, susp, threats, mit))
print("  => DETECTION CONFIRMED (%d identities, %d with threat/mitigation)"
      % (len(per), flagged))
' || {
  rc=$?
  if [ "$rc" = "3" ]; then
    echo "  MUD active but no detection records in the last ${window_min}m"
    echo "  (drive the malicious-user traffic profile, then re-run)"
    exit 3
  fi
  exit "$rc"
}
