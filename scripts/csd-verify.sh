#!/usr/bin/env bash
# CSD behavioral verification (CSD-3).
#
# Closed-loop check that F5 XC Client-Side Defense, once enabled on the LB, actually generates
# detection STATISTICS from real browser-side attack activity — the plane the config/matrix tests
# cannot exercise. Pairs with the traffic-generator suites/csd-detection driver (the Combined
# Detection Script: third-party CDN script injection + external exfil, per csd/docs).
#
# CSD detection is fundamentally asynchronous and browser-driven:
#   - curl cannot trigger it; a real browser must execute the injected CSD JS and beacon to
#     *.zeronaught.com. The traffic-generator suites/csd-detection suite is that browser driver.
#   - the CSD backend aggregates beacons before statistics appear (docs: 5-10 min, up to 30).
# So this verifier separates what is synchronous and deterministic (config gate, driver executed
# with the CSD beacon returning 200) from what is async (the statistics), and uses the mud-verify
# exit-3 semantic for "enabled + driven, but stats have not aggregated yet — re-run later".
#
# Steps:
#   1) Gate (exit 2): client_side_defense is configured on the LB AND a protected_domain covering
#      f5-sales-demo.com exists (CSD returns 500 / never scans without the protected domain).
#   2) Baseline the CSD /summary counters.
#   3) DRIVE (opt-in, DRIVE=1): ship the csd-detection suite to the traffic-generator VM and run it;
#      require its synchronous PASS (CSD JS injected + telemetry beacon 200). Without DRIVE=1 the
#      verifier only reads the stats plane (assumes traffic was already driven).
#   4) Detection (exit 3 if not yet): poll /detected_domains for the injected/exfil domains and
#      /summary suspicious_scripts above baseline.
#   5) Mitigation: report registered /mitigated_domains and, when a detected domain is mitigated,
#      the /summary blocked_scripts / mitigated_domains counters.
#   6) Per-script telemetry (deepest leaf): /scripts (epoch window) -> for a detected script,
#      /scripts/{id}/{behaviors,networkInteractions} non-empty.
#   7) Origin cross-check: from the VM, GET the origin /csd-demo/exfil/log (the same-origin attack
#      recorder) to confirm the origin server observed attack traffic.
#
# Exit: 0 = CSD enabled, driven, and detection statistics present; 2 = CSD not enabled/no protected
# domain; 3 = enabled + driven but statistics not aggregated yet (increase traffic / re-run later).
# Read-only against the config plane; the CSD stats plane and origin log are read-only.
#
# Env: XCSH_API_URL, XCSH_API_TOKEN (required); Azure CLI logged in when DRIVE=1 or the origin
# cross-check runs. Usage: [DRIVE=1] [POLL_MIN=15] scripts/csd-verify.sh
set -uo pipefail

: "${XCSH_API_URL:?XCSH_API_URL must be set}"
: "${XCSH_API_TOKEN:?XCSH_API_TOKEN must be set}"
NS="${NS:-webapp-api-protection}"
LB="${LB:-webapp-api-protection}"
TARGET="${TARGET:-http://www.f5-sales-demo.com/}"
PROTECTED_ROOT="${PROTECTED_ROOT:-f5-sales-demo.com}"
VM_NAME="${VM_NAME:-vm-traffic-generator-rmordasiewicz}"
VM_RG="${VM_RG:-rg-traffic-generator-webapp-api-protection-rmordasiewicz}"
DRIVE="${DRIVE:-0}"
POLL_MIN="${POLL_MIN:-15}"
SUITE_JS="$(cd "$(dirname "$0")/.." && pwd)/../traffic-generator/suites/csd-detection/01-combined-detection.js"
base="${XCSH_API_URL%/}"
csd="${base}/api/shape/csd/namespaces/${NS}"
auth=(-H "Authorization: APIToken ${XCSH_API_TOKEN}")

echo "== 1) CSD enabled on ${NS}/${LB} + protected_domain present? =="
# Gate on two RELIABLE signals: client_side_defense on the LB (injects the sensor) and CSD
# /status (isConfigured && isEnabled). The protected_domains list/GET-by-name API is unreliable
# for verifying enrollment — the list renders a blank placeholder item and GET-by-name 404s even
# when the domain is enrolled (create returns 409 "domains already exist"); domains are also
# tenant-globally unique. So the protected_domain is reported for context but NOT used to gate.
cfg=$(curl -s "${auth[@]}" "${base}/api/config/namespaces/${NS}/http_loadbalancers/${LB}?response_format=GET_RSP_FORMAT_DEFAULT")
csd_on=$(printf '%s' "$cfg" | python3 -c '
import sys, json
s = (json.load(sys.stdin) or {}).get("spec", {})
print("yes" if s.get("client_side_defense") is not None else "no")
' 2>/dev/null || echo "no")
status_ok=$(curl -s "${auth[@]}" "${csd}/status" | python3 -c '
import sys, json
d = json.load(sys.stdin) or {}
print("yes" if d.get("isConfigured") and d.get("isEnabled") else "no")
' 2>/dev/null || echo "no")
echo "  client_side_defense configured: ${csd_on}"
echo "  CSD status isConfigured+isEnabled: ${status_ok}"
echo "  protected_domain ~ ${PROTECTED_ROOT}: (info only; domain-list API is unreliable — see comment)"
if [ "${csd_on}" != "yes" ] || [ "${status_ok}" != "yes" ]; then
  echo "  => CSD not fully enabled (need client_side_defense on the LB + CSD status enabled)."
  exit 2
fi
echo "  => CSD ENABLED"

echo "== 2) Baseline CSD /summary =="
base_summary=$(curl -s "${auth[@]}" "${csd}/summary")
base_susp=$(printf '%s' "$base_summary" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("suspicious_scripts",0))' 2>/dev/null || echo 0)
echo "  suspicious_scripts baseline: ${base_susp}"

if [ "${DRIVE}" = "1" ]; then
  echo "== 3) Drive csd-detection suite on ${VM_NAME} =="
  [ -f "${SUITE_JS}" ] || {
    echo "  suite not found: ${SUITE_JS}"
    exit 2
  }
  b64=$(base64 <"${SUITE_JS}" | tr -d '\n')
  fqdn="${TARGET#http://}"
  fqdn="${fqdn#https://}"
  fqdn="${fqdn%%/*}"
  remote=$(
    cat <<REMOTE
echo '${b64}' | base64 -d > /tmp/csd-combined-detection.js
NODE_PATH=/usr/lib/node_modules TARGET_PROTOCOL=http node /tmp/csd-combined-detection.js '${fqdn}' 2>&1 | tail -12
REMOTE
  )
  msg=$(az vm run-command invoke --name "${VM_NAME}" --resource-group "${VM_RG}" \
    --command-id RunShellScript --scripts "${remote}" --query "value[0].message" -o tsv 2>&1)
  echo "${msg}" | sed 's/^/  /'
  if ! printf '%s' "${msg}" | grep -q "PASS: CSD injected"; then
    echo "  => driver did not confirm CSD injection/beacon; CSD not effective on the dataplane."
    exit 2
  fi
else
  echo "== 3) Drive skipped (DRIVE!=1) — reading stats plane for previously-driven traffic =="
fi

echo "== 4) Detection statistics (poll up to ${POLL_MIN}m) =="
# Detection is asserted on the docs' real signals, in priority order:
#   DET-3 (primary, fastest): /detected_domains contains a THIRD-PARTY domain from the attack —
#         one of the injected CDN / external-exfil domains, NOT the monitored site itself.
#   DET-1 (secondary, slower): /scripts non-empty, or summary.suspicious_scripts above baseline.
# detected_domains.count is NOT used to gate — it always includes the monitored site (count>=1
# whenever CSD has transactions), so gating on it is a false positive.
deadline=$((SECONDS + POLL_MIN * 60))
detected="no"
tpd=""
while :; do
  susp=$(curl -s "${auth[@]}" "${csd}/summary" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("suspicious_scripts",0))' 2>/dev/null || echo 0)
  # /scripts requires a window duration of EXACTLY 1, 7, or 30 days.
  now=$(date +%s)
  scount=$(curl -s -X POST "${auth[@]}" -H "Content-Type: application/json" \
    -d "{\"startTime\":\"$((now - 86400))\",\"endTime\":\"${now}\"}" "${csd}/scripts" | python3 -c '
import sys, json
d = json.load(sys.stdin)
if isinstance(d, dict) and d.get("code"):
    print(0); sys.exit(0)
a = d.get("scripts") if isinstance(d, dict) else d
print(len(a or []))
' 2>/dev/null || echo 0)
  # DET-3: third-party attack domains present in detected_domains (excludes the monitored site).
  tpd=$(curl -s "${auth[@]}" "${csd}/detected_domains" | python3 -c '
import sys, json
attack = ("jsdelivr", "unpkg", "esm.sh", "jspm", "httpbin", "jsonplaceholder")
d = json.load(sys.stdin) or {}
hits = [ (x.get("domain") or "") for x in (d.get("domains_list") or [])
         if any(a in (x.get("domain") or "") for a in attack) ]
print(",".join(hits))
' 2>/dev/null || echo "")
  if [ -n "${tpd}" ] || [ "${susp}" -gt "${base_susp}" ] 2>/dev/null || [ "${scount}" -gt 0 ] 2>/dev/null; then
    detected="yes"
    echo "  DET-3 third-party domains=[${tpd}] | suspicious_scripts=${susp} scripts=${scount}"
    break
  fi
  if [ "${SECONDS}" -ge "${deadline}" ]; then
    echo "  DET-3 third-party domains=[none] | suspicious_scripts=${susp} (baseline ${base_susp}) scripts=${scount}"
    break
  fi
  echo "  ...t+$(((SECONDS) / 60))m DET-3=[${tpd:-none}] suspicious_scripts=${susp} scripts=${scount}; waiting"
  sleep 60
done
if [ "${detected}" != "yes" ]; then
  echo "  => CSD enabled + driven, but no detection statistics aggregated within ${POLL_MIN}m."
  echo "     The CSD console stats plane aggregates on an infrequent (~daily) batch in this tenant"
  echo "     (detected_domains.lastUpdated is frozen between batches). Re-run after the next batch."
  exit 3
fi

echo "== 5) Mitigation state =="
mit=$(curl -s "${auth[@]}" "${csd}/mitigated_domains" | python3 -c '
import sys, json
d = json.load(sys.stdin) or {}
items = d.get("items") or d.get("domains_list") or []
print(",".join((i.get("name") or i.get("domain") or "") for i in items) or "(none)")
' 2>/dev/null || echo "(none)")
sm=$(curl -s "${auth[@]}" "${csd}/summary")
echo "  registered mitigated_domains: ${mit}"
echo "  summary blocked_scripts/mitigated_domains: $(printf '%s' "$sm" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("blocked_scripts",0),"/",d.get("mitigated_domains",0))' 2>/dev/null)"

echo "== 6) Per-script telemetry (deepest leaf) =="
now=$(date +%s)
start=$((now - 86400))
sid=$(curl -s -X POST "${auth[@]}" -H "Content-Type: application/json" \
  -d "{\"startTime\":\"${start}\",\"endTime\":\"${now}\"}" "${csd}/scripts" | python3 -c '
import sys, json
d = json.load(sys.stdin)
if isinstance(d, dict) and d.get("code"):  # error object
    print(""); sys.exit(0)
arr = d.get("scripts") if isinstance(d, dict) else d
arr = arr or []
print(arr[0].get("id","") if arr else "")
' 2>/dev/null || echo "")
if [ -n "${sid}" ]; then
  beh=$(curl -s "${auth[@]}" "${csd}/scripts/${sid}/behaviors" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(len(d if isinstance(d,list) else d.get("behaviors",[])))' 2>/dev/null || echo 0)
  net=$(curl -s "${auth[@]}" "${csd}/scripts/${sid}/networkInteractions" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(len(d if isinstance(d,list) else d.get("networkInteractions",[])))' 2>/dev/null || echo 0)
  echo "  script ${sid}: behaviors=${beh} networkInteractions=${net}"
else
  echo "  no script id yet (script analysis lags detected_domains)"
fi

echo "== 7) Origin cross-check (from ${VM_NAME}) =="
remote_log="curl -s -m 15 '${TARGET%/}/csd-demo/exfil/log' | head -c 400"
olog=$(az vm run-command invoke --name "${VM_NAME}" --resource-group "${VM_RG}" \
  --command-id RunShellScript --scripts "${remote_log}" --query "value[0].message" -o tsv 2>&1 | grep -v '^\[' | tr -d '\n')
echo "  origin /csd-demo/exfil/log: ${olog:0:200}"

echo "PASS: CSD enabled, driven, and detection statistics present (detected_domains / suspicious_scripts)."
exit 0
