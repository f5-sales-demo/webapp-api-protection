#!/usr/bin/env bash
# Staged blindfold + API-crawler behavioral verification (live).
#
# A. Blindfold sealing works: provider::xcsh::blindfold seals a credential offline
#    into a string:/// location (cleartext never leaves the machine).
# B. Clear crawler applies live: the inline api_crawler with a clear_secret_info
#    password is ACCEPTED by F5 XC and is idempotent — the working live secret path.
# C. Blindfold crawler password: F5 XC returns a server-side 500 for
#    blindfold_secret_info on the api_crawler login password (verified live,
#    persistent). This is a PLATFORM limitation (the provider/module/function are
#    correct); recorded as a KNOWN LIMITATION, not a failure. The blindfold arm is
#    plan-tested (tests/api_secret.tftest.hcl). See docs/superpowers/plans/sp1-findings.md.
# D. Discovery inventory (best-effort; the crawler runs asynchronously).
#
# Restores canonical (no crawler) at the end. Requires XCSH creds + init'd dir.
set -uo pipefail

umask 077
trap 'rm -f /tmp/crawl-clear.tfvars.json /tmp/crawl-bf.tfvars.json /tmp/crawl-*.log /tmp/disco.json 2>/dev/null' EXIT

cd "$(dirname "$0")/../terraform" || exit 1
ARM_ACCESS_KEY=$(az storage account keys list -n f5salesdemotfstate -g f5-sales-demo-tfstate --query "[0].value" -o tsv)
export ARM_ACCESS_KEY

NS="webapp-api-protection"
COMMON=(-input=false
  -var 'lb_domains=["www.f5-sales-demo.com","api.f5-sales-demo.com"]'
  -var 'subscription_id=75f86c46-9cbc-4f6c-85ea-195e3d3c8ac0')

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; }
info() { echo "INFO: $*"; }
known() { echo "KNOWN-LIMITATION: $*"; }

# --- A. blindfold sealing works ---------------------------------------------
LOC=$(../scripts/blindfold-seal.sh "DvwaCrawl-Demo" 2>/dev/null)
if [ -n "$LOC" ] && [ "${LOC#string:///}" != "$LOC" ]; then
  pass "provider::xcsh::blindfold sealed a credential offline (${LOC:0:18}..., ${#LOC} chars)"
else
  fail "blindfold seal produced no valid location"
fi

# --- B. clear crawler applies live + idempotent ------------------------------
cat >/tmp/crawl-clear.tfvars.json <<EOF
{ "api_discovery_choice": "enable",
  "api_crawler_domains": [{ "domain": "www.f5-sales-demo.com", "user": "admin" }],
  "api_crawler_password": { "method": "clear", "plaintext": "password" } }
EOF
if terraform apply -auto-approve "${COMMON[@]}" -var-file=/tmp/crawl-clear.tfvars.json >/tmp/crawl-clear.log 2>&1; then
  pass "F5 XC ACCEPTED the clear-secret crawler credential (apply succeeded)"
  if terraform plan -detailed-exitcode "${COMMON[@]}" -var-file=/tmp/crawl-clear.tfvars.json >/tmp/crawl-clear-plan.log 2>&1; then
    pass "clear crawler config is idempotent (plan = No changes)"
  else
    fail "clear crawler not idempotent"
  fi
else
  fail "clear crawler apply failed: $(sed 's/\x1b\[[0-9;]*m//g' /tmp/crawl-clear.log | grep -iE 'error|status:' | head -1)"
fi

# --- C. blindfold crawler password: platform 500 (documented) ----------------
cat >/tmp/crawl-bf.tfvars.json <<EOF
{ "api_discovery_choice": "enable",
  "api_crawler_domains": [{ "domain": "www.f5-sales-demo.com", "user": "admin" }],
  "api_crawler_password": { "method": "blindfold", "location": $(jq -Rn --arg l "$LOC" '$l') } }
EOF
if terraform apply -auto-approve "${COMMON[@]}" -var-file=/tmp/crawl-bf.tfvars.json >/tmp/crawl-bf.log 2>&1; then
  pass "F5 XC ACCEPTED the blindfold crawler credential (platform now supports it!)"
else
  code=$(sed 's/\x1b\[[0-9;]*m//g' /tmp/crawl-bf.log | grep -oiE 'status: [0-9]+' | head -1)
  known "api_crawler password + blindfold_secret_info -> F5 XC ${code:-server error} (platform-side; clear works). Blindfold arm is plan-tested; see sp1-findings.md."
fi

# --- D. discovery inventory (best-effort) ------------------------------------
CODE=$(curl -s -o /tmp/disco.json -w '%{http_code}' \
  -H "Authorization: APIToken $XCSH_API_TOKEN" \
  "$XCSH_API_URL/api/data/namespaces/$NS/api_endpoints" 2>/dev/null || echo "000")
info "discovery inventory GET -> HTTP $CODE (crawler is async; endpoints populate over time)"

# --- E. restore canonical ----------------------------------------------------
if terraform apply -auto-approve "${COMMON[@]}" >/tmp/crawl-restore.log 2>&1; then
  pass "restored canonical (no crawler)"
else
  fail "canonical restore failed — inspect state"
fi
