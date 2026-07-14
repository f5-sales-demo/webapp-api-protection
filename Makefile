# webapp-api-protection developer targets.

.PHONY: mud-matrix mud-verify waf-matrix api-discovery-matrix api-definition-matrix api-crawl-verify test

# Run the plan-level test suite (no tenant contact).
test:
	cd terraform && terraform test

# Cycle the live LB through every MUD option combination and verify apply /
# idempotency / round-trip import. See scripts/mud-matrix.sh.
mud-matrix:
	bash scripts/mud-matrix.sh

# Verify MUD detection + active mitigation under malicious-user traffic. See
# scripts/mud-verify.sh.
mud-verify:
	bash scripts/mud-verify.sh

# Cycle the live app_firewall through the all-pairs + enum + min/max + maximal
# WAF variant set and verify apply / idempotency / round-trip import. Runs in
# batches: `make waf-matrix` (all) or `bash scripts/waf-matrix.sh START END`.
# See scripts/waf_pairs.py (generator) and scripts/waf-matrix.sh (harness).
waf-matrix:
	bash scripts/waf-matrix.sh

# Cycle the live LB through the API discovery/crawler all-pairs variant set and
# verify apply / idempotency / round-trip import (re-applying write-only crawler
# secrets on import). Runs in batches: `make api-discovery-matrix` (all) or
# `bash scripts/api-discovery-matrix.sh START END`. See scripts/api_discovery_pairs.py
# (generator) and scripts/api-discovery-matrix.sh (harness).
api-discovery-matrix:
	bash scripts/api-discovery-matrix.sh

# Cycle the live LB through the API Definition & spec-enforcement (SP2) all-pairs
# variant set and verify apply / idempotency / round-trip import (re-applying the
# write-only code_base_integration access_token on import; blindfold token = SKIP).
# Requires GH_TOKEN in the environment. Runs in batches: `make api-definition-matrix`
# (all) or `bash scripts/api-definition-matrix.sh START END`. See
# scripts/api_definition_pairs.py (generator) and scripts/api-definition-matrix.sh.
api-definition-matrix:
	bash scripts/api-definition-matrix.sh

# Staged blindfold verification: seal round-trip (a pre-sealed crawler credential
# applies + is idempotent + import-clean) plus an authenticated-crawl attempt
# against a real origin app. See scripts/api-crawl-verify.sh.
api-crawl-verify:
	bash scripts/api-crawl-verify.sh
