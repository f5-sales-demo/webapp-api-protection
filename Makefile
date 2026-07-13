# webapp-api-protection developer targets.

.PHONY: mud-matrix mud-verify waf-matrix test

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
# See scripts/waf-pairs.py (generator) and scripts/waf-matrix.sh (harness).
waf-matrix:
	bash scripts/waf-matrix.sh
