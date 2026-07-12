# webapp-api-protection developer targets.

.PHONY: mud-matrix mud-verify test

# Run the MUD plan-level test suite (no tenant contact).
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
