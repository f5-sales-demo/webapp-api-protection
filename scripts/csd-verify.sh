#!/usr/bin/env bash
# Read-only CSD verifier. Traffic generation is a separate prerequisite: run
# eight headed Chrome sessions with traffic-generator's population driver first.
#
# Required: XCSH_API_URL, XCSH_API_TOKEN, EXPECTED_DOMAIN, SINCE_EPOCH
# Optional: VERIFY_PHASE=detection|mitigation (default detection), POLL_MIN (default 15)
# Exit: 0 verified; 2 configuration/authentication/dataplane failure;
#       3 healthy but aggregation pending.
set -uo pipefail

exec python3 "$(cd "$(dirname "$0")" && pwd)/csd_verify.py" "$@"
