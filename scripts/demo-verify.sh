#!/usr/bin/env bash
# Bounded fail-closed showcase verification; arguments are never evaluated.
set -euo pipefail
SCRIPT_DIR="$(dirname -- "${BASH_SOURCE[0]}")"
exec python3 "${SCRIPT_DIR}/demo_verify.py" "$@"
