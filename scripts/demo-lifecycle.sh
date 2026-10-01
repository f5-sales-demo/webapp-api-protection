#!/usr/bin/env bash
# Unattended lifecycle; no shell-sourced config or credential minting.
set -euo pipefail
SCRIPT_DIR="$(dirname -- "${BASH_SOURCE[0]}")"
exec python3 "$SCRIPT_DIR/demo_lifecycle.py" "$@"
