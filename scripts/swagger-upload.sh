#!/usr/bin/env bash
# Print only an exact, content-verified object-store version path on stdout.
# Usage: swagger-upload.sh <name> <openapi-file> [namespace]
# Requires XCSH_API_URL and XCSH_API_TOKEN; optional SWAGGER_RECEIPT_PATH.
# YAML is rejected explicitly; supply JSON OpenAPI 3.0/3.1 or Swagger 2.0.
set -euo pipefail
SCRIPT_DIR="$(dirname -- "${BASH_SOURCE[0]}")"
exec python3 "$SCRIPT_DIR/swagger_upload.py" "$@"
