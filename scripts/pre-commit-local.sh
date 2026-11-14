#!/usr/bin/env bash
# Credential-free application contracts; never access cloud storage or run live lifecycle operations.
set -euo pipefail
SCRIPT_DIR="$(dirname -- "${BASH_SOURCE[0]}")"
REPO_ROOT="$(realpath -- "$SCRIPT_DIR/..")"
export PYTHONPATH="$REPO_ROOT/scripts:$REPO_ROOT/tests:$REPO_ROOT${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONDONTWRITEBYTECODE=1
if ! python3 -c 'from importlib.metadata import PackageNotFoundError, version
try:
    valid = (version("python-hcl2") == "7.3.1"
             and version("PyYAML") == "6.0.2"
             and version("pytest") == "8.4.2")
except PackageNotFoundError:
    valid = False
raise SystemExit(not valid)'; then
  if ! command -v uv >/dev/null; then
    printf '%s\n' 'Required test dependencies need uv; see the Static showcase contracts command in .github/workflows/terraform.yml.' >&2
    exit 1
  fi
  exec uv run --no-project --with python-hcl2==7.3.1 --with PyYAML==6.0.2 --with pytest==8.4.2 -- bash "$SCRIPT_DIR/pre-commit-local.sh" "$@"
fi
python3 -m pytest -q "$REPO_ROOT/tests"
bash -n "$SCRIPT_DIR/demo-lifecycle.sh" "$SCRIPT_DIR/demo-verify.sh" \
  "$SCRIPT_DIR/swagger-upload.sh" "$SCRIPT_DIR/pre-commit-local.sh"
