#!/usr/bin/env bash
# Seal a secret with F5 XC Blindfold ONCE (offline) and print the resulting
# "string:///..." location to pin into config.
#
# provider::xcsh::blindfold uses a random data key, so it returns a DIFFERENT
# ciphertext every call. Calling it inline in Terraform config would therefore
# re-seal on every plan and drift (non-idempotent). The correct, F5-documented
# pattern is to seal ONCE offline and pin the resulting location — that is what
# this helper produces. Feed the output into api_crawler_password.location (or any
# blindfold_secret_info.location).
#
# Usage: blindfold-seal.sh <plaintext> [policy_name] [policy_namespace]
#   Requires XCSH_API_URL + XCSH_API_TOKEN in the environment, and the terraform/
#   working dir to be initialized (the provider function is served by the provider).
set -euo pipefail

PLAINTEXT="${1:?usage: blindfold-seal.sh <plaintext> [policy_name] [policy_namespace]}"
POLICY="${2:-ves-io-allow-volterra}"
NAMESPACE="${3:-shared}"

cd "$(dirname "$0")/../terraform"

# Escape backslashes and double quotes for safe embedding in the HCL string literal.
esc=${PLAINTEXT//\\/\\\\}
esc=${esc//\"/\\\"}

expr="provider::xcsh::blindfold(base64encode(\"${esc}\"), \"${POLICY}\", \"${NAMESPACE}\")"
printf '%s\n' "$expr" | terraform console 2>/dev/null | tr -d '"' | grep '^string:///' | tail -1
