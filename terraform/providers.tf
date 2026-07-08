# The xcsh provider authenticates from the environment — no secrets in code.
# Export one of the following credential sets before running Terraform:
#
#   Token auth:  XCSH_API_URL + XCSH_API_TOKEN
#   P12 auth:    XCSH_API_URL + XCSH_P12_FILE + XCSH_P12_PASSWORD
#   PEM auth:    XCSH_API_URL + XCSH_CERT + XCSH_KEY
#
# For this repo XCSH_API_URL points at the staging tenant
# (https://nferreira.staging.volterra.us), which is VPN-accessible only.
# See terraform/README.md for local dev setup (dev_overrides + env).
provider "xcsh" {}
