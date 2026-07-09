# The xcsh provider authenticates from the environment — no secrets in code.
# Export one of the following credential sets before running Terraform:
#
#   Token auth:  XCSH_API_URL + XCSH_API_TOKEN
#   P12 auth:    XCSH_API_URL + XCSH_P12_FILE + XCSH_P12_PASSWORD
#   PEM auth:    XCSH_API_URL + XCSH_CERT + XCSH_KEY
#
# For this repo XCSH_API_URL points at the production tenant
# (https://f5-sales-demo.console.ves.volterra.io), which is internet-reachable.
# See terraform/README.md for local dev setup (dev_overrides + env).
provider "xcsh" {}

# Azure — for the origin-server and traffic-generator VMs this plan deploys.
# Auth comes from the environment (az CLI login locally; ARM_* / a service
# principal in CI). Only the subscription is set here, from a variable so nothing
# environment-specific is hardcoded. The azuread provider is read-only (it just
# resolves the deployer identity for resource naming/tags in the modules).
provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

provider "azuread" {}
