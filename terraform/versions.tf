terraform {
  # >= 1.8 for provider-defined functions (provider::xcsh::blindfold, used by
  # scripts/blindfold-seal.sh to seal API-crawler / SecretType credentials).
  required_version = ">= 1.8"

  required_providers {
    xcsh = {
      source  = "f5-sales-demo/xcsh"
      version = "= 15.5.2"
    }
    # Azure providers: this plan also deploys its OWN Azure origin server and
    # traffic generator (modules/origin-server, modules/traffic-generator), which
    # the load balancer's origin pool points at. Registry versions are pinned
    # exactly for reproducible unattended lifecycle runs.
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "= 5.7.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "= 3.10.0"
    }
  }
}
