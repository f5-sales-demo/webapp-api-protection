terraform {
  # >= 1.8 for provider-defined functions (provider::xcsh::blindfold, used by
  # scripts/blindfold-seal.sh to seal API-crawler / SecretType credentials).
  required_version = ">= 1.8"

  required_providers {
    xcsh = {
      source = "f5-sales-demo/xcsh"
      # >= 3.71.1: carries the nested-list value-conversion fix (#1083) — nested
      # ListNestedBlocks (e.g. the inline api_crawler domains) are modeled as
      # types.List so they hold plan-time unknowns; without it the API crawler
      # block fails with a Value Conversion Error. (Supersedes the >= 3.64.0
      # nested Optional+Computed scalar fix.) Locally consumed via dev_overrides.
      version = ">= 3.71.1"
    }
    # Azure providers: this plan also deploys its OWN Azure origin server and
    # traffic generator (modules/origin-server, modules/traffic-generator), which
    # the load balancer's origin pool points at. Versions match the upstream
    # example plans the modules were incorporated from.
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.0"
    }
  }
}
