terraform {
  # >= 1.8 for provider-defined functions (provider::xcsh::blindfold, used by
  # scripts/blindfold-seal.sh to seal API-crawler / SecretType credentials).
  required_version = ">= 1.8"

  required_providers {
    xcsh = {
      source = "f5-sales-demo/xcsh"
      # >= 3.71.2: carries the object-ref tenant reconstruction fix (#1091, PR
      # #1092) — object-refs at any nesting depth (LB api_specification.
      # api_definition, enable_api_discovery...code_base_integrations[], and the
      # standalone code_base_integration/api_definition refs) keep their Computed
      # `tenant` from surviving apply, so SP2's LB wiring plans clean. Builds on
      # 3.71.1's nested-list value-conversion fix (#1083) for the inline
      # api_crawler domains. Locally consumed via dev_overrides.
      version = ">= 3.71.2"
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
