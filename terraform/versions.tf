terraform {
  # >= 1.8 for provider-defined functions (provider::xcsh::blindfold, used by
  # scripts/blindfold-seal.sh to seal API-crawler / SecretType credentials).
  required_version = ">= 1.8"

  required_providers {
    xcsh = {
      source = "f5-sales-demo/xcsh"
      # >= 3.71.3: SP3 API-Protection read-back fix (provider #1095, PR #1096).
      # api_protection_rules / validation_custom_list with a concrete client_matcher
      # arm (ip_prefix / ip_threat) previously failed apply ("inconsistent result":
      # server-echoed client_matcher.any_client{} + api_endpoint_method.invert_matcher)
      # and drifted on import (any_client / any_ip / skip_response_validation server-
      # default oneof base markers). 3.71.3 threads prior-state into reconstructed
      # spine blocks + nested-list elements and suppresses those markers on import, so
      # the SP3 matrix is 13/13 idempotent + round-trip-import clean. Builds on 3.71.2's
      # object-ref tenant reconstruction (#1091). Locally consumed via dev_overrides.
      version = ">= 3.71.3"
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
