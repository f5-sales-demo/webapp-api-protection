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
      #
      # >= 3.71.4: SP4 API-Testing read-back fix (provider #1099, PR #1100). Applying an
      # xcsh_api_testing / LB api_testing credential previously failed apply ("inconsistent
      # result": server-echoed credentials_choice base marker `standard`; dropped write-only
      # api_key.value secret) and drifted on import. 3.71.4 threads prior-state into lists
      # nested in LIST elements (domains[].credentials[]) and preserves list-element empty
      # markers' absence, + suppresses `standard` on import. SP4 matrix idempotent +
      # round-trip-import clean.
      #
      # >= 3.72.0: Coverage Batch B rate limiting (provider #1104, PR #1105). A
      # standalone xcsh_rate_limiter_policy rule that omits a client matcher drifted on
      # import (server materializes the any_asn/any_country/any_ip base marker of each
      # client-matcher oneof; cascaded custom_rate_limiter.tenant to known-after-apply).
      # 3.72.0 suppresses those RateLimiterPolicy markers on import, so the standalone
      # policy round-trips 0-change. LB rate_limit allow-lists/policies + api_rate_limit
      # arm needed no provider change (any_client/any_ip already suppressed).
      #
      # >= 3.72.1: Coverage Batch F app_api_group (provider #1108, PR #1109). Marshalling
      # a single nested block whose child is another single block with the SAME GoName
      # (F5 XC view-ref wrappers, e.g. xcsh_app_api_group http_loadbalancer{http_loadbalancer{}})
      # shadowed the outer map var, sending "http_loadbalancer": {} and dropping the LB
      # association -> 400. 3.72.1 names the marshal map var by nesting path so the outer
      # map carries the populated ref, so xcsh_app_api_group applies.
      version = ">= 3.72.1"
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
