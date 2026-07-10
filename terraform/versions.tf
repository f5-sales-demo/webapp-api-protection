terraform {
  required_version = ">= 1.5"

  required_providers {
    xcsh = {
      source = "f5-sales-demo/xcsh"
      # >= 3.64.0: first release carrying the nested Optional+Computed scalar
      # fix (http_health_check.use_http2 no longer unknown-after-apply). Resources
      # http_loadbalancer, origin_pool, app_firewall (WAF), api_definition are all
      # generated. Locally the provider is consumed via dev_overrides (ignores this).
      version = ">= 3.64.0"
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
