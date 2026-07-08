terraform {
  required_version = ">= 1.5"

  required_providers {
    xcsh = {
      source = "f5-sales-demo/xcsh"
      # >= 3.63.0: release whose generated resources include http_loadbalancer,
      # origin_pool, app_firewall (WAF) and api_definition (API protection) —
      # the full roadmap for this repo. Locally the provider is consumed via
      # dev_overrides, which ignores this constraint.
      version = ">= 3.63.0"
    }
  }
}
