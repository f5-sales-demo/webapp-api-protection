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
  }
}
