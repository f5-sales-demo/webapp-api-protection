# Plan-level tests: verify the module wires the load balancer + origin pool
# correctly, without contacting the tenant. Run with:
#   terraform test
# (provider auth from XCSH_API_URL/XCSH_API_TOKEN env; plan does not call the API)

variables {
  namespace       = "webapp-api-protection"
  lb_domains      = ["www.f5-sales-demo.com", "api.f5-sales-demo.com"]
  origin_dns_name = "httpbin.org"
  origin_port     = 80
}

run "plan_creates_loadbalancer_and_pool" {
  command = plan

  assert {
    condition     = output.loadbalancer_name == "webapp-api-protection"
    error_message = "Load balancer name should be webapp-api-protection"
  }

  assert {
    condition     = output.origin_pool_name == "httpbin-origin-pool"
    error_message = "Origin pool name should be httpbin-origin-pool"
  }

  assert {
    condition     = output.domains == tolist(var.lb_domains)
    error_message = "Load balancer should serve exactly the configured lb_domains"
  }

  assert {
    condition     = output.healthcheck_name == "httpbin-healthcheck"
    error_message = "Origin pool should reference an httpbin-healthcheck health check"
  }
}
