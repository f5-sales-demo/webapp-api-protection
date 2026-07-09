# Plan-level unit tests for the http-lb module: verify it wires the load balancer,
# origin pool, and health check correctly, without contacting any tenant or Azure.
# Targets ./modules/http-lb directly (with a dummy origin IP) so no Azure auth is
# needed. Run with:  terraform test
# (provider auth from XCSH_API_URL/XCSH_API_TOKEN env; plan does not call the API)

run "plan_creates_loadbalancer_and_pool" {
  command = plan

  module {
    source = "./modules/http-lb"
  }

  variables {
    namespace         = "webapp-api-protection"
    lb_domains        = ["www.f5-sales-demo.com", "api.f5-sales-demo.com"]
    origin_ip         = "203.0.113.10"
    origin_port       = 80
    health_check_path = "/health"
    labels            = {}
    waf_mode          = "blocking"
  }

  assert {
    condition     = output.loadbalancer_name == "webapp-api-protection"
    error_message = "Load balancer name should be webapp-api-protection"
  }

  assert {
    condition     = output.app_firewall_name == "webapp-api-protection-waf"
    error_message = "LB should reference the webapp-api-protection-waf app firewall"
  }

  assert {
    condition     = output.origin_pool_name == "origin-pool"
    error_message = "Origin pool name should be origin-pool"
  }

  assert {
    condition     = output.domains == tolist(var.lb_domains)
    error_message = "Load balancer should serve exactly the configured lb_domains"
  }

  assert {
    condition     = output.healthcheck_name == "origin-healthcheck"
    error_message = "Origin pool should reference an origin-healthcheck health check"
  }
}
