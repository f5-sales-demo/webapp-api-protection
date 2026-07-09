# End-to-end test: apply the plan against the tenant (creates the namespace + LB +
# pool + health check), assert real F5 XC identifiers, then terraform test
# auto-destroys them (namespace cascade-deleted). Requires reachable tenant + valid
# XCSH_API_URL/XCSH_API_TOKEN. Run deliberately with `terraform test` — it creates
# and removes REAL production objects (incl. the namespace), so do not run it while
# the real deployment of the same namespace exists.

variables {
  namespace       = "webapp-api-protection"
  lb_domains      = ["www.f5-sales-demo.com", "api.f5-sales-demo.com"]
  origin_dns_name = "httpbin.org"
  origin_port     = 80
}

run "apply_to_tenant_creates_objects" {
  command = apply

  assert {
    condition     = output.loadbalancer_id != ""
    error_message = "Load balancer must have a real F5 XC id after apply (API accepted the config)"
  }

  assert {
    condition     = output.loadbalancer_name == "webapp-api-protection"
    error_message = "Load balancer name mismatch after apply"
  }

  assert {
    condition     = output.origin_pool_name == "httpbin-origin-pool"
    error_message = "Origin pool name mismatch after apply"
  }

  assert {
    condition     = output.healthcheck_name == "httpbin-healthcheck"
    error_message = "Health check name mismatch after apply"
  }
}
