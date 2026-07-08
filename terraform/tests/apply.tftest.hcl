# End-to-end test: apply the plan against the tenant, assert the objects were
# created with real F5 XC identifiers, then terraform test auto-destroys them.
# Requires reachable tenant + valid XCSH_API_URL/XCSH_API_TOKEN. Run with:
#   terraform test
# This creates and then removes real objects, so it targets a prototyping
# namespace (var.namespace) only.

variables {
  namespace       = "r-mordasiewicz"
  lb_domain       = "httpbin-webapp-tf.example.com"
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
