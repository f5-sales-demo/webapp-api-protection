# End-to-end test: apply the http-lb module against the tenant (into an existing
# namespace), assert real F5 XC identifiers, then terraform test auto-destroys the
# objects. Requires a reachable tenant + valid XCSH_API_URL/XCSH_API_TOKEN AND a
# pre-existing namespace (pass -var namespace=<ns>). It targets ./modules/http-lb
# (not the root) so it does NOT create Azure VMs.
#
# Run deliberately with `terraform test`. It creates and removes REAL objects named
# origin-pool / origin-healthcheck / webapp-api-protection in the given namespace,
# so DO NOT run it while the real deployment using those names exists — it will
# collide. Use a throwaway namespace for this test.

run "apply_to_tenant_creates_objects" {
  command = apply

  module {
    source = "./modules/http-lb"
  }

  variables {
    namespace         = "webapp-api-protection-test"
    lb_domains        = ["test.f5-sales-demo.com"]
    origin_ip         = "203.0.113.10"
    origin_port       = 80
    health_check_path = "/health"
    labels            = {}
    waf_mode          = "blocking"
    # Keep this deliberate apply test addon-independent (CSD needs the tenant addon).
    csd_enabled = false
  }

  assert {
    condition     = output.loadbalancer_id != ""
    error_message = "Load balancer must have a real F5 XC id after apply (API accepted the config)"
  }

  assert {
    condition     = output.loadbalancer_name == "webapp-api-protection"
    error_message = "Load balancer name mismatch after apply"
  }

  assert {
    condition     = output.origin_pool_name == "origin-pool"
    error_message = "Origin pool name mismatch after apply"
  }

  assert {
    condition     = output.healthcheck_name == "origin-healthcheck"
    error_message = "Health check name mismatch after apply"
  }
}
