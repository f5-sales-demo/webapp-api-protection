# Plan-level tests for CR-1: custom routes foundation (simple_route path-prefix -> pool).
# Targets ./modules/http-lb. command = plan (no creds).
variables {
  namespace         = "webapp-api-protection"
  lb_domains        = ["www.f5-sales-demo.com"]
  origin_ip         = "203.0.113.10"
  origin_port       = 80
  health_check_path = "/health"
  labels            = {}
  csd_enabled       = false
  mud_enabled       = false
}

run "simple_route_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    custom_routes = [{ path_prefix = "/app" }]
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.routes[0].simple_route.path.prefix == "/app"
    error_message = "simple_route path prefix must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.routes[0].simple_route.origin_pools[0].pool.name == "origin-pool"
    error_message = "simple_route origin_pools pool ref must render"
  }
}

run "routes_omitted_by_default" {
  command = plan
  module { source = "./modules/http-lb" }
  assert {
    condition     = length(xcsh_http_loadbalancer.this.routes) == 0
    error_message = "routes must be empty by default"
  }
}

run "bad_path_prefix_rejected" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { custom_routes = [{ path_prefix = "app" }] }
  expect_failures = [var.custom_routes]
}
