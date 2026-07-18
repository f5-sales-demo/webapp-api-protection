# Plan-level tests for custom routes (CR-1 foundation + CR-2 match). Targets ./modules/http-lb.
# command = plan (no creds).
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

run "prefix_route_to_pool" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    custom_routes = [{ path_mode = "prefix", path_value = "/app" }]
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.routes[0].simple_route.path.prefix == "/app"
    error_message = "prefix path match must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.routes[0].simple_route.origin_pools[0].pool.name == "origin-pool"
    error_message = "origin_pools pool ref must render"
  }
}

run "exact_and_regex_path" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    custom_routes = [
      { path_mode = "exact", path_value = "/health" },
      { path_mode = "regex", path_value = "^/v[0-9]+/.*$" },
    ]
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.routes[0].simple_route.path.path == "/health"
    error_message = "exact path match must render on path.path"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.routes[1].simple_route.path.regex == "^/v[0-9]+/.*$"
    error_message = "regex path match must render"
  }
}

run "header_and_port_match" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    custom_routes = [{
      path_mode     = "prefix"
      path_value    = "/api"
      http_method   = "GET"
      incoming_port = 443
      headers = [
        { name = "x-canary", mode = "exact", value = "on" },
        { name = "x-legacy", mode = "presence", invert_match = true },
      ]
    }]
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.routes[0].simple_route.headers[0].exact == "on"
    error_message = "header exact match must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.routes[0].simple_route.headers[1].invert_match == true
    error_message = "header invert_match must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.routes[0].simple_route.incoming_port.port == 443
    error_message = "incoming_port match must render"
  }
}

run "advanced_options_render" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    custom_routes = [{
      path_mode           = "prefix"
      path_value          = "/app"
      prefix_rewrite      = "/"
      priority            = "HIGH"
      timeout_ms          = 5000
      req_headers_add     = [{ name = "x-route", value = "app" }]
      resp_headers_remove = ["server"]
      waf_mode            = "app_firewall"
    }]
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.routes[0].simple_route.advanced_options.prefix_rewrite == "/"
    error_message = "advanced_options.prefix_rewrite must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.routes[0].simple_route.advanced_options.priority == "HIGH"
    error_message = "advanced_options.priority must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.routes[0].simple_route.advanced_options.request_headers_to_add[0].name == "x-route"
    error_message = "advanced_options request_headers_to_add must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.routes[0].simple_route.advanced_options.app_firewall.name == "webapp-api-protection-waf"
    error_message = "advanced_options per-route app_firewall ref must render"
  }
}

run "advanced_options_omitted_when_no_tuning" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { custom_routes = [{ path_mode = "prefix", path_value = "/app" }] }
  assert {
    condition     = xcsh_http_loadbalancer.this.routes[0].simple_route.advanced_options == null
    error_message = "advanced_options must be omitted when no tuning field is set"
  }
}

run "bad_waf_mode_rejected" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { custom_routes = [{ path_mode = "prefix", path_value = "/x", waf_mode = "block" }] }
  expect_failures = [var.custom_routes]
}

run "routes_omitted_by_default" {
  command = plan
  module { source = "./modules/http-lb" }
  assert {
    condition     = length(xcsh_http_loadbalancer.this.routes) == 0
    error_message = "routes must be empty by default"
  }
}

run "bad_path_mode_rejected" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { custom_routes = [{ path_mode = "glob", path_value = "/x" }] }
  expect_failures = [var.custom_routes]
}

run "header_exact_requires_value" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    custom_routes = [{ path_mode = "prefix", path_value = "/x", headers = [{ name = "h", mode = "exact" }] }]
  }
  expect_failures = [var.custom_routes]
}
