# Plan-level tests for LPC-5b: xcsh_origin_pool.origin tuning. Targets ./modules/http-lb.
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

run "defaults_round_robin_distributed" {
  command = plan
  module { source = "./modules/http-lb" }
  assert {
    condition     = xcsh_origin_pool.origin.loadbalancer_algorithm == "ROUND_ROBIN"
    error_message = "default loadbalancer_algorithm must be ROUND_ROBIN"
  }
  assert {
    condition     = xcsh_origin_pool.origin.endpoint_selection == "DISTRIBUTED"
    error_message = "default endpoint_selection must be DISTRIBUTED"
  }
  assert {
    condition     = xcsh_origin_pool.origin.advanced_options == null
    error_message = "advanced_options must be omitted by default"
  }
}

run "algorithm_and_selection_render" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    origin_lb_algorithm       = "LEAST_REQUEST"
    origin_endpoint_selection = "LOCAL_PREFERRED"
  }
  assert {
    condition     = xcsh_origin_pool.origin.loadbalancer_algorithm == "LEAST_REQUEST"
    error_message = "loadbalancer_algorithm must render"
  }
  assert {
    condition     = xcsh_origin_pool.origin.endpoint_selection == "LOCAL_PREFERRED"
    error_message = "endpoint_selection must render"
  }
}

run "advanced_options_render" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    origin_connection_timeout = 3000
    origin_http_idle_timeout  = 300000
  }
  assert {
    condition     = xcsh_origin_pool.origin.advanced_options.connection_timeout == 3000
    error_message = "advanced_options.connection_timeout must render"
  }
  assert {
    condition     = xcsh_origin_pool.origin.advanced_options.http_idle_timeout == 300000
    error_message = "advanced_options.http_idle_timeout must render"
  }
}

run "bad_algorithm_rejected" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { origin_lb_algorithm = "RING_HASH" }
  expect_failures = [var.origin_lb_algorithm]
}

run "bad_selection_rejected" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { origin_endpoint_selection = "GLOBAL" }
  expect_failures = [var.origin_endpoint_selection]
}
