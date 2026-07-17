# Plan-level tests for header/cookie manipulation (LPC-2): more_option request/response
# headers add/remove + cookies remove. Targets ./modules/http-lb. command = plan (no creds).
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

run "headers_add_remove_render" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    request_headers_to_add     = [{ name = "x-env", value = "prod", append = true }]
    response_headers_to_add    = [{ name = "x-frame-options", value = "DENY" }]
    request_headers_to_remove  = ["x-internal"]
    response_headers_to_remove = ["server"]
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.more_option.request_headers_to_add[0].name == "x-env"
    error_message = "request_headers_to_add must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.more_option.request_headers_to_add[0].append == true
    error_message = "request_headers_to_add append must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.more_option.response_headers_to_add[0].value == "DENY"
    error_message = "response_headers_to_add must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.more_option.response_headers_to_remove[0] == "server"
    error_message = "response_headers_to_remove must render"
  }
}

run "cookies_remove_render" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    request_cookies_to_remove  = ["tracking"]
    response_cookies_to_remove = ["debug"]
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.more_option.request_cookies_to_remove[0] == "tracking"
    error_message = "request_cookies_to_remove must render"
  }
}

run "more_option_omitted_by_default" {
  command = plan
  module { source = "./modules/http-lb" }
  assert {
    condition     = xcsh_http_loadbalancer.this.more_option == null
    error_message = "more_option must be omitted (null) by default"
  }
}

run "disable_default_error_pages_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { disable_default_error_pages = true }
  assert {
    condition     = xcsh_http_loadbalancer.this.more_option.disable_default_error_pages == true
    error_message = "disable_default_error_pages must render inside more_option"
  }
}
