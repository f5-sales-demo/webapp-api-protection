# Plan-level tests for app-layer protection (LPC-1): cors_policy, csrf_policy,
# protected_cookies. Targets ./modules/http-lb. command = plan (no creds).
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

run "cors_policy_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    cors_policy = {
      allow_origin      = ["https://app.example.com"]
      allow_methods     = "GET, POST"
      allow_credentials = true
      maximum_age       = 600
    }
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.cors_policy.allow_origin[0] == "https://app.example.com"
    error_message = "cors_policy allow_origin must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.cors_policy.allow_credentials == true
    error_message = "cors_policy allow_credentials must render"
  }
}

run "csrf_all_domains_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { csrf_policy_mode = "all_domains" }
  assert {
    condition     = xcsh_http_loadbalancer.this.csrf_policy.all_load_balancer_domains != null
    error_message = "csrf all_domains marker must render"
  }
}

run "csrf_custom_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    csrf_policy_mode    = "custom"
    csrf_custom_domains = ["trusted.example.com"]
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.csrf_policy.custom_domain_list.domains[0] == "trusted.example.com"
    error_message = "csrf custom_domain_list must render"
  }
}

run "protected_cookies_render" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    protected_cookies = [{ name = "SESSION", httponly = "add", secure = "add", samesite = "strict", tampering = "enable", max_age_value = 3600 }]
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.protected_cookies[0].name == "SESSION"
    error_message = "protected_cookies name must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.protected_cookies[0].add_httponly != null && xcsh_http_loadbalancer.this.protected_cookies[0].samesite_strict != null && xcsh_http_loadbalancer.this.protected_cookies[0].enable_tampering_protection != null
    error_message = "protected_cookies attribute markers must render"
  }
}

run "app_protection_omitted_by_default" {
  command = plan
  module { source = "./modules/http-lb" }
  assert {
    condition     = xcsh_http_loadbalancer.this.cors_policy == null && xcsh_http_loadbalancer.this.csrf_policy == null && try(length(xcsh_http_loadbalancer.this.protected_cookies), 0) == 0
    error_message = "cors/csrf/protected_cookies must be omitted by default"
  }
}

run "rejects_bad_csrf_mode" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { csrf_policy_mode = "maybe" }
  expect_failures = [var.csrf_policy_mode]
}

run "rejects_bad_cookie_samesite" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { protected_cookies = [{ name = "X", samesite = "sometimes" }] }
  expect_failures = [var.protected_cookies]
}

run "rejects_bad_cookie_httponly" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { protected_cookies = [{ name = "X", httponly = "maybe" }] }
  expect_failures = [var.protected_cookies]
}
