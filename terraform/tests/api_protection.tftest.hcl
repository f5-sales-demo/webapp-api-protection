# Plan-level tests for API Protection (SP3): shared client-matcher, rate limiting,
# sensitive data / data guard, api_protection_rules, validation_custom_list.
# Targets ./modules/http-lb with a dummy origin.
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

# --- Shared client-matcher (Task 1) ---
run "client_matcher_any_default" {
  command = plan
  module { source = "./modules/http-lb" }
  assert {
    condition     = output.client_matcher_mode == "any"
    error_message = "client_matcher must default to any"
  }
}

run "client_matcher_ip_prefix" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    client_matcher = { mode = "ip_prefix", ip_prefixes = ["10.0.0.0/8"], invert = false }
  }
  assert {
    condition     = output.client_matcher_mode == "ip_prefix"
    error_message = "ip_prefix client_matcher must render"
  }
}

run "client_matcher_ip_threat" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    client_matcher = { mode = "ip_threat", ip_threat_categories = ["SPAM_SOURCES", "BOTNETS"] }
  }
  assert {
    condition     = output.client_matcher_mode == "ip_threat"
    error_message = "ip_threat client_matcher must render"
  }
}

run "client_matcher_rejects_bad_mode" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    client_matcher = { mode = "asn" }
  }
  expect_failures = [var.client_matcher]
}

# --- Rate limiting (Task 3) ---
run "rate_limit_disabled_default" {
  command = plan
  module { source = "./modules/http-lb" }
  assert {
    condition     = output.rate_limit_choice == "disable"
    error_message = "rate_limit must default to disable (0-change)"
  }
}

run "rate_limit_inline_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limit_choice            = "rate_limit"
    rate_limit_total_number      = 500
    rate_limit_unit              = "MINUTE"
    rate_limit_period_multiplier = 1
    rate_limit_burst_multiplier  = 2
  }
  assert {
    condition     = output.rate_limit_choice == "rate_limit"
    error_message = "inline rate_limit arm must render"
  }
}

run "rate_limit_rejects_bad_unit" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limit_choice = "rate_limit"
    rate_limit_unit   = "WEEK"
  }
  expect_failures = [var.rate_limit_unit]
}
