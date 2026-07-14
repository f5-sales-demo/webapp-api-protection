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

# --- Sensitive data & data guard (Tasks 4-5) ---
run "sensitive_data_default" {
  command = plan
  module { source = "./modules/http-lb" }
  assert {
    condition     = output.sensitive_data_policy_choice == "default" && output.sensitive_data_policy_created == false
    error_message = "sensitive data must default to the suppressed default policy (0-change)"
  }
}

run "sensitive_data_custom_policy" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    sensitive_data_policy_enabled = true
    sensitive_data_policy_choice  = "custom"
    sensitive_data_compliances    = ["GDPR", "PCI_DSS"]
  }
  assert {
    condition     = output.sensitive_data_policy_created == true && output.sensitive_data_policy_choice == "custom"
    error_message = "custom sensitive_data_policy must render + create the standalone policy"
  }
}

run "sensitive_data_rejects_bad_compliance" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    sensitive_data_policy_enabled = true
    sensitive_data_compliances    = ["NOT_A_FRAMEWORK"]
  }
  expect_failures = [var.sensitive_data_compliances]
}

run "data_guard_rules_render" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    data_guard_rules = [
      { domain_mode = "any", path = "/api/pay", apply = true },
      { domain_mode = "suffix", domain = "f5-sales-demo.com", path = "/api/ssn", apply = false },
    ]
  }
  assert {
    condition     = output.data_guard_rule_count == 2
    error_message = "data_guard_rules must render"
  }
}

run "data_guard_exact_requires_domain" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    data_guard_rules = [{ domain_mode = "exact", path = "/x" }]
  }
  expect_failures = [var.data_guard_rules]
}

# --- API protection rules (Task 6) ---
run "api_protection_rules_default_empty" {
  command = plan
  module { source = "./modules/http-lb" }
  assert {
    condition     = output.api_protection_rule_count == 0
    error_message = "api_protection_rules must default to empty (0-change)"
  }
}

run "api_protection_allow_and_deny" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_protection_rules = [
      { path = "/api/health", domain_mode = "any", methods = ["GET"], action = "allow" },
      { path = "/api/admin", domain_mode = "specific", domain = "api.f5-sales-demo.com", methods = ["POST", "DELETE"], action = "deny" },
    ]
  }
  assert {
    condition     = output.api_protection_rule_count == 2
    error_message = "allow + deny api_protection_rules must render"
  }
}

run "api_protection_with_ip_threat_matcher" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    client_matcher       = { mode = "ip_threat", ip_threat_categories = ["BOTNETS", "TOR_PROXY"] }
    api_protection_rules = [{ path = "/api/pay", action = "deny" }]
  }
  assert {
    condition     = output.api_protection_rule_count == 1 && output.client_matcher_mode == "ip_threat"
    error_message = "api_protection_rules with ip_threat client-matcher must render"
  }
}

run "api_protection_rejects_bad_action" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_protection_rules = [{ path = "/x", action = "block" }]
  }
  expect_failures = [var.api_protection_rules]
}

# --- OpenAPI validation custom_list (Task 7 — SP2 deferral) ---
run "validation_custom_list_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_definition_choice        = "specification"
    api_specification_validation = "custom_list"
    validation_custom_rules = [
      { path = "/api/health", methods = ["GET"], action = "report" },
      { path = "/api/admin", methods = ["POST"], action = "block" },
    ]
  }
  assert {
    condition     = output.api_specification_validation == "custom_list"
    error_message = "validation_custom_list arm must render"
  }
}

run "validation_custom_rules_reject_bad_action" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_definition_choice        = "specification"
    api_specification_validation = "custom_list"
    validation_custom_rules      = [{ path = "/x", action = "quarantine" }]
  }
  expect_failures = [var.validation_custom_rules]
}
