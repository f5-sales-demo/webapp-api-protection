# Plan-level tests for API Protection: rate limiting, sensitive data / data guard,
# api_protection_rules (per-rule client_matcher + request_matcher + api_groups_rules,
# Coverage Batch D), validation_custom_list. Targets ./modules/http-lb.
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
    sensitive_data_policy_choice = "custom"
    sensitive_data_compliances   = ["GDPR", "PCI_DSS"]
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
    sensitive_data_policy_choice = "custom"
    sensitive_data_compliances   = ["NOT_A_FRAMEWORK"]
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

run "api_protection_per_rule_ip_threat_and_invert" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_protection_rules = [{
      path           = "/api/pay"
      action         = "deny"
      methods        = ["POST"]
      methods_invert = true
      client_matcher = { mode = "ip_threat_category_list", ip_threat_categories = ["BOTNETS", "TOR_PROXY"] }
    }]
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.api_protection_rules.api_endpoint_rules[0].client_matcher.ip_threat_category_list != null && xcsh_http_loadbalancer.this.api_protection_rules.api_endpoint_rules[0].api_endpoint_method.invert_matcher == true
    error_message = "per-rule ip_threat client_matcher + methods_invert must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.api_protection_rules.api_endpoint_rules[0].action.deny != null && xcsh_http_loadbalancer.this.api_protection_rules.api_endpoint_rules[0].action.allow == null
    error_message = "action=deny must render (and allow omitted)"
  }
}

run "api_protection_deep_matchers_and_request_matcher" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_protection_rules = [{
      path           = "/api/orders"
      action         = "allow"
      client_matcher = { mode = "asn_matcher", asn_sets = [{ name = "corp-asns" }] }
      request_matcher = {
        headers      = [{ name = "x-tenant", presence = "present" }]
        query_params = [{ name = "debug", presence = "match", exact_values = ["1"] }]
      }
    }]
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.api_protection_rules.api_endpoint_rules[0].client_matcher.asn_matcher != null
    error_message = "asn_matcher (ref sets) must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.api_protection_rules.api_endpoint_rules[0].request_matcher.headers[0].check_present != null && xcsh_http_loadbalancer.this.api_protection_rules.api_endpoint_rules[0].request_matcher.query_params[0].item != null
    error_message = "request_matcher header(present) + query_param(match) must render"
  }
}

run "api_protection_tls_fingerprint_matcher" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_protection_rules = [{
      path           = "/api/bot"
      action         = "deny"
      client_matcher = { mode = "tls_fingerprint_matcher", tls_classes = ["ANY_MALICIOUS_FINGERPRINT"] }
    }]
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.api_protection_rules.api_endpoint_rules[0].client_matcher.tls_fingerprint_matcher != null
    error_message = "tls_fingerprint_matcher must render"
  }
}

run "api_protection_rejects_bad_tls_class" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_protection_rules = [{ path = "/x", client_matcher = { mode = "tls_fingerprint_matcher", tls_classes = ["Automated"] } }]
  }
  expect_failures = [var.api_protection_rules]
}

run "api_protection_group_rules_render" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_protection_group_rules = [
      { api_group = "sensitive", action = "deny", client_matcher = { mode = "ip_prefix_list", ip_prefixes = ["10.0.0.0/8"] } },
      { base_path = "/api/internal", action = "allow" },
    ]
  }
  assert {
    condition     = output.api_protection_group_rule_count == 2 && xcsh_http_loadbalancer.this.api_protection_rules.api_groups_rules[0].client_matcher.ip_prefix_list != null
    error_message = "api_groups_rules (allow/deny + client_matcher) must render"
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

run "api_protection_rejects_bad_client_matcher_mode" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_protection_rules = [{ path = "/x", client_matcher = { mode = "ip_prefixlist" } }]
  }
  expect_failures = [var.api_protection_rules]
}

run "api_protection_rejects_client_matcher_empty_payload" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_protection_rules = [{ path = "/x", client_matcher = { mode = "asn_list" } }]
  }
  expect_failures = [var.api_protection_rules]
}

run "api_protection_group_rejects_no_target" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_protection_group_rules = [{ action = "deny" }]
  }
  expect_failures = [var.api_protection_group_rules]
}

run "api_protection_group_rejects_client_matcher_empty_payload" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_protection_group_rules = [{ base_path = "/x", client_matcher = { mode = "ip_prefix_list" } }]
  }
  expect_failures = [var.api_protection_group_rules]
}

run "api_protection_group_rejects_bad_tls_class" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_protection_group_rules = [{ base_path = "/x", client_matcher = { mode = "tls_fingerprint_matcher", tls_classes = ["Nope"] } }]
  }
  expect_failures = [var.api_protection_group_rules]
}

run "api_protection_rejects_bad_ip_threat_category" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_protection_rules = [{ path = "/x", client_matcher = { mode = "ip_threat_category_list", ip_threat_categories = ["MALWARE"] } }]
  }
  expect_failures = [var.api_protection_rules]
}

run "api_protection_rejects_bad_request_matcher_presence" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_protection_rules = [{ path = "/x", request_matcher = { headers = [{ name = "x", presence = "maybe" }] } }]
  }
  expect_failures = [var.api_protection_rules]
}

run "api_protection_group_rejects_specific_without_domain" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_protection_group_rules = [{ base_path = "/x", domain_mode = "specific" }]
  }
  expect_failures = [var.api_protection_group_rules]
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
