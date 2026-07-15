# Plan-level tests for the sensitive-data surface (Coverage Batch C): standalone
# xcsh_data_type, the sensitive_data_policy custom_data_types refs, the LB
# sensitive_data_disclosure_rules, and disabled_predefined_data_types. Targets
# ./modules/http-lb. Defaults keep everything off (0-change).
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

# --- standalone xcsh_data_type ---

run "data_type_none_by_default" {
  command = plan
  module { source = "./modules/http-lb" }
  assert {
    condition     = output.data_type_count == 0
    error_message = "no data types by default (0-change)"
  }
}

run "data_type_key_regex" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    data_types = [{
      name              = "dt-acct"
      compliances       = ["PCI_DSS"]
      is_sensitive_data = true
      rules             = [{ type = "key", key_matcher = "regex", key_regex = "^account_id$" }]
    }]
  }
  assert {
    condition     = output.data_type_count == 1 && contains(output.data_type_names, "dt-acct")
    error_message = "dt-acct must render one xcsh_data_type"
  }
  assert {
    condition     = xcsh_data_type.this["dt-acct"].rules[0].key_pattern.regex_value == "^account_id$" && xcsh_data_type.this["dt-acct"].is_sensitive_data == true
    error_message = "type=key regex must render key_pattern.regex_value"
  }
}

run "data_type_value_substring_and_key_value_exact" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    data_types = [
      { name = "dt-tok", rules = [{ type = "value", value_matcher = "substring", value_substring = "secret" }] },
      { name = "dt-kv", rules = [{ type = "key_value", key_matcher = "exact", key_exact = ["ssn"], value_matcher = "regex", value_regex = "\\d{3}-\\d{2}-\\d{4}" }] },
    ]
  }
  assert {
    condition     = xcsh_data_type.this["dt-tok"].rules[0].value_pattern.substring_value == "secret"
    error_message = "type=value substring must render value_pattern.substring_value"
  }
  assert {
    condition     = xcsh_data_type.this["dt-kv"].rules[0].key_value_pattern.key_pattern.exact_values != null && xcsh_data_type.this["dt-kv"].rules[0].key_value_pattern.value_pattern.regex_value == "\\d{3}-\\d{2}-\\d{4}"
    error_message = "type=key_value must render both key_pattern.exact_values + value_pattern.regex_value"
  }
}

# --- data_type validation failures ---

run "data_type_rejects_dup_names" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { data_types = [{ name = "dup" }, { name = "dup" }] }
  expect_failures = [var.data_types]
}

run "data_type_rejects_bad_compliance" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { data_types = [{ name = "d", compliances = ["NOPE"] }] }
  expect_failures = [var.data_types]
}

run "data_type_rejects_bad_rule_type" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { data_types = [{ name = "d", rules = [{ type = "header" }] }] }
  expect_failures = [var.data_types]
}

run "data_type_rejects_key_without_matcher" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { data_types = [{ name = "d", rules = [{ type = "key" }] }] }
  expect_failures = [var.data_types]
}

run "data_type_rejects_exact_empty_payload" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { data_types = [{ name = "d", rules = [{ type = "key", key_matcher = "exact" }] }] }
  expect_failures = [var.data_types]
}

run "data_type_rejects_regex_null_payload" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { data_types = [{ name = "d", rules = [{ type = "key", key_matcher = "regex" }] }] }
  expect_failures = [var.data_types]
}

run "data_type_rejects_value_substring_null_payload" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { data_types = [{ name = "d", rules = [{ type = "value", value_matcher = "substring" }] }] }
  expect_failures = [var.data_types]
}

# --- policy custom_data_types + disabled_predefined ---

run "policy_custom_data_types_and_disabled_predefined" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    sensitive_data_policy_choice       = "custom"
    sensitive_data_disabled_predefined = ["EMAIL", "PHONE_NUMBER"]
    data_types                         = [{ name = "dt-acct", rules = [{ type = "key", key_matcher = "regex", key_regex = "^acct$" }] }]
    sensitive_data_custom_type_refs    = ["dt-acct"]
  }
  assert {
    condition     = xcsh_sensitive_data_policy.this[0].custom_data_types[0].custom_data_type_ref.name == "dt-acct"
    error_message = "custom_data_types must reference the dt-acct data_type"
  }
  assert {
    condition     = toset(xcsh_sensitive_data_policy.this[0].disabled_predefined_data_types) == toset(["EMAIL", "PHONE_NUMBER"])
    error_message = "disabled_predefined_data_types must render on the policy"
  }
}

# --- LB sensitive_data_disclosure_rules ---

run "sensitive_data_disclosure_mask_and_report" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    sensitive_data_disclosure_rules = [
      { path = "/api/users", methods = ["GET"], fields = ["ssn", "dob"], action = "mask" },
      { path = "/api/audit", action = "report" },
    ]
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.sensitive_data_disclosure_rules != null && xcsh_http_loadbalancer.this.sensitive_data_disclosure_rules.sensitive_data_types_in_response[0].mask != null
    error_message = "action=mask must render mask on the first disclosure rule"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.sensitive_data_disclosure_rules.sensitive_data_types_in_response[0].api_endpoint.path == "/api/users" && xcsh_http_loadbalancer.this.sensitive_data_disclosure_rules.sensitive_data_types_in_response[1].report != null
    error_message = "disclosure rules must render api_endpoint + report arm"
  }
  # mask/report are a oneof, and a fieldless rule omits the body block entirely.
  assert {
    condition     = xcsh_http_loadbalancer.this.sensitive_data_disclosure_rules.sensitive_data_types_in_response[0].report == null && xcsh_http_loadbalancer.this.sensitive_data_disclosure_rules.sensitive_data_types_in_response[1].mask == null
    error_message = "mask/report must be mutually exclusive per rule"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.sensitive_data_disclosure_rules.sensitive_data_types_in_response[0].body != null && xcsh_http_loadbalancer.this.sensitive_data_disclosure_rules.sensitive_data_types_in_response[1].body == null
    error_message = "body block must render when fields are named and be omitted when none are"
  }
}

# --- precondition / validation failures ---

run "disclosure_rejects_bad_action" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { sensitive_data_disclosure_rules = [{ path = "/x", action = "hide" }] }
  expect_failures = [var.sensitive_data_disclosure_rules]
}

run "custom_type_refs_reject_without_policy" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    sensitive_data_policy_choice    = "default"
    data_types                      = [{ name = "dt-acct" }]
    sensitive_data_custom_type_refs = ["dt-acct"]
  }
  expect_failures = [xcsh_http_loadbalancer.this]
}

run "custom_type_refs_reject_unknown" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    sensitive_data_policy_choice    = "custom"
    sensitive_data_custom_type_refs = ["ghost"]
  }
  expect_failures = [xcsh_sensitive_data_policy.this]
}
