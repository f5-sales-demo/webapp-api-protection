# Plan-level tests for the service_policy foundation (SPol-1): the standalone
# xcsh_service_policy rule-handling + server-scope oneofs and the LB
# service_policies_choice wiring. Targets ./modules/http-lb. command = plan (no creds).
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

# --- render: rule_list arm with an ALLOW rule ---
run "rule_list_action_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies = [{
      name          = "spol-rules"
      rule_handling = "rule_list"
      rules         = [{ name = "allow-one", action = "ALLOW" }]
    }]
  }
  assert {
    condition     = xcsh_service_policy.this["spol-rules"].rule_list.rules[0].spec.action == "ALLOW"
    error_message = "rule_list rule action must render ALLOW"
  }
}

# --- render: allow_all arm emits the empty marker ---
run "allow_all_arm_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies = [{ name = "spol-allow", rule_handling = "allow_all" }]
  }
  assert {
    condition     = xcsh_service_policy.this["spol-allow"].allow_all_requests != null
    error_message = "allow_all arm must emit allow_all_requests"
  }
}

# --- render: server_selector scope ---
run "server_selector_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies = [{
      name            = "spol-srv"
      rule_handling   = "allow_all"
      server_scope    = "selector"
      server_selector = ["app in (webapp)"]
    }]
  }
  assert {
    condition     = length(xcsh_service_policy.this["spol-srv"].server_selector.expressions) == 1
    error_message = "server_selector expressions must render"
  }
}

# --- render: LB active_service_policies wiring in order ---
run "lb_active_service_policies_wiring" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies        = [{ name = "spol-a", rule_handling = "allow_all" }]
    service_policies_choice = "active"
    service_policy_active   = ["spol-a"]
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.active_service_policies.policies[0].name == "spol-a"
    error_message = "LB active_service_policies must reference the policy by name"
  }
}

# --- 0-change default: no policies, no LB block ---
run "default_creates_nothing" {
  command = plan
  module { source = "./modules/http-lb" }
  assert {
    condition     = length(xcsh_service_policy.this) == 0
    error_message = "default (empty service_policies) must create no service policy"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.active_service_policies == null && xcsh_http_loadbalancer.this.no_service_policies == null
    error_message = "default service_policies_choice=omit must emit no LB service-policy block"
  }
}

# --- validation failures ---

run "rejects_bad_rule_handling" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies = [{ name = "x", rule_handling = "permit_all" }]
  }
  expect_failures = [var.service_policies]
}

run "rejects_bad_server_scope" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies = [{ name = "x", server_scope = "any" }]
  }
  expect_failures = [var.service_policies]
}

run "rejects_rules_on_non_rule_list" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies = [{ name = "x", rule_handling = "allow_all", rules = [{ name = "r" }] }]
  }
  expect_failures = [var.service_policies]
}

run "rejects_bad_choice" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies_choice = "namespace"
  }
  expect_failures = [var.service_policies_choice]
}

# --- precondition failures ---

run "rejects_empty_rule_list" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies = [{ name = "empty", rule_handling = "rule_list", rules = [] }]
  }
  expect_failures = [xcsh_service_policy.this]
}

run "rejects_active_without_names" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies        = [{ name = "spol-a", rule_handling = "allow_all" }]
    service_policies_choice = "active"
    service_policy_active   = []
  }
  expect_failures = [xcsh_http_loadbalancer.this]
}

run "rejects_active_name_not_created" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies        = [{ name = "spol-a", rule_handling = "allow_all" }]
    service_policies_choice = "active"
    service_policy_active   = ["ghost"]
  }
  expect_failures = [xcsh_http_loadbalancer.this]
}

# ============================================================================
# SPol-2: rule client/asn/ip/tls matchers
# ============================================================================

run "matcher_ip_threat_and_asn_and_ip_and_tls_render" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies = [{
      name          = "spol2"
      rule_handling = "rule_list"
      rules = [{
        name   = "r0", action = "DENY"
        client = "ip_threat", ip_threat_categories = ["BOTNETS"]
        asn    = "list", asn_numbers = [64512]
        ip     = "prefix_list", ip_prefixes = ["10.0.0.0/8"]
        tls    = "matcher", tls_classes = ["TRICKBOT"]
      }]
    }]
  }
  assert {
    condition     = xcsh_service_policy.this["spol2"].rule_list.rules[0].spec.ip_threat_category_list.ip_threat_categories[0] == "BOTNETS"
    error_message = "ip_threat_category_list must render"
  }
  assert {
    condition     = xcsh_service_policy.this["spol2"].rule_list.rules[0].spec.asn_list.as_numbers[0] == 64512
    error_message = "asn_list must render"
  }
  assert {
    condition     = xcsh_service_policy.this["spol2"].rule_list.rules[0].spec.ip_prefix_list.ip_prefixes[0] == "10.0.0.0/8"
    error_message = "ip_prefix_list must render"
  }
  assert {
    condition     = xcsh_service_policy.this["spol2"].rule_list.rules[0].spec.tls_fingerprint_matcher.classes[0] == "TRICKBOT"
    error_message = "tls_fingerprint_matcher.classes must render"
  }
}

run "matcher_client_selector_render" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies = [{
      name  = "spol2s", rule_handling = "rule_list"
      rules = [{ name = "r0", action = "ALLOW", client = "selector", client_selector = ["app in (webapp)"] }]
    }]
  }
  assert {
    condition     = length(xcsh_service_policy.this["spol2s"].rule_list.rules[0].spec.client_selector.expressions) == 1
    error_message = "client_selector.expressions must render"
  }
}

run "matcher_rejects_bad_ip_threat_category" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies = [{
      name  = "x", rule_handling = "rule_list"
      rules = [{ name = "r0", client = "ip_threat", ip_threat_categories = ["NOT_A_CATEGORY"] }]
    }]
  }
  expect_failures = [var.service_policies]
}

run "matcher_rejects_bad_tls_class" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies = [{
      name  = "x", rule_handling = "rule_list"
      rules = [{ name = "r0", tls = "matcher", tls_classes = ["MALWARE_X"] }]
    }]
  }
  expect_failures = [var.service_policies]
}

run "matcher_rejects_bad_client_selector_arm" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies = [{
      name  = "x", rule_handling = "rule_list"
      rules = [{ name = "r0", client = "cookie" }]
    }]
  }
  expect_failures = [var.service_policies]
}

# ============================================================================
# SPol-3: rule request matchers
# ============================================================================

run "request_matchers_render" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies = [{
      name = "spol3", rule_handling = "rule_list"
      rules = [{
        name         = "r0", action = "DENY"
        http_methods = ["POST", "DELETE"]
        path_prefix  = ["/admin"]
        domain_exact = ["www.f5-sales-demo.com"]
        headers      = [{ name = "x-test", presence = "match", exact_values = ["v1"] }, { name = "x-must", presence = "present" }]
        query_params = [{ key = "debug", presence = "match", exact_values = ["1"] }]
      }]
    }]
  }
  assert {
    condition     = xcsh_service_policy.this["spol3"].rule_list.rules[0].spec.http_method.methods[0] == "POST"
    error_message = "http_method must render"
  }
  assert {
    condition     = xcsh_service_policy.this["spol3"].rule_list.rules[0].spec.path.prefix_values[0] == "/admin"
    error_message = "path.prefix_values must render"
  }
  assert {
    condition     = xcsh_service_policy.this["spol3"].rule_list.rules[0].spec.headers[0].item.exact_values[0] == "v1"
    error_message = "header item exact_values must render"
  }
  assert {
    condition     = xcsh_service_policy.this["spol3"].rule_list.rules[0].spec.headers[1].check_present != null
    error_message = "header presence=present must render check_present"
  }
}

run "request_rejects_bad_http_method" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies = [{ name = "x", rule_handling = "rule_list", rules = [{ name = "r0", http_methods = ["FETCH"] }] }]
  }
  expect_failures = [var.service_policies]
}

run "request_rejects_bad_header_presence" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies = [{ name = "x", rule_handling = "rule_list", rules = [{ name = "r0", headers = [{ name = "h", presence = "maybe" }] }] }]
  }
  expect_failures = [var.service_policies]
}
