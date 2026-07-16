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
