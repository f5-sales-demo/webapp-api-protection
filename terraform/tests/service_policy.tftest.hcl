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

# --- SPol-2b: ref matcher arms (asn_matcher -> bgp_asn_set, ip_matcher -> ip_prefix_set) ---
run "ref_matchers_render" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policy_bgp_asn_sets   = [{ name = "m-asn", as_numbers = [64512] }]
    service_policy_ip_prefix_sets = [{ name = "m-ip", ipv4_prefixes = ["10.0.0.0/8"] }]
    service_policies = [{
      name  = "spol2b", rule_handling = "rule_list"
      rules = [{ name = "r0", action = "DENY", asn = "matcher", asn_sets = ["m-asn"], ip = "matcher", ip_prefix_sets = ["m-ip"], ip_invert = true }]
    }]
  }
  assert {
    condition     = xcsh_service_policy.this["spol2b"].rule_list.rules[0].spec.asn_matcher.asn_sets[0].name == "m-asn"
    error_message = "asn_matcher must reference the bgp_asn_set by name"
  }
  assert {
    condition     = xcsh_service_policy.this["spol2b"].rule_list.rules[0].spec.ip_matcher.prefix_sets[0].name == "m-ip"
    error_message = "ip_matcher must reference the ip_prefix_set by name"
  }
  assert {
    condition     = xcsh_service_policy.this["spol2b"].rule_list.rules[0].spec.ip_matcher.invert_matcher == true
    error_message = "ip_matcher invert_matcher must render from ip_invert"
  }
  assert {
    condition     = xcsh_bgp_asn_set.this["m-asn"].as_numbers[0] == 64512
    error_message = "bgp_asn_set ref object must be created"
  }
}

run "ref_asn_matcher_rejects_empty_sets" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies = [{ name = "x", rule_handling = "rule_list", rules = [{ name = "r0", asn = "matcher" }] }]
  }
  expect_failures = [var.service_policies]
}

run "ref_asn_matcher_rejects_undefined_set" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policy_bgp_asn_sets = [{ name = "known", as_numbers = [64512] }]
    service_policies            = [{ name = "x", rule_handling = "rule_list", rules = [{ name = "r0", asn = "matcher", asn_sets = ["ghost"] }] }]
  }
  expect_failures = [var.service_policies]
}

run "ref_ip_matcher_rejects_undefined_set" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies = [{ name = "x", rule_handling = "rule_list", rules = [{ name = "r0", ip = "matcher", ip_prefix_sets = ["ghost"] }] }]
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

# ============================================================================
# SPol-4a: rule action-side (waf_action / bot_action / mum_action)
# ============================================================================

run "action_skip_arms_render" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies = [{
      name  = "spol4", rule_handling = "rule_list"
      rules = [{ name = "r0", action = "ALLOW", waf_action_mode = "skip", bot_action_mode = "skip", mum_action_mode = "skip" }]
    }]
  }
  assert {
    condition     = xcsh_service_policy.this["spol4"].rule_list.rules[0].spec.waf_action.waf_skip_processing != null
    error_message = "waf_action skip must render waf_skip_processing"
  }
  assert {
    condition     = xcsh_service_policy.this["spol4"].rule_list.rules[0].spec.bot_action.bot_skip_processing != null
    error_message = "bot_action skip must render bot_skip_processing"
  }
  assert {
    condition     = xcsh_service_policy.this["spol4"].rule_list.rules[0].spec.mum_action.skip_processing != null
    error_message = "mum_action skip must render skip_processing"
  }
}

# waf skip with bot/mum OMITTED under ALLOW is valid (bot/mum are independent of waf —
# the SPol-4a all-or-nothing precondition was a misdiagnosis of the DENY rejection).
run "action_skip_omit_bot_mum_render" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies = [{
      name  = "spol4i", rule_handling = "rule_list"
      rules = [{ name = "r0", action = "ALLOW", waf_action_mode = "skip" }]
    }]
  }
  assert {
    condition     = xcsh_service_policy.this["spol4i"].rule_list.rules[0].spec.waf_action.waf_skip_processing != null
    error_message = "waf skip with omitted bot/mum must render"
  }
  assert {
    condition     = xcsh_service_policy.this["spol4i"].rule_list.rules[0].spec.bot_action == null && xcsh_service_policy.this["spol4i"].rule_list.rules[0].spec.mum_action == null
    error_message = "omitted bot/mum must stay null alongside waf skip"
  }
}

run "action_default_waf_none_no_bot_mum" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies = [{ name = "spol4d", rule_handling = "rule_list", rules = [{ name = "r0", action = "DENY" }] }]
  }
  assert {
    condition     = xcsh_service_policy.this["spol4d"].rule_list.rules[0].spec.waf_action.none != null
    error_message = "default waf_action must be none"
  }
  assert {
    condition     = xcsh_service_policy.this["spol4d"].rule_list.rules[0].spec.bot_action == null && xcsh_service_policy.this["spol4d"].rule_list.rules[0].spec.mum_action == null
    error_message = "default bot_action/mum_action must be omitted (null)"
  }
}

run "action_rejects_bad_waf_mode" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies = [{ name = "x", rule_handling = "rule_list", rules = [{ name = "r0", waf_action_mode = "block" }] }]
  }
  expect_failures = [var.service_policies]
}

# A configured WAF action (skip or detection_control) on a DENY rule is rejected by F5 XC.
run "action_rejects_waf_on_deny" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies = [{ name = "x", rule_handling = "rule_list", rules = [{ name = "r0", action = "DENY", waf_action_mode = "skip" }] }]
  }
  expect_failures = [var.service_policies]
}

# --- SPol-4b: detection_control renders all four exclusion lists ---
run "detection_control_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies = [{
      name          = "spol4b-dc"
      rule_handling = "rule_list"
      rules = [{
        name                             = "r0", action = "ALLOW", waf_action_mode = "detection_control"
        waf_exclude_attack_type_contexts = [{ context = "CONTEXT_ANY", exclude_attack_type = "ATTACK_TYPE_SQL_INJECTION" }]
        waf_exclude_violation_contexts   = [{ context = "CONTEXT_HEADER", context_name = "x-h", exclude_violation = "VIOL_JSON_MALFORMED" }]
        waf_exclude_signature_contexts   = [{ context = "CONTEXT_URL", signature_id = 200000001 }]
        waf_exclude_bot_names            = ["curl"]
      }]
    }]
  }
  assert {
    condition     = xcsh_service_policy.this["spol4b-dc"].rule_list.rules[0].spec.waf_action.app_firewall_detection_control.exclude_attack_type_contexts[0].exclude_attack_type == "ATTACK_TYPE_SQL_INJECTION"
    error_message = "detection_control attack-type exclusion must render"
  }
  assert {
    condition     = xcsh_service_policy.this["spol4b-dc"].rule_list.rules[0].spec.waf_action.app_firewall_detection_control.exclude_bot_name_contexts[0].bot_name == "curl"
    error_message = "detection_control bot-name exclusion must render"
  }
  assert {
    condition     = xcsh_service_policy.this["spol4b-dc"].rule_list.rules[0].spec.waf_action.app_firewall_detection_control.exclude_signature_contexts[0].signature_id == 200000001
    error_message = "detection_control signature exclusion must render"
  }
}

# --- SPol-4b: segment_policy markers render ---
run "segment_policy_markers_render" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies = [{
      name          = "spol4b-seg"
      rule_handling = "rule_list"
      rules         = [{ name = "r0", action = "DENY", segment_src = "any", segment_dst = "any" }]
    }]
  }
  assert {
    condition     = xcsh_service_policy.this["spol4b-seg"].rule_list.rules[0].spec.segment_policy.src_any != null && xcsh_service_policy.this["spol4b-seg"].rule_list.rules[0].spec.segment_policy.dst_any != null
    error_message = "segment_policy src_any/dst_any markers must render"
  }
}

run "segment_policy_omitted_by_default" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies = [{ name = "spol4b-nseg", rule_handling = "rule_list", rules = [{ name = "r0", action = "DENY" }] }]
  }
  assert {
    condition     = xcsh_service_policy.this["spol4b-nseg"].rule_list.rules[0].spec.segment_policy == null
    error_message = "segment_policy must be omitted (null) when no marker selected"
  }
}

# --- SPol-4b: request_constraints emits exceeds where set + none markers elsewhere ---
run "request_constraints_render" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies = [{
      name          = "spol4b-rc"
      rule_handling = "rule_list"
      rules         = [{ name = "r0", action = "DENY", request_constraints_enabled = true, max_url_size = 2048 }]
    }]
  }
  assert {
    condition     = xcsh_service_policy.this["spol4b-rc"].rule_list.rules[0].spec.request_constraints.max_url_size_exceeds == 2048
    error_message = "request_constraints set dimension must render max_*_exceeds"
  }
  assert {
    condition     = xcsh_service_policy.this["spol4b-rc"].rule_list.rules[0].spec.request_constraints.max_cookie_count_none != null
    error_message = "request_constraints unset dimension must render max_*_none marker"
  }
}

run "request_constraints_omitted_by_default" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies = [{ name = "spol4b-nrc", rule_handling = "rule_list", rules = [{ name = "r0", action = "DENY" }] }]
  }
  assert {
    condition     = xcsh_service_policy.this["spol4b-nrc"].rule_list.rules[0].spec.request_constraints == null
    error_message = "request_constraints must be omitted (null) when not enabled"
  }
}

# --- SPol-4b validation rejections ---
run "detection_control_rejects_deny" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies = [{ name = "x", rule_handling = "rule_list", rules = [{ name = "r0", action = "DENY", waf_action_mode = "detection_control", waf_exclude_bot_names = ["curl"] }] }]
  }
  expect_failures = [var.service_policies]
}

run "detection_control_rejects_empty" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies = [{ name = "x", rule_handling = "rule_list", rules = [{ name = "r0", action = "ALLOW", waf_action_mode = "detection_control" }] }]
  }
  expect_failures = [var.service_policies]
}

run "detection_control_rejects_exclusions_without_mode" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies = [{ name = "x", rule_handling = "rule_list", rules = [{ name = "r0", action = "DENY", waf_exclude_bot_names = ["curl"] }] }]
  }
  expect_failures = [var.service_policies]
}

run "detection_control_rejects_bad_context" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies = [{ name = "x", rule_handling = "rule_list", rules = [{ name = "r0", action = "ALLOW", waf_action_mode = "detection_control", waf_exclude_violation_contexts = [{ context = "CONTEXT_BOGUS", exclude_violation = "VIOL_NONE" }] }] }]
  }
  expect_failures = [var.service_policies]
}

run "detection_control_rejects_bad_attack_type" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies = [{ name = "x", rule_handling = "rule_list", rules = [{ name = "r0", action = "ALLOW", waf_action_mode = "detection_control", waf_exclude_attack_type_contexts = [{ exclude_attack_type = "ATTACK_TYPE_BOGUS" }] }] }]
  }
  expect_failures = [var.service_policies]
}

run "detection_control_rejects_bad_signature_id" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies = [{ name = "x", rule_handling = "rule_list", rules = [{ name = "r0", action = "ALLOW", waf_action_mode = "detection_control", waf_exclude_signature_contexts = [{ signature_id = 42 }] }] }]
  }
  expect_failures = [var.service_policies]
}

run "segment_policy_rejects_bad_src" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    service_policies = [{ name = "x", rule_handling = "rule_list", rules = [{ name = "r0", action = "DENY", segment_src = "segments" }] }]
  }
  expect_failures = [var.service_policies]
}
