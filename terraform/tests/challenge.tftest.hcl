# Plan-level tests for the unified `challenge` variable owning the LB challenge_type oneof
# (no_challenge/enable/js/captcha/policy_based). CH-1: mode selection + js/captcha arms + MUD
# derivation. CH-2: policy_based_challenge parameter + activation oneofs. command = plan.
variables {
  namespace         = "webapp-api-protection"
  lb_domains        = ["www.f5-sales-demo.com"]
  origin_ip         = "203.0.113.10"
  origin_port       = 80
  health_check_path = "/health"
  labels            = {}
  waf_mode          = "blocking"
  csd_enabled       = false
  mud_enabled       = false
}

run "js_challenge_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    challenge = { mode = "js", cookie_expiry = 3600, custom_page = "string:///PGgxPkNoZWNr", js_script_delay = 5000 }
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.js_challenge.cookie_expiry == 3600
    error_message = "js_challenge.cookie_expiry must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.js_challenge.js_script_delay == 5000
    error_message = "js_challenge.js_script_delay must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.captcha_challenge == null && xcsh_http_loadbalancer.this.enable_challenge == null
    error_message = "only the js_challenge arm may render for mode=js"
  }
  assert {
    condition     = output.challenge_mode == "js"
    error_message = "effective challenge_mode must be js"
  }
}

run "captcha_challenge_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    challenge = { mode = "captcha", cookie_expiry = 7200 }
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.captcha_challenge.cookie_expiry == 7200
    error_message = "captcha_challenge.cookie_expiry must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.js_challenge == null
    error_message = "js_challenge arm must be absent for mode=captcha"
  }
}

run "none_omits_all_arms" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { challenge = { mode = "none" } }
  assert {
    condition     = xcsh_http_loadbalancer.this.js_challenge == null && xcsh_http_loadbalancer.this.captcha_challenge == null && xcsh_http_loadbalancer.this.enable_challenge == null && xcsh_http_loadbalancer.this.policy_based_challenge == null
    error_message = "mode=none must emit no challenge arm (server default no_challenge)"
  }
  assert {
    condition     = output.challenge_mode == "none"
    error_message = "effective challenge_mode must be none"
  }
}

run "mud_default_derives_enable_with_mitigation" {
  command = plan
  module { source = "./modules/http-lb" }
  # mud_enabled=true, challenge unset -> derive enable + attach the mitigation ref
  # (preserves the pre-unify MUD default).
  variables { mud_enabled = true }
  assert {
    condition     = output.challenge_mode == "enable"
    error_message = "mud_enabled with no explicit challenge must derive mode=enable"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.enable_challenge.malicious_user_mitigation.name == "webapp-api-protection-mud"
    error_message = "derived enable arm must attach the malicious_user_mitigation ref"
  }
}

run "explicit_enable_with_mud_attaches_ref" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    mud_enabled = true
    challenge   = { mode = "enable", attach_malicious_user_mitigation = true }
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.enable_challenge.malicious_user_mitigation.name == "webapp-api-protection-mud"
    error_message = "explicit enable + attach must reference the mitigation policy"
  }
}

run "policy_based_custom_params_render" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    challenge = {
      mode = "policy_based"
      policy_based = {
        activation         = "always_js"
        js_params          = { cookie_expiry = 1800, js_script_delay = 2000 }
        captcha_params     = { cookie_expiry = 1800 }
        temporary_blocking = { custom_page = "string:///QmxvY2tlZC4=" }
      }
    }
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.policy_based_challenge.js_challenge_parameters.js_script_delay == 2000
    error_message = "custom js_challenge_parameters must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.policy_based_challenge.captcha_challenge_parameters.cookie_expiry == 1800
    error_message = "custom captcha_challenge_parameters must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.policy_based_challenge.temporary_user_blocking != null
    error_message = "custom temporary_user_blocking must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.policy_based_challenge.always_enable_js_challenge != null
    error_message = "activation always_js must render always_enable_js_challenge"
  }
}

run "policy_based_defaults_omit_custom_arms" {
  command = plan
  module { source = "./modules/http-lb" }
  # mode=policy_based with no params -> empty policy_based_challenge (server applies default_* arms)
  variables { challenge = { mode = "policy_based" } }
  assert {
    condition     = xcsh_http_loadbalancer.this.policy_based_challenge != null
    error_message = "policy_based_challenge block must render for mode=policy_based"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.policy_based_challenge.js_challenge_parameters == null && xcsh_http_loadbalancer.this.policy_based_challenge.captcha_challenge_parameters == null && xcsh_http_loadbalancer.this.policy_based_challenge.always_enable_js_challenge == null
    error_message = "no custom arm may render when policy_based params are unset"
  }
}

run "js_script_delay_min_rejected" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { challenge = { mode = "policy_based", policy_based = { js_params = { js_script_delay = 500 } } } }
  expect_failures = [var.challenge]
}

run "policy_based_requires_policy_based_mode" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { challenge = { mode = "js", policy_based = { activation = "always_js" } } }
  expect_failures = [var.challenge]
}

run "bad_activation_rejected" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { challenge = { mode = "policy_based", policy_based = { activation = "always_everything" } } }
  expect_failures = [var.challenge]
}

run "rule_list_actions_and_matchers_render" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    challenge = {
      mode = "policy_based"
      policy_based = {
        rules = [
          {
            name         = "js-login"
            action       = "js"
            path_mode    = "exact"
            path_values  = ["/login"]
            http_methods = ["GET", "POST"]
            headers      = [{ name = "x-probe", mode = "exact", values = ["on"] }]
          },
          {
            name              = "captcha-admin"
            action            = "captcha"
            path_mode         = "regex"
            path_values       = ["^/admin/.*$"]
            client_expression = "tier in (gold)"
          },
          { name = "disable-health", action = "disable", path_mode = "exact", path_values = ["/health"] },
        ]
      }
    }
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.policy_based_challenge.rule_list.rules[0].spec.enable_javascript_challenge != null
    error_message = "rule 0 action=js must render enable_javascript_challenge"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.policy_based_challenge.rule_list.rules[0].spec.path.exact_values[0] == "/login"
    error_message = "rule 0 path exact matcher must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.policy_based_challenge.rule_list.rules[0].spec.http_method.methods[1] == "POST"
    error_message = "rule 0 http_method matcher must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.policy_based_challenge.rule_list.rules[1].spec.enable_captcha_challenge != null
    error_message = "rule 1 action=captcha must render enable_captcha_challenge"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.policy_based_challenge.rule_list.rules[1].spec.client_selector.expressions[0] == "tier in (gold)"
    error_message = "rule 1 client_selector expression must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.policy_based_challenge.rule_list.rules[2].spec.disable_challenge != null
    error_message = "rule 2 action=disable must render disable_challenge"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.policy_based_challenge.rule_list.rules[0].metadata.name == "js-login"
    error_message = "rule metadata.name must render"
  }
}

run "rule_list_omitted_without_rules" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { challenge = { mode = "policy_based", policy_based = { activation = "always_js" } } }
  assert {
    condition     = xcsh_http_loadbalancer.this.policy_based_challenge.rule_list == null
    error_message = "rule_list must be omitted when no rules are defined"
  }
}

run "bad_rule_action_rejected" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { challenge = { mode = "policy_based", policy_based = { rules = [{ name = "r", action = "block" }] } } }
  expect_failures = [var.challenge]
}

run "bad_rule_path_mode_rejected" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { challenge = { mode = "policy_based", policy_based = { rules = [{ name = "r", path_mode = "prefix" }] } } }
  expect_failures = [var.challenge]
}

run "bad_mode_rejected" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { challenge = { mode = "javascript" } }
  expect_failures = [var.challenge]
}

run "js_requires_cookie_expiry" {
  command = plan
  module { source = "./modules/http-lb" }
  # CH-4: mode=js without cookie_expiry is rejected by the API (uint32 gte 1) — caught at plan.
  variables { challenge = { mode = "js", js_script_delay = 2000 } }
  expect_failures = [var.challenge]
}

run "attach_requires_carrier_arm" {
  command = plan
  module { source = "./modules/http-lb" }
  # js arm cannot carry the mitigation ref
  variables {
    mud_enabled = true
    challenge   = { mode = "js", attach_malicious_user_mitigation = true }
  }
  expect_failures = [var.challenge]
}

run "attach_requires_mud_enabled" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    mud_enabled = false
    challenge   = { mode = "enable", attach_malicious_user_mitigation = true }
  }
  # cross-variable rule (attach needs the mitigation resource) -> LB lifecycle precondition
  expect_failures = [xcsh_http_loadbalancer.this]
}
