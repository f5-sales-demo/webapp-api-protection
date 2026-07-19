# Plan-level tests for CH-1: the unified `challenge` variable owning the LB challenge_type
# oneof (no_challenge/enable/js/captcha/policy_based). command = plan, targets ./modules/http-lb.
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

run "bad_mode_rejected" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { challenge = { mode = "javascript" } }
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
