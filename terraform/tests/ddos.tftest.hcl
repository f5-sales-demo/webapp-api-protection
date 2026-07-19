# Plan-level tests for DDoS-1: l7_ddos_protection. The module emits only non-default arms
# (custom rps_threshold, js/captcha clientside_action); the server materializes the default
# markers (default_rps_threshold / clientside_action_none / mitigation_block / ddos_policy_none),
# import-suppressed by the provider (#1155). command = plan, targets ./modules/http-lb.
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

run "omitted_by_default" {
  command = plan
  module { source = "./modules/http-lb" }
  assert {
    condition     = xcsh_http_loadbalancer.this.l7_ddos_protection == null
    error_message = "l7_ddos_protection must be omitted unless ddos.l7_enabled"
  }
}

run "custom_rps_js_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    ddos = {
      l7_enabled         = true
      rps_threshold      = 2500
      clientside_action  = "js"
      cs_cookie_expiry   = 3600
      cs_js_script_delay = 2000
    }
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.l7_ddos_protection.rps_threshold == 2500
    error_message = "custom rps_threshold must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.l7_ddos_protection.clientside_action_js_challenge.js_script_delay == 2000
    error_message = "clientside_action_js_challenge must render for js"
  }
  # default markers are NOT emitted by the module (server materializes + provider suppresses them)
  assert {
    condition     = xcsh_http_loadbalancer.this.l7_ddos_protection.clientside_action_captcha_challenge == null
    error_message = "captcha arm must be absent for clientside_action=js"
  }
}

run "captcha_default_rps_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    ddos = {
      l7_enabled        = true
      clientside_action = "captcha"
      cs_cookie_expiry  = 7200
    }
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.l7_ddos_protection.clientside_action_captcha_challenge.cookie_expiry == 7200
    error_message = "clientside_action_captcha_challenge must render for captcha"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.l7_ddos_protection.rps_threshold == null
    error_message = "rps_threshold must be null (server default) when unset"
  }
}

run "enabled_minimal_renders_block" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { ddos = { l7_enabled = true } }
  # minimal: block present, no custom arms (server applies all defaults)
  assert {
    condition     = xcsh_http_loadbalancer.this.l7_ddos_protection != null
    error_message = "l7_ddos_protection must render when l7_enabled"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.l7_ddos_protection.clientside_action_js_challenge == null && xcsh_http_loadbalancer.this.l7_ddos_protection.rps_threshold == null
    error_message = "minimal l7_ddos_protection must emit no custom arm"
  }
}

run "mitigation_rules_source_arms_render" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    ddos = {
      mitigation_rules = [
        { name = "block-cn", source = "country", countries = ["COUNTRY_CN", "COUNTRY_RU"] },
        { name = "block-asn", source = "asn", as_numbers = [64512, 64513] },
        { name = "block-ip", source = "ip", ip_prefixes = ["203.0.113.0/24"], ip_invert = true },
        { name = "block-tls", source = "tls", tls_classes = ["TRICKBOT"] },
      ]
    }
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.ddos_mitigation_rules[0].ddos_client_source.country_list[0] == "COUNTRY_CN"
    error_message = "country source arm must render country_list"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.ddos_mitigation_rules[0].metadata.name == "block-cn"
    error_message = "rule metadata.name must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.ddos_mitigation_rules[0].block != null
    error_message = "block action must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.ddos_mitigation_rules[1].ddos_client_source.asn_list.as_numbers[0] == 64512
    error_message = "asn source arm must render asn_list.as_numbers"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.ddos_mitigation_rules[2].ip_prefix_list.invert_match == true
    error_message = "ip source arm must render rule-level ip_prefix_list.invert_match"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.ddos_mitigation_rules[3].ddos_client_source.tls_fingerprint_matcher.classes[0] == "TRICKBOT"
    error_message = "tls source arm must render tls_fingerprint_matcher.classes"
  }
}

run "mitigation_rules_omitted_by_default" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { ddos = {} }
  assert {
    condition     = length(xcsh_http_loadbalancer.this.ddos_mitigation_rules) == 0
    error_message = "ddos_mitigation_rules must be empty by default"
  }
}

run "bad_mitigation_source_rejected" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { ddos = { mitigation_rules = [{ name = "r", source = "user_agent" }] } }
  expect_failures = [var.ddos]
}

run "bad_clientside_action_rejected" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { ddos = { l7_enabled = true, clientside_action = "block" } }
  expect_failures = [var.ddos]
}

run "bad_rps_threshold_rejected" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { ddos = { l7_enabled = true, rps_threshold = 0 } }
  expect_failures = [var.ddos]
}
