# Plan-level tests for the full rate-limiting surface (Coverage Batch B):
# standalone xcsh_rate_limiter (Stage 1), xcsh_rate_limiter_policy (Stage 2),
# LB rate_limit allow-lists/policies (Stage 3), and the api_rate_limit arm (Stage 4).
# Targets ./modules/http-lb. Defaults keep everything off (0-change).
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

# --- Stage 1: standalone xcsh_rate_limiter ---

run "rate_limiter_none_by_default" {
  command = plan
  module { source = "./modules/http-lb" }
  assert {
    condition     = output.rate_limiter_count == 0
    error_message = "no standalone rate limiters by default (0-change)"
  }
}

run "rate_limiter_basic_render" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limiters = [{
      name   = "rl-basic"
      limits = [{ total_number = 100, unit = "MINUTE" }]
    }]
  }
  assert {
    condition     = output.rate_limiter_count == 1 && contains(output.rate_limiter_names, "rl-basic")
    error_message = "rl-basic must render one xcsh_rate_limiter"
  }
  assert {
    condition     = xcsh_rate_limiter.this["rl-basic"].limits[0].total_number == 100
    error_message = "limits.total_number must plumb through"
  }
}

run "rate_limiter_action_block_and_token_bucket" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limiters = [{
      name = "rl-strict"
      limits = [{
        total_number          = 10
        unit                  = "SECOND"
        action                = "block"
        action_block_unit     = "minutes"
        action_block_duration = 5
        algorithm             = "token_bucket"
      }]
    }]
  }
  assert {
    condition     = xcsh_rate_limiter.this["rl-strict"].limits[0].action_block != null && xcsh_rate_limiter.this["rl-strict"].limits[0].action_block.minutes.duration == 5 && xcsh_rate_limiter.this["rl-strict"].limits[0].action_block.hours == null
    error_message = "action=block/minutes must render action_block.minutes.duration=5 and no hours"
  }
  assert {
    condition     = xcsh_rate_limiter.this["rl-strict"].limits[0].token_bucket != null && xcsh_rate_limiter.this["rl-strict"].limits[0].leaky_bucket == null
    error_message = "algorithm=token_bucket must render token_bucket only"
  }
}

run "rate_limiter_multiple_unique" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limiters = [
      { name = "rl-a", limits = [{ total_number = 5, unit = "SECOND" }] },
      { name = "rl-b", limits = [{ total_number = 50, unit = "HOUR" }] },
    ]
  }
  assert {
    condition     = output.rate_limiter_count == 2
    error_message = "two distinct rate limiters must render"
  }
}

# --- Stage 1 validation failures ---

run "rate_limiter_rejects_day_unit" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limiters = [{ name = "rl-day", limits = [{ total_number = 1, unit = "DAY" }] }]
  }
  expect_failures = [var.rate_limiters]
}

run "rate_limiter_rejects_duplicate_names" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limiters = [
      { name = "dup", limits = [{ total_number = 1 }] },
      { name = "dup", limits = [{ total_number = 2 }] },
    ]
  }
  expect_failures = [var.rate_limiters]
}

run "rate_limiter_rejects_block_without_duration" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limiters = [{ name = "rl-bad", limits = [{ total_number = 1, action = "block" }] }]
  }
  expect_failures = [var.rate_limiters]
}

run "rate_limiter_rejects_bad_algorithm" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limiters = [{ name = "rl-bad", limits = [{ total_number = 1, algorithm = "sieve" }] }]
  }
  expect_failures = [var.rate_limiters]
}

run "rate_limiter_rejects_zero_total" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limiters = [{ name = "rl-zero", limits = [{ total_number = 0 }] }]
  }
  expect_failures = [var.rate_limiters]
}

# --- Stage 2: standalone xcsh_rate_limiter_policy ---

run "rate_limiter_policy_none_by_default" {
  command = plan
  module { source = "./modules/http-lb" }
  assert {
    condition     = output.rate_limiter_policy_count == 0
    error_message = "no rate-limiter policies by default (0-change)"
  }
}

run "rate_limiter_policy_apply_any_server" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limiter_policies = [{
      name  = "rlp-basic"
      rules = [{ name = "r1", action = "apply", http_methods = ["GET", "POST"] }]
    }]
  }
  assert {
    condition     = output.rate_limiter_policy_count == 1 && contains(output.rate_limiter_policy_names, "rlp-basic")
    error_message = "rlp-basic must render one policy"
  }
  assert {
    condition     = xcsh_rate_limiter_policy.this["rlp-basic"].any_server != null
    error_message = "default server_scope must render any_server"
  }
  assert {
    condition     = xcsh_rate_limiter_policy.this["rlp-basic"].rules[0].spec.apply_rate_limiter != null && toset(xcsh_rate_limiter_policy.this["rlp-basic"].rules[0].spec.http_method.methods) == toset(["GET", "POST"])
    error_message = "rule must render apply_rate_limiter + http_method"
  }
}

run "rate_limiter_policy_custom_and_matchers" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limiters = [{ name = "rl-x", limits = [{ total_number = 5, unit = "SECOND" }] }]
    rate_limiter_policies = [{
      name              = "rlp-custom"
      server_scope      = "name_matcher"
      server_name_exact = ["api.f5-sales-demo.com"]
      rules = [{
        name                = "deny-legacy"
        action              = "custom"
        custom_rate_limiter = "rl-x"
        ip                  = "prefix_list"
        ip_prefixes         = ["10.0.0.0/8"]
        country             = "list"
        countries           = ["COUNTRY_US", "COUNTRY_CA"]
        path_prefixes       = ["/api/legacy"]
        headers             = [{ name = "x-debug", presence = "present" }]
      }]
    }]
  }
  assert {
    condition     = toset(xcsh_rate_limiter_policy.this["rlp-custom"].server_name_matcher.exact_values) == toset(["api.f5-sales-demo.com"])
    error_message = "server_scope=name_matcher must render server_name_matcher"
  }
  assert {
    condition     = xcsh_rate_limiter_policy.this["rlp-custom"].rules[0].spec.custom_rate_limiter.name == "rl-x"
    error_message = "action=custom must reference the rl-x rate limiter"
  }
  assert {
    condition     = toset(xcsh_rate_limiter_policy.this["rlp-custom"].rules[0].spec.ip_prefix_list.ip_prefixes) == toset(["10.0.0.0/8"]) && toset(xcsh_rate_limiter_policy.this["rlp-custom"].rules[0].spec.country_list.country_codes) == toset(["COUNTRY_US", "COUNTRY_CA"])
    error_message = "ip=prefix_list + country=list must render inline matchers"
  }
  assert {
    condition     = xcsh_rate_limiter_policy.this["rlp-custom"].rules[0].spec.headers[0].check_present != null
    error_message = "headers presence=present must render check_present"
  }
}

run "rate_limiter_policy_selector_and_ref_matchers" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limiter_policies = [{
      name            = "rlp-sel"
      server_scope    = "selector"
      server_selector = ["app in (api)"]
      rules = [{
        name     = "asn-ip-ref"
        action   = "bypass"
        asn      = "matcher"
        asn_sets = [{ name = "corp-asns" }]
        ip       = "matcher"
        ip_sets  = [{ name = "corp-prefixes" }]
      }]
    }]
  }
  assert {
    condition     = toset(xcsh_rate_limiter_policy.this["rlp-sel"].server_selector.expressions) == toset(["app in (api)"])
    error_message = "server_scope=selector must render server_selector"
  }
  assert {
    condition     = xcsh_rate_limiter_policy.this["rlp-sel"].rules[0].spec.bypass_rate_limiter != null && xcsh_rate_limiter_policy.this["rlp-sel"].rules[0].spec.asn_matcher != null && xcsh_rate_limiter_policy.this["rlp-sel"].rules[0].spec.ip_matcher != null
    error_message = "bypass + asn_matcher + ip_matcher (ref sets) must render"
  }
}

# --- Stage 2 validation failures ---

run "rate_limiter_policy_rejects_bad_server_scope" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limiter_policies = [{ name = "bad", server_scope = "everything" }]
  }
  expect_failures = [var.rate_limiter_policies]
}

run "rate_limiter_policy_rejects_bad_action" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limiter_policies = [{ name = "bad", rules = [{ name = "r", action = "throttle" }] }]
  }
  expect_failures = [var.rate_limiter_policies]
}

run "rate_limiter_policy_rejects_custom_without_ref" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limiter_policies = [{ name = "bad", rules = [{ name = "r", action = "custom" }] }]
  }
  expect_failures = [var.rate_limiter_policies]
}

run "rate_limiter_policy_rejects_dup_rule_names" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limiter_policies = [{ name = "p", rules = [{ name = "r", action = "apply" }, { name = "r", action = "bypass" }] }]
  }
  expect_failures = [var.rate_limiter_policies]
}

run "rate_limiter_policy_rejects_custom_missing_limiter" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    # action=custom references rl-missing, which is not in var.rate_limiters -> precondition fails
    rate_limiter_policies = [{ name = "p", rules = [{ name = "r", action = "custom", custom_rate_limiter = "rl-missing" }] }]
  }
  expect_failures = [xcsh_rate_limiter_policy.this]
}

run "rate_limiter_policy_rejects_bare_country_code" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limiter_policies = [{ name = "p", rules = [{ name = "r", action = "apply", country = "list", countries = ["US"] }] }]
  }
  expect_failures = [var.rate_limiter_policies]
}

# --- Stage 3: LB rate_limit allow-lists + policy refs ---

run "rate_limit_default_no_lists" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { rate_limit_choice = "rate_limit" }
  assert {
    condition     = xcsh_http_loadbalancer.this.rate_limit.no_ip_allowed_list != null && xcsh_http_loadbalancer.this.rate_limit.no_policies != null
    error_message = "rate_limit defaults must render no_ip_allowed_list + no_policies (0-change vs SP3)"
  }
}

run "rate_limit_inline_ip_allowed_list" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limit_choice              = "rate_limit"
    rate_limit_ip_allowed_prefixes = ["192.0.2.0/24", "198.51.100.0/24"]
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.rate_limit.ip_allowed_list != null && toset(xcsh_http_loadbalancer.this.rate_limit.ip_allowed_list.prefixes) == toset(["192.0.2.0/24", "198.51.100.0/24"]) && xcsh_http_loadbalancer.this.rate_limit.no_ip_allowed_list == null
    error_message = "inline prefixes must render ip_allowed_list, not no_ip_allowed_list"
  }
}

run "rate_limit_custom_ip_allowed_list" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limit_choice                = "rate_limit"
    rate_limit_custom_ip_prefix_sets = [{ name = "corp-prefixes" }]
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.rate_limit.custom_ip_allowed_list != null && xcsh_http_loadbalancer.this.rate_limit.custom_ip_allowed_list.rate_limiter_allowed_prefixes[0].name == "corp-prefixes"
    error_message = "custom sets must render custom_ip_allowed_list.rate_limiter_allowed_prefixes"
  }
}

run "rate_limit_with_policies" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limit_choice      = "rate_limit"
    rate_limit_policy_refs = ["rlp-a"]
    rate_limiter_policies  = [{ name = "rlp-a", rules = [{ name = "r", action = "apply" }] }]
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.rate_limit.policies != null && xcsh_http_loadbalancer.this.rate_limit.policies.policies[0].name == "rlp-a" && xcsh_http_loadbalancer.this.rate_limit.no_policies == null
    error_message = "policy refs must render policies.policies, not no_policies"
  }
}

# --- Stage 3 validation / precondition failures ---

run "rate_limit_rejects_both_ip_lists" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limit_choice                = "rate_limit"
    rate_limit_ip_allowed_prefixes   = ["192.0.2.0/24"]
    rate_limit_custom_ip_prefix_sets = [{ name = "corp" }]
  }
  expect_failures = [xcsh_http_loadbalancer.this]
}

run "rate_limit_rejects_policy_ref_without_arm" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limit_choice      = "disable"
    rate_limit_policy_refs = ["rlp-a"]
    rate_limiter_policies  = [{ name = "rlp-a", rules = [{ name = "r", action = "apply" }] }]
  }
  expect_failures = [xcsh_http_loadbalancer.this]
}

run "rate_limit_rejects_unknown_policy_ref" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limit_choice      = "rate_limit"
    rate_limit_policy_refs = ["ghost"]
  }
  expect_failures = [xcsh_http_loadbalancer.this]
}

# --- Stage 4: LB api_rate_limit arm (per-endpoint) ---

run "api_rate_limit_endpoint_ref_and_matchers" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limit_choice = "api_rate_limit"
    rate_limiters     = [{ name = "rl-api", limits = [{ total_number = 10, unit = "MINUTE" }] }]
    api_rate_limit_endpoint_rules = [{
      api_endpoint_path = "/api/orders"
      methods           = ["POST"]
      ref_rate_limiter  = "rl-api"
      client_matcher = {
        mode        = "ip_prefix_list"
        ip_prefixes = ["203.0.113.0/24"]
      }
      request_matcher = {
        headers = [{ name = "x-tenant", presence = "present" }]
      }
    }]
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.api_rate_limit != null && xcsh_http_loadbalancer.this.rate_limit == null
    error_message = "rate_limit_choice=api_rate_limit must render api_rate_limit, not rate_limit"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.api_rate_limit.api_endpoint_rules[0].ref_rate_limiter.name == "rl-api" && xcsh_http_loadbalancer.this.api_rate_limit.api_endpoint_rules[0].api_endpoint_path == "/api/orders"
    error_message = "endpoint rule must reference rl-api on /api/orders"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.api_rate_limit.api_endpoint_rules[0].client_matcher.ip_prefix_list != null && xcsh_http_loadbalancer.this.api_rate_limit.api_endpoint_rules[0].any_domain != null
    error_message = "endpoint rule must render ip_prefix_list client_matcher + any_domain default"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.api_rate_limit.api_endpoint_rules[0].request_matcher.headers[0].check_present != null
    error_message = "request_matcher header presence=present must render check_present"
  }
}

run "api_rate_limit_endpoint_inline_and_asn_matcher" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limit_choice = "api_rate_limit"
    api_rate_limit_endpoint_rules = [{
      api_endpoint_path = "/api/login"
      specific_domain   = "api.f5-sales-demo.com"
      inline_threshold  = 5
      inline_unit       = "MINUTE"
      client_matcher = {
        mode     = "asn_matcher"
        asn_sets = [{ name = "corp-asns" }]
      }
    }]
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.api_rate_limit.api_endpoint_rules[0].inline_rate_limiter.threshold == 5 && xcsh_http_loadbalancer.this.api_rate_limit.api_endpoint_rules[0].inline_rate_limiter.use_http_lb_user_id != null
    error_message = "inline limiter must render threshold + use_http_lb_user_id default"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.api_rate_limit.api_endpoint_rules[0].specific_domain == "api.f5-sales-demo.com" && xcsh_http_loadbalancer.this.api_rate_limit.api_endpoint_rules[0].client_matcher.asn_matcher != null
    error_message = "specific_domain attr + asn_matcher ref must render"
  }
}

run "api_rate_limit_bypass_and_server_url" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limit_choice = "api_rate_limit"
    rate_limiters     = [{ name = "rl-su", limits = [{ total_number = 20, unit = "MINUTE" }] }]
    api_rate_limit_endpoint_rules = [{
      api_endpoint_path = "/api/x"
      inline_threshold  = 1
    }]
    api_rate_limit_bypass_rules = [{
      base_path        = "/api/health"
      target           = "api_endpoint"
      endpoint_path    = "/api/health"
      endpoint_methods = ["GET"]
    }]
    api_rate_limit_server_url_rules = [{
      base_path        = "/api/v2"
      ref_rate_limiter = "rl-su"
      client_matcher   = { mode = "tls_fingerprint_matcher", tls_classes = ["Automated"] }
    }]
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.api_rate_limit.bypass_rate_limiting_rules.bypass_rate_limiting_rules[0].api_endpoint != null
    error_message = "bypass rule target=api_endpoint must render api_endpoint"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.api_rate_limit.server_url_rules[0].ref_rate_limiter.name == "rl-su" && xcsh_http_loadbalancer.this.api_rate_limit.server_url_rules[0].client_matcher.tls_fingerprint_matcher != null
    error_message = "server_url rule must render ref limiter + tls_fingerprint_matcher"
  }
}

# --- Stage 4 validation / precondition failures ---

run "api_rate_limit_rejects_both_limiters" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limit_choice             = "api_rate_limit"
    rate_limiters                 = [{ name = "rl", limits = [{ total_number = 1 }] }]
    api_rate_limit_endpoint_rules = [{ api_endpoint_path = "/x", ref_rate_limiter = "rl", inline_threshold = 5 }]
  }
  expect_failures = [var.api_rate_limit_endpoint_rules]
}

run "api_rate_limit_rejects_neither_limiter" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limit_choice             = "api_rate_limit"
    api_rate_limit_endpoint_rules = [{ api_endpoint_path = "/x" }]
  }
  expect_failures = [var.api_rate_limit_endpoint_rules]
}

run "api_rate_limit_rejects_bad_bypass_target" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limit_choice           = "api_rate_limit"
    api_rate_limit_bypass_rules = [{ base_path = "/x", target = "whatever" }]
  }
  expect_failures = [var.api_rate_limit_bypass_rules]
}

run "api_rate_limit_rejects_rules_without_arm" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limit_choice             = "rate_limit"
    api_rate_limit_endpoint_rules = [{ api_endpoint_path = "/x", inline_threshold = 1 }]
  }
  expect_failures = [xcsh_http_loadbalancer.this]
}

run "api_rate_limit_rejects_unknown_ref" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limit_choice             = "api_rate_limit"
    api_rate_limit_endpoint_rules = [{ api_endpoint_path = "/x", ref_rate_limiter = "ghost" }]
  }
  expect_failures = [xcsh_http_loadbalancer.this]
}

# --- Review-driven negative coverage (Batch B) ---

run "server_url_rejects_both_limiters" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limit_choice               = "api_rate_limit"
    rate_limiters                   = [{ name = "rl", limits = [{ total_number = 1 }] }]
    api_rate_limit_server_url_rules = [{ base_path = "/v2", ref_rate_limiter = "rl", inline_threshold = 5 }]
  }
  expect_failures = [var.api_rate_limit_server_url_rules]
}

run "server_url_rejects_bad_inline_unit" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limit_choice               = "api_rate_limit"
    api_rate_limit_server_url_rules = [{ base_path = "/v2", inline_threshold = 5, inline_unit = "DAY" }]
  }
  expect_failures = [var.api_rate_limit_server_url_rules]
}

run "server_url_rejects_ref_user_without_ref" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limit_choice               = "api_rate_limit"
    api_rate_limit_server_url_rules = [{ base_path = "/v2", inline_threshold = 5, inline_user_id = "ref" }]
  }
  expect_failures = [var.api_rate_limit_server_url_rules]
}

run "bypass_rejects_bad_client_matcher_mode" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limit_choice           = "api_rate_limit"
    api_rate_limit_bypass_rules = [{ target = "any_url", client_matcher = { mode = "ip_prefixlist" } }]
  }
  expect_failures = [var.api_rate_limit_bypass_rules]
}

run "bypass_rejects_base_path_target_without_base_path" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limit_choice           = "api_rate_limit"
    api_rate_limit_bypass_rules = [{ target = "base_path" }]
  }
  expect_failures = [var.api_rate_limit_bypass_rules]
}

run "bypass_rejects_api_groups_target_without_groups" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limit_choice           = "api_rate_limit"
    api_rate_limit_bypass_rules = [{ target = "api_groups" }]
  }
  expect_failures = [var.api_rate_limit_bypass_rules]
}

run "endpoint_rejects_client_matcher_empty_payload" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limit_choice = "api_rate_limit"
    api_rate_limit_endpoint_rules = [{
      api_endpoint_path = "/x"
      inline_threshold  = 1
      client_matcher    = { mode = "ip_prefix_list" } # ip_prefixes empty
    }]
  }
  expect_failures = [var.api_rate_limit_endpoint_rules]
}

run "policy_rejects_list_arm_empty_payload" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limiter_policies = [{ name = "p", rules = [{ name = "r", action = "apply", asn = "list" }] }] # asn_numbers empty
  }
  expect_failures = [var.rate_limiter_policies]
}

run "api_rate_limit_arm_rejects_empty" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { rate_limit_choice = "api_rate_limit" } # no rules of any kind
  expect_failures = [xcsh_http_loadbalancer.this]
}

run "rate_limit_ip_allowed_rejects_off_arm" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limit_choice              = "api_rate_limit"
    rate_limit_ip_allowed_prefixes = ["192.0.2.0/24"]
    api_rate_limit_endpoint_rules  = [{ api_endpoint_path = "/x", inline_threshold = 1 }]
  }
  expect_failures = [xcsh_http_loadbalancer.this]
}

run "server_url_client_matcher_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    rate_limit_choice = "api_rate_limit"
    api_rate_limit_server_url_rules = [{
      base_path        = "/v3"
      inline_threshold = 10
      client_matcher   = { mode = "ip_prefix_list", ip_prefixes = ["10.1.0.0/16"] }
    }]
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.api_rate_limit.server_url_rules[0].client_matcher.ip_prefix_list != null
    error_message = "server_url client_matcher must render (positive coverage for the bypass/server_url matcher path)"
  }
}
