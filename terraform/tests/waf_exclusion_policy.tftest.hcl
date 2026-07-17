# Plan-level tests for LPC-4b: standalone xcsh_waf_exclusion_policy + LB waf_exclusion_policy
# ref arm. Targets ./modules/http-lb. command = plan (no creds).
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

run "standalone_policy_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    waf_exclusion_policies = [{
      name = "excl-pol-a"
      rules = [{
        name       = "skip-probe"
        path       = "prefix"
        path_value = "/probe"
        action     = "skip"
      }]
    }]
  }
  assert {
    condition     = xcsh_waf_exclusion_policy.this["excl-pol-a"].name == "excl-pol-a"
    error_message = "standalone policy name must render"
  }
  assert {
    condition     = xcsh_waf_exclusion_policy.this["excl-pol-a"].waf_exclusion_rules[0].path_prefix == "/probe"
    error_message = "standalone policy rule must render"
  }
}

run "lb_ref_arm_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    waf_exclusion_policies = [{
      name  = "excl-pol-a"
      rules = [{ name = "r", action = "skip" }]
    }]
    waf_exclusion_policy_ref = "excl-pol-a"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.waf_exclusion.waf_exclusion_policy.name == "excl-pol-a"
    error_message = "LB waf_exclusion_policy ref arm must render the referenced policy name"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.waf_exclusion.waf_exclusion_inline_rules == null
    error_message = "inline arm must be omitted when the policy ref arm is used"
  }
}

run "policy_and_inline_mutually_exclusive" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    waf_exclusion_policies   = [{ name = "p", rules = [{ name = "r", action = "skip" }] }]
    waf_exclusion_policy_ref = "p"
    waf_exclusion_rules      = [{ name = "inline", action = "skip" }]
  }
  expect_failures = [xcsh_http_loadbalancer.this]
}

run "ref_must_exist_in_policies" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    waf_exclusion_policies   = [{ name = "p", rules = [{ name = "r", action = "skip" }] }]
    waf_exclusion_policy_ref = "does-not-exist"
  }
  expect_failures = [xcsh_http_loadbalancer.this]
}

run "no_policies_by_default" {
  command = plan
  module { source = "./modules/http-lb" }
  assert {
    condition     = length(xcsh_waf_exclusion_policy.this) == 0
    error_message = "no standalone policies by default"
  }
}
