# Plan-level tests for LPC-4a: LB inline waf_exclusion rules. Targets ./modules/http-lb.
# command = plan (no creds).
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

run "skip_rule_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    waf_exclusion_rules = [{
      name       = "skip-health"
      path       = "prefix"
      path_value = "/health"
      methods    = ["GET", "HEAD"]
      action     = "skip"
    }]
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.waf_exclusion.waf_exclusion_inline_rules.rules[0].metadata.name == "skip-health"
    error_message = "rule metadata.name must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.waf_exclusion.waf_exclusion_inline_rules.rules[0].path_prefix == "/health"
    error_message = "path_prefix must render for path=prefix"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.waf_exclusion.waf_exclusion_inline_rules.rules[0].waf_skip_processing != null
    error_message = "waf_skip_processing arm must render for action=skip"
  }
}

run "detection_control_rule_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    waf_exclusion_rules = [{
      name         = "excl-sig"
      domain       = "exact"
      domain_value = "api.f5-sales-demo.com"
      action       = "detection_control"
      exclude_signatures = [
        { signature_id = 0, context = "CONTEXT_ANY" },
        { signature_id = 200002147, context = "CONTEXT_HEADER", context_name = "x-api" },
      ]
      exclude_violations = [{ violation = "VIOL_JSON_MALFORMED" }]
    }]
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.waf_exclusion.waf_exclusion_inline_rules.rules[0].exact_value == "api.f5-sales-demo.com"
    error_message = "exact_value must render for domain=exact"
  }
  # signature_id 0 = "all signatures"; round-trips since provider v3.72.10 (#1129).
  assert {
    condition     = xcsh_http_loadbalancer.this.waf_exclusion.waf_exclusion_inline_rules.rules[0].app_firewall_detection_control.exclude_signature_contexts[0].signature_id == 0
    error_message = "signature_id=0 (all signatures) must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.waf_exclusion.waf_exclusion_inline_rules.rules[0].app_firewall_detection_control.exclude_signature_contexts[1].signature_id == 200002147
    error_message = "exclude_signature_contexts signature_id must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.waf_exclusion.waf_exclusion_inline_rules.rules[0].app_firewall_detection_control.exclude_violation_contexts[0].exclude_violation == "VIOL_JSON_MALFORMED"
    error_message = "exclude_violation_contexts must render"
  }
}

run "waf_exclusion_omitted_by_default" {
  command = plan
  module { source = "./modules/http-lb" }
  assert {
    condition     = xcsh_http_loadbalancer.this.waf_exclusion == null
    error_message = "waf_exclusion must be omitted (null) by default"
  }
}

run "bad_domain_rejected" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { waf_exclusion_rules = [{ name = "r", domain = "glob" }] }
  expect_failures = [var.waf_exclusion_rules]
}

run "exact_domain_requires_value" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { waf_exclusion_rules = [{ name = "r", domain = "exact" }] }
  expect_failures = [var.waf_exclusion_rules]
}

run "bad_method_rejected" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { waf_exclusion_rules = [{ name = "r", methods = ["FETCH"] }] }
  expect_failures = [var.waf_exclusion_rules]
}

run "detection_control_requires_exclusion" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { waf_exclusion_rules = [{ name = "r", action = "detection_control" }] }
  expect_failures = [var.waf_exclusion_rules]
}

run "bad_context_rejected" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    waf_exclusion_rules = [{
      name               = "r"
      action             = "detection_control"
      exclude_signatures = [{ signature_id = 0, context = "CONTEXT_WHATEVER" }]
    }]
  }
  expect_failures = [var.waf_exclusion_rules]
}
