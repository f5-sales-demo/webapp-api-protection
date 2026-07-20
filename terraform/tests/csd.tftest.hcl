# Plan-level tests for CSD policy: client_side_defense.policy js_insert oneof + exclude_list.
# command = plan, targets ./modules/http-lb. csd_enabled gates the block.
variables {
  namespace         = "webapp-api-protection"
  lb_domains        = ["www.f5-sales-demo.com"]
  origin_ip         = "203.0.113.10"
  origin_port       = 80
  health_check_path = "/health"
  labels            = {}
  csd_enabled       = true
  mud_enabled       = false
}

run "all_pages_default_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  assert {
    condition     = xcsh_http_loadbalancer.this.client_side_defense.policy.js_insert_all_pages != null
    error_message = "default js_insert must be all_pages"
  }
}

run "disabled_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { csd = { js_insert = "disabled" } }
  assert {
    condition     = xcsh_http_loadbalancer.this.client_side_defense.policy.disable_js_insert != null
    error_message = "js_insert=disabled must render disable_js_insert"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.client_side_defense.policy.js_insert_all_pages == null
    error_message = "js_insert_all_pages must be absent when disabled"
  }
}

run "all_except_exclude_list_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    csd = {
      js_insert = "all_except"
      exclude_list = [
        { name = "skip-admin", domain_mode = "suffix", domain_value = "f5-sales-demo.com", path_mode = "prefix", path_value = "/admin" },
        { name = "skip-health", domain_mode = "any", path_mode = "exact", path_value = "/health" },
      ]
    }
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.client_side_defense.policy.js_insert_all_pages_except.exclude_list[0].metadata.name == "skip-admin"
    error_message = "exclude_list metadata.name must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.client_side_defense.policy.js_insert_all_pages_except.exclude_list[0].domain.suffix_value == "f5-sales-demo.com"
    error_message = "exclude_list domain suffix_value must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.client_side_defense.policy.js_insert_all_pages_except.exclude_list[0].path.prefix == "/admin"
    error_message = "exclude_list path prefix must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.client_side_defense.policy.js_insert_all_pages_except.exclude_list[1].any_domain != null
    error_message = "exclude_list any_domain must render for domain_mode=any"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.client_side_defense.policy.js_insert_all_pages_except.exclude_list[1].path.path == "/health"
    error_message = "exclude_list path exact must render on path.path"
  }
}

run "insertion_rules_render" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    csd = {
      js_insert = "insertion_rules"
      insertion_rules = {
        rules = [
          { name = "ins-home", domain_mode = "any", path_mode = "prefix", path_value = "/" },
          { name = "ins-checkout", description = "checkout pages", domain_mode = "suffix", domain_value = "f5-sales-demo.com", path_mode = "exact", path_value = "/csd-demo/" },
        ]
        exclude_list = [
          { name = "skip-health", domain_mode = "any", path_mode = "exact", path_value = "/health" },
        ]
      }
    }
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.client_side_defense.policy.js_insertion_rules.rules[0].any_domain != null
    error_message = "insertion_rules.rules[0] any_domain must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.client_side_defense.policy.js_insertion_rules.rules[0].path.prefix == "/"
    error_message = "insertion_rules.rules[0] path prefix must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.client_side_defense.policy.js_insertion_rules.rules[1].metadata.description_spec == "checkout pages"
    error_message = "insertion_rules.rules[1] metadata.description_spec must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.client_side_defense.policy.js_insertion_rules.rules[1].domain.suffix_value == "f5-sales-demo.com"
    error_message = "insertion_rules.rules[1] domain suffix_value must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.client_side_defense.policy.js_insertion_rules.exclude_list[0].path.path == "/health"
    error_message = "insertion_rules.exclude_list[0] path exact must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.client_side_defense.policy.js_insert_all_pages == null
    error_message = "js_insert_all_pages must be absent when insertion_rules selected"
  }
}

run "insertion_rules_regex_modes" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    csd = {
      js_insert = "insertion_rules"
      insertion_rules = {
        rules = [
          { name = "ins-regex", domain_mode = "regex", domain_value = ".*[.]f5-sales-demo[.]com", path_mode = "regex", path_value = "^/app/.*$" },
        ]
      }
    }
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.client_side_defense.policy.js_insertion_rules.rules[0].domain.regex_value == ".*[.]f5-sales-demo[.]com"
    error_message = "regex domain_mode must render domain.regex_value"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.client_side_defense.policy.js_insertion_rules.rules[0].path.regex == "^/app/.*$"
    error_message = "regex path_mode must render path.regex"
  }
}

run "all_except_regex_modes" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    csd = {
      js_insert    = "all_except"
      exclude_list = [{ name = "skip-regex", domain_mode = "regex", domain_value = "cdn[.].*", path_mode = "regex", path_value = "^/static/.*$" }]
    }
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.client_side_defense.policy.js_insert_all_pages_except.exclude_list[0].domain.regex_value == "cdn[.].*"
    error_message = "all_except regex domain_mode must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.client_side_defense.policy.js_insert_all_pages_except.exclude_list[0].path.regex == "^/static/.*$"
    error_message = "all_except regex path_mode must render"
  }
}

run "insertion_rules_requires_rules" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { csd = { js_insert = "insertion_rules", insertion_rules = { rules = [] } } }
  expect_failures = [var.csd]
}

run "insertion_rules_requires_mode" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { csd = { js_insert = "all_pages", insertion_rules = { rules = [{ name = "r", path_value = "/" }] } } }
  expect_failures = [var.csd]
}

run "csd_disabled_omits_block" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { csd_enabled = false }
  assert {
    condition     = xcsh_http_loadbalancer.this.client_side_defense == null
    error_message = "client_side_defense must be omitted when csd_enabled=false"
  }
}

run "bad_js_insert_rejected" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { csd = { js_insert = "some_pages" } }
  expect_failures = [var.csd]
}

run "exclude_list_requires_all_except" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { csd = { js_insert = "all_pages", exclude_list = [{ name = "x", path_value = "/x" }] } }
  expect_failures = [var.csd]
}

run "exclude_domain_value_required" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { csd = { js_insert = "all_except", exclude_list = [{ name = "x", domain_mode = "exact", path_value = "/x" }] } }
  expect_failures = [var.csd]
}
