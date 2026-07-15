# Plan-level tests for App API Groups (Coverage Batch F): xcsh_app_api_group render
# (elements + LB association) and api_protection_group_rules referencing a module-created
# group. Targets ./modules/http-lb, dummy origin.
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

run "app_api_group_none_by_default" {
  command = plan
  module { source = "./modules/http-lb" }
  assert {
    condition     = output.app_api_group_count == 0
    error_message = "no app_api_groups by default (0-change)"
  }
}

run "app_api_group_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    app_api_groups = [{
      name     = "orders-api"
      elements = [{ path_regex = "/api/orders.*", methods = ["GET", "POST"] }]
    }]
  }
  assert {
    condition     = output.app_api_group_count == 1 && contains(output.app_api_group_names, "orders-api")
    error_message = "orders-api group must render"
  }
  assert {
    condition     = xcsh_app_api_group.this["orders-api"].http_loadbalancer.http_loadbalancer.name == "webapp-api-protection" && xcsh_app_api_group.this["orders-api"].elements[0].path_regex == "/api/orders.*"
    error_message = "group must associate to the LB by name + render elements"
  }
}

run "api_groups_rule_references_created_group" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    app_api_groups             = [{ name = "orders-api", elements = [{ path_regex = "/api/orders.*" }] }]
    api_protection_group_rules = [{ api_group = "orders-api", action = "deny" }]
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.api_protection_rules.api_groups_rules[0].api_group == "orders-api" && xcsh_http_loadbalancer.this.api_protection_rules.api_groups_rules[0].action.deny != null
    error_message = "api_groups_rules must reference the created group by name with the deny action"
  }
}

# --- validation failures ---

run "app_api_group_rejects_dup_names" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { app_api_groups = [{ name = "g" }, { name = "g" }] }
  expect_failures = [var.app_api_groups]
}

run "app_api_group_rejects_bad_method" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { app_api_groups = [{ name = "g", elements = [{ path_regex = "/x", methods = ["FETCH"] }] }] }
  expect_failures = [var.app_api_groups]
}

run "app_api_group_rejects_empty_path_regex" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { app_api_groups = [{ name = "g", elements = [{ path_regex = "" }] }] }
  expect_failures = [var.app_api_groups]
}
