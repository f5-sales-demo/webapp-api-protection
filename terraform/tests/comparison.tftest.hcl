mock_provider "xcsh" {}

variables {
  namespace        = "example"
  origin_pool_name = "example-origin"
  swagger_path     = "/api/object_store/namespaces/example/stored_objects/swagger/schema/v1"
}

run "waf_pair" {
  command = plan
  module { source = "./modules/comparison" }
  variables { category = "waf" }
  assert {
    condition = (
      length(xcsh_http_loadbalancer.this) == 2 &&
      xcsh_app_firewall.this["before"].monitoring != null &&
      xcsh_app_firewall.this["after"].blocking != null &&
      output.endpoints.before.url == "https://waf-before.f5-sales-demo.com" &&
      output.endpoints.after.url == "https://waf-after.f5-sales-demo.com"
    )
    error_message = "WAF comparison must isolate monitoring and blocking across two HTTPS hosts."
  }
  assert {
    condition     = length(xcsh_malicious_user_mitigation.this) == 0
    error_message = "Non-MUD comparisons must not create mitigation policies."
  }
}

run "schema_pair" {
  command = plan
  module { source = "./modules/comparison" }
  variables { category = "schema" }
  assert {
    condition = (
      length(xcsh_api_definition.this) == 2 &&
      xcsh_http_loadbalancer.this["before"].api_specification.validation_all_spec_endpoints.validation_mode.validation_mode_active.enforcement_report != null &&
      xcsh_http_loadbalancer.this["after"].api_specification.validation_all_spec_endpoints.validation_mode.validation_mode_active.enforcement_block != null &&
      toset(xcsh_api_definition.this["before"].swagger_specs) == toset([var.swagger_path]) &&
      toset(xcsh_api_definition.this["after"].swagger_specs) == toset([var.swagger_path])
    )
    error_message = "Schema pair must share immutable content and isolate reporting from blocking."
  }
}

run "endpoint_pair" {
  command = plan
  module { source = "./modules/comparison" }
  variables { category = "endpoint" }
  assert {
    condition = (
      xcsh_http_loadbalancer.this["before"].api_protection_rules.api_endpoint_rules[0].action.allow != null &&
      xcsh_http_loadbalancer.this["after"].api_protection_rules.api_endpoint_rules[0].action.deny != null &&
      xcsh_http_loadbalancer.this["after"].api_protection_rules.api_endpoint_rules[0].api_endpoint_path == "/httpbin/anything/admin" &&
      toset(xcsh_http_loadbalancer.this["after"].api_protection_rules.api_endpoint_rules[0].api_endpoint_method.methods) == toset(["POST", "DELETE"])
    )
    error_message = "Endpoint pair must differ only for exact admin POST and DELETE."
  }
}

run "rate_pair" {
  command = plan
  module { source = "./modules/comparison" }
  variables { category = "rate" }
  assert {
    condition = (
      xcsh_http_loadbalancer.this["after"].api_rate_limit.api_endpoint_rules[0].inline_rate_limiter.threshold == 20 &&
      xcsh_http_loadbalancer.this["after"].api_rate_limit.api_endpoint_rules[0].inline_rate_limiter.unit == "MINUTE" &&
      xcsh_http_loadbalancer.this["after"].api_rate_limit.api_endpoint_rules[0].inline_rate_limiter.use_http_lb_user_id != null &&
      xcsh_user_identification.this["before"].rules[0].http_header_name == "X-MUD-User" &&
      xcsh_user_identification.this["after"].rules[0].http_header_name == "X-MUD-User"
    )
    error_message = "Rate protection must use a declared 20/minute per-user limiter."
  }
}

run "mud_pair" {
  command = plan
  module { source = "./modules/comparison" }
  variables { category = "mud" }
  assert {
    condition = (
      length(xcsh_malicious_user_mitigation.this) == 1 &&
      xcsh_app_firewall.this["before"].blocking != null &&
      xcsh_app_firewall.this["after"].blocking != null &&
      xcsh_http_loadbalancer.this["after"].enable_malicious_user_detection != null &&
      xcsh_http_loadbalancer.this["after"].enable_challenge.malicious_user_mitigation.name == xcsh_malicious_user_mitigation.this[0].name &&
      alltrue([for rule in xcsh_malicious_user_mitigation.this[0].mitigation_type.rules : rule.mitigation_action.block_temporarily != null])
    )
    error_message = "MUD after must enable detection and temporary mitigation while both retain WAF blocking."
  }
}
