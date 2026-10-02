# Configuration rendering only: live readiness/acceptance must prove each responsible
# XC control and benign availability; this plan test is not security proof.
variables {
  namespace                         = jsondecode(file("showcase.tfvars.json")).namespace
  lb_domains                        = jsondecode(file("showcase.tfvars.json")).lb_domains
  origin_ip                         = "203.0.113.10"
  csd_enabled                       = jsondecode(file("showcase.tfvars.json")).csd_enabled
  lb_https_auto_cert                = true
  waf_mode                          = jsondecode(file("showcase.tfvars.json")).waf_mode
  waf_blocking_page_mode            = jsondecode(file("showcase.tfvars.json")).waf_blocking_page_mode
  waf_blocking_page                 = jsondecode(file("showcase.tfvars.json")).waf_blocking_page
  waf_blocking_page_response_code   = jsondecode(file("showcase.tfvars.json")).waf_blocking_page_response_code
  api_discovery_choice              = jsondecode(file("showcase.tfvars.json")).api_discovery_choice
  mud_enabled                       = jsondecode(file("showcase.tfvars.json")).mud_enabled
  mud_user_id                       = jsondecode(file("showcase.tfvars.json")).mud_user_id
  mud_user_id_rule                  = jsondecode(file("showcase.tfvars.json")).mud_user_id_rule
  mud_mitigation                    = jsondecode(file("showcase.tfvars.json")).mud_mitigation
  challenge                         = jsondecode(file("showcase.tfvars.json")).challenge
  api_definition_choice             = jsondecode(file("showcase.tfvars.json")).api_definition_choice
  api_specification_validation      = jsondecode(file("showcase.tfvars.json")).api_specification_validation
  api_validation_request_mode       = jsondecode(file("showcase.tfvars.json")).api_validation_request_mode
  api_validation_request_properties = jsondecode(file("showcase.tfvars.json")).api_validation_request_properties
  api_validation_response_mode      = jsondecode(file("showcase.tfvars.json")).api_validation_response_mode
  api_validation_fall_through       = jsondecode(file("showcase.tfvars.json")).api_validation_fall_through
  api_protection_rules              = jsondecode(file("showcase.tfvars.json")).api_protection_rules
  rate_limit_choice                 = jsondecode(file("showcase.tfvars.json")).rate_limit_choice
  api_rate_limit_endpoint_rules     = jsondecode(file("showcase.tfvars.json")).api_rate_limit_endpoint_rules
  api_rate_limit_bypass_rules       = jsondecode(file("showcase.tfvars.json")).api_rate_limit_bypass_rules
  api_rate_limit_server_url_rules   = jsondecode(file("showcase.tfvars.json")).api_rate_limit_server_url_rules
  # Existing documented sample URI: never a deployable substitute for the lifecycle
  # uploader's receipt. The lifecycle MUST inject its exact uploaded version.
  api_definition_swagger_specs = ["/api/object_store/namespaces/webapp-api-protection/stored_objects/swagger/vampi/v1-26-07-14"]
}

run "showcase_effective_controls" {
  command = plan
  module {
    source = "./modules/http-lb"
  }

  assert {
    condition = (
      xcsh_http_loadbalancer.this.https_auto_cert.port == 443 &&
      xcsh_http_loadbalancer.this.https_auto_cert.http_redirect == false &&
      toset(xcsh_http_loadbalancer.this.domains) == toset(["www.f5-sales-demo.com", "api.f5-sales-demo.com"]) &&
      xcsh_http_loadbalancer.this.client_side_defense == null &&
      xcsh_app_firewall.this.blocking != null &&
      var.waf_mode == "blocking" &&
      xcsh_http_loadbalancer.this.app_firewall.name == xcsh_app_firewall.this.name &&
      xcsh_http_loadbalancer.this.enable_api_discovery != null
    )
    error_message = "Effective LB must offer auto-certificate HTTPS and retain HTTP, serve both domains, attach blocking WAF, enable discovery, and omit CSD."
  }

  assert {
    condition = (
      var.waf_blocking_page_mode == "custom" &&
      xcsh_app_firewall.this.blocking != null &&
      xcsh_app_firewall.this.blocking_page.response_code == "Forbidden" &&
      xcsh_app_firewall.this.blocking_page.blocking_page == "string:///${base64encode("<!doctype html><html><body>Request Rejected</body></html>")}" &&
      base64decode(trimprefix(xcsh_app_firewall.this.blocking_page.blocking_page, "string:///")) == "<!doctype html><html><body>Request Rejected</body></html>"
    )
    error_message = "Showcase WAF must enforce blocking with explicit HTTP 403 (Forbidden) and an inline base64 URI containing the synthetic Request Rejected body."
  }

  # Provider 12 monitoring is Optional+Computed: omitted is UNKNOWN at plan,
  # not null. Check the configuration's inactive-arm expression separately;
  # the assertion above still inspects the actual planned blocking marker.
  assert {
    condition     = var.waf_mode == "blocking" && strcontains(file("modules/http-lb/main.tf"), "monitoring = var.waf_mode == \"monitoring\" ? {} : null")
    error_message = "Blocking mode must configure monitoring as null, not enable both WAF arms."
  }

  assert {
    condition = (
      xcsh_http_loadbalancer.this.enable_malicious_user_detection != null &&
      xcsh_http_loadbalancer.this.user_identification.name == xcsh_user_identification.mud[0].name &&
      xcsh_user_identification.mud[0].rules[0].http_header_name == "X-MUD-User" &&
      xcsh_http_loadbalancer.this.enable_challenge.malicious_user_mitigation.name == xcsh_malicious_user_mitigation.mud[0].name &&
      xcsh_http_loadbalancer.this.js_challenge == null &&
      xcsh_http_loadbalancer.this.captcha_challenge == null &&
      xcsh_http_loadbalancer.this.policy_based_challenge == null &&
      alltrue([for r in xcsh_malicious_user_mitigation.mud[0].mitigation_type.rules : r.mitigation_action.block_temporarily != null])
    )
    error_message = "MUD must identify X-MUD-User and attach risk-based mitigation, never universally challenge benign identities."
  }

  assert {
    condition = (
      toset(xcsh_api_definition.this[0].swagger_specs) == toset(var.api_definition_swagger_specs) &&
      xcsh_http_loadbalancer.this.api_specification.api_definition.name == xcsh_api_definition.this[0].name &&
      xcsh_http_loadbalancer.this.api_specification.validation_all_spec_endpoints.validation_mode.validation_mode_active.enforcement_block != null &&
      toset(xcsh_http_loadbalancer.this.api_specification.validation_all_spec_endpoints.validation_mode.validation_mode_active.request_validation_properties) == toset(["PROPERTY_HTTP_BODY", "PROPERTY_CONTENT_TYPE"]) &&
      xcsh_http_loadbalancer.this.api_specification.validation_all_spec_endpoints.validation_mode.response_validation_mode_active == null &&
      xcsh_http_loadbalancer.this.api_specification.validation_all_spec_endpoints.validation_mode.skip_response_validation == null &&
      xcsh_http_loadbalancer.this.api_specification.validation_all_spec_endpoints.fall_through_mode.fall_through_mode_allow != null
    )
    error_message = "Schema enforcement must block invalid requests only; response enforcement must be omitted and unrelated endpoints allowed."
  }

  assert {
    condition = (
      length(xcsh_http_loadbalancer.this.api_protection_rules.api_endpoint_rules) == 1 &&
      xcsh_http_loadbalancer.this.api_protection_rules.api_endpoint_rules[0].api_endpoint_path == "/httpbin/anything/admin" &&
      toset(xcsh_http_loadbalancer.this.api_protection_rules.api_endpoint_rules[0].api_endpoint_method.methods) == toset(["POST", "DELETE"]) &&
      xcsh_http_loadbalancer.this.api_protection_rules.api_endpoint_rules[0].api_endpoint_method.invert_matcher == false &&
      xcsh_http_loadbalancer.this.api_protection_rules.api_endpoint_rules[0].action.deny != null &&
      length(xcsh_http_loadbalancer.this.api_protection_rules.api_groups_rules) == 0
    )
    error_message = "Deny must be exact admin POST/DELETE only, not GET or an unrelated endpoint/group."
  }

  assert {
    condition = (
      xcsh_http_loadbalancer.this.rate_limit == null &&
      length(xcsh_http_loadbalancer.this.api_rate_limit.api_endpoint_rules) == 1 &&
      length(xcsh_http_loadbalancer.this.api_rate_limit.server_url_rules) == 0 &&
      xcsh_http_loadbalancer.this.api_rate_limit.bypass_rate_limiting_rules == null &&
      xcsh_http_loadbalancer.this.api_rate_limit.api_endpoint_rules[0].api_endpoint_path == "/httpbin/anything/rate-limit" &&
      toset(xcsh_http_loadbalancer.this.api_rate_limit.api_endpoint_rules[0].api_endpoint_method.methods) == toset(["GET"]) &&
      xcsh_http_loadbalancer.this.api_rate_limit.api_endpoint_rules[0].api_endpoint_method.invert_matcher == false &&
      xcsh_http_loadbalancer.this.api_rate_limit.api_endpoint_rules[0].inline_rate_limiter.threshold == 20 &&
      xcsh_http_loadbalancer.this.api_rate_limit.api_endpoint_rules[0].inline_rate_limiter.unit == "MINUTE" &&
      xcsh_http_loadbalancer.this.api_rate_limit.api_endpoint_rules[0].inline_rate_limiter.use_http_lb_user_id != null
    )
    error_message = "Only GET /httpbin/anything/rate-limit may be limited to 20/min per LB header identity; no global limiter."
  }

  assert {
    condition = (
      length(var.api_definition_swagger_specs) == 1 &&
      jsondecode(file("fixtures/showcase-openapi.json")).openapi == "3.0.3" &&
      length(keys(jsondecode(file("fixtures/showcase-openapi.json")).paths)) == 1 &&
      length(keys(jsondecode(file("fixtures/showcase-openapi.json")).paths["/httpbin/post"])) == 1 &&
      jsondecode(file("fixtures/showcase-openapi.json")).paths["/httpbin/post"].post.requestBody.required &&
      jsondecode(file("fixtures/showcase-openapi.json")).paths["/httpbin/post"].post.requestBody.content["application/json"].schema.required == ["demo_id"] &&
      jsondecode(file("fixtures/showcase-openapi.json")).paths["/httpbin/post"].post.requestBody.content["application/json"].schema.properties.demo_id.type == "string" &&
      toset([for s in jsondecode(file("fixtures/showcase-openapi.json")).servers : s.url]) == toset(["http://www.f5-sales-demo.com", "http://api.f5-sales-demo.com"])
    )
    error_message = "Synthetic OpenAPI must constrain only POST /httpbin/post to required string demo_id across both HTTP servers."
  }
}

# Representation regression only, not the deployable showcase profile: ensure
# the alternative explicit choice renders monitoring and omits blocking.
run "explicit_monitoring_choice_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    waf_mode           = "monitoring"
    lb_https_auto_cert = false
  }
  assert {
    condition = (
      xcsh_app_firewall.this.monitoring != null &&
      xcsh_app_firewall.this.blocking == null &&
      xcsh_http_loadbalancer.this.app_firewall.name == xcsh_app_firewall.this.name
    )
    error_message = "Explicit monitoring must render the monitoring marker and omit blocking on the attached WAF."
  }
}
