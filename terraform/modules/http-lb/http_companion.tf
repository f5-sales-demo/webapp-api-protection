# XC HTTP and HTTPS choices are exclusive. Retain HTTP with a second owned listener
# using the same origin, WAF, identity, schema, endpoint and mitigation resources.
resource "xcsh_http_loadbalancer" "http" {
  count     = var.lb_https_auto_cert ? 1 : 0
  name      = "${local.lb_name}-http"
  namespace = var.namespace
  labels    = var.labels
  domains   = var.lb_domains

  http {
    port                 = 80
    dns_volterra_managed = true
  }
  default_route_pools {
    pool {
      name      = xcsh_origin_pool.origin.name
      namespace = var.namespace
    }
    weight   = 1
    priority = 1
  }
  app_firewall {
    name      = xcsh_app_firewall.this.name
    namespace = var.namespace
  }
  enable_api_discovery {}
  enable_malicious_user_detection = var.mud_enabled ? {} : null
  dynamic "user_identification" {
    for_each = var.mud_enabled && var.mud_user_id == "user_identification" ? [1] : []
    content {
      name      = xcsh_user_identification.mud[0].name
      namespace = var.namespace
    }
  }
  dynamic "enable_challenge" {
    for_each = local.challenge_mode == "enable" ? [1] : []
    content {
      dynamic "malicious_user_mitigation" {
        for_each = local.challenge_attach_mud ? [1] : []
        content {
          name      = xcsh_malicious_user_mitigation.mud[0].name
          namespace = var.namespace
        }
      }
    }
  }
  dynamic "api_specification" {
    for_each = var.api_definition_choice == "specification" ? [1] : []
    content {
      api_definition {
        name      = xcsh_api_definition.this[0].name
        namespace = var.namespace
      }
      validation_all_spec_endpoints {
        validation_mode {
          validation_mode_active {
            enforcement_block             = {}
            request_validation_properties = var.api_validation_request_properties
          }
        }
        fall_through_mode {
          fall_through_mode_allow = {}
        }
      }
    }
  }
  dynamic "api_protection_rules" {
    for_each = length(var.api_protection_rules) > 0 ? [1] : []
    content {
      dynamic "api_endpoint_rules" {
        for_each = var.api_protection_rules
        iterator = ep
        content {
          metadata { name = "api-protection-${ep.key}" }
          api_endpoint_path = ep.value.path
          any_domain        = {}
          api_endpoint_method { methods = ep.value.methods }
          action { deny = {} }
        }
      }
    }
  }
  dynamic "api_rate_limit" {
    for_each = var.rate_limit_choice == "api_rate_limit" ? [1] : []
    content {
      api_endpoint_rules {
        any_domain        = {}
        api_endpoint_path = "/httpbin/anything/rate-limit"
        api_endpoint_method {
          methods = ["GET"]
        }
        inline_rate_limiter {
          threshold           = 20
          unit                = "MINUTE"
          use_http_lb_user_id = {}
        }
      }
    }
  }
  advertise_on_public_default_vip = {}
  round_robin                     = {}

  lifecycle {
    precondition {
      condition     = !var.csd_enabled && var.waf_mode == "blocking" && var.api_discovery_choice == "enable" && var.api_specification_validation == "all_spec_endpoints" && var.api_validation_request_mode == "block" && var.challenge.mode == "enable"
      error_message = "The additional HTTP listener requires the protected showcase configuration with CSD disabled."
    }
  }
}
