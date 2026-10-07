variable "namespace" { type = string }
variable "origin_pool_name" { type = string }
variable "swagger_path" { type = string }
variable "category" {
  type = string
  validation {
    condition     = contains(["waf", "schema", "endpoint", "rate", "mud"], var.category)
    error_message = "Unsupported comparison category."
  }
}
locals {
  endpoints = {
    before = { name = "${var.category}-before", protected = false }
    after  = { name = "${var.category}-after", protected = true }
  }
}
resource "xcsh_app_firewall" "this" {
  for_each                   = local.endpoints
  name                       = "${each.value.name}-waf"
  namespace                  = var.namespace
  monitoring                 = var.category == "waf" && !each.value.protected ? {} : null
  blocking                   = var.category != "waf" || each.value.protected ? {} : null
  default_detection_settings = {}
}
resource "xcsh_user_identification" "this" {
  for_each  = local.endpoints
  name      = "${each.value.name}-user"
  namespace = var.namespace
  rules { http_header_name = "X-MUD-User" }
}
resource "xcsh_malicious_user_mitigation" "this" {
  count     = var.category == "mud" ? 1 : 0
  name      = "mud-after-mitigation"
  namespace = var.namespace
  mitigation_type {
    rules {
      threat_level { low = {} }
      mitigation_action { block_temporarily = {} }
    }
    rules {
      threat_level { medium = {} }
      mitigation_action { block_temporarily = {} }
    }
    rules {
      threat_level { high = {} }
      mitigation_action { block_temporarily = {} }
    }
  }
}
resource "xcsh_api_definition" "this" {
  for_each      = var.category == "schema" ? local.endpoints : {}
  name          = "${each.value.name}-schema"
  namespace     = var.namespace
  swagger_specs = [var.swagger_path]
}
resource "xcsh_http_loadbalancer" "this" {
  for_each  = local.endpoints
  name      = each.value.name
  namespace = var.namespace
  domains   = ["${each.value.name}.f5-sales-demo.com"]
  https_auto_cert {
    port          = 443
    http_redirect = false
    no_mtls       = {}
  }
  default_route_pools {
    pool {
      name      = var.origin_pool_name
      namespace = var.namespace
    }
    priority = 1
    weight   = 1
  }
  app_firewall {
    name      = xcsh_app_firewall.this[each.key].name
    namespace = var.namespace
  }
  user_identification {
    name      = xcsh_user_identification.this[each.key].name
    namespace = var.namespace
  }
  enable_api_discovery {}
  enable_malicious_user_detection = var.category == "mud" && each.value.protected ? {} : null
  dynamic "enable_challenge" {
    for_each = var.category == "mud" && each.value.protected ? [1] : []
    content {
      malicious_user_mitigation {
        name      = xcsh_malicious_user_mitigation.this[0].name
        namespace = var.namespace
      }
    }
  }
  dynamic "api_specification" {
    for_each = var.category == "schema" ? [1] : []
    content {
      api_definition {
        name      = xcsh_api_definition.this[each.key].name
        namespace = var.namespace
      }
      validation_all_spec_endpoints {
        validation_mode {
          validation_mode_active {
            request_validation_properties = ["PROPERTY_HTTP_BODY", "PROPERTY_CONTENT_TYPE"]
            enforcement_report            = each.value.protected ? null : {}
            enforcement_block             = each.value.protected ? {} : null
          }
        }
        fall_through_mode { fall_through_mode_allow = {} }
      }
    }
  }
  dynamic "api_protection_rules" {
    for_each = var.category == "endpoint" ? [1] : []
    content {
      api_endpoint_rules {
        metadata { name = "api-protection-0" }
        api_endpoint_path = "/httpbin/anything/admin"
        any_domain        = {}
        api_endpoint_method { methods = ["POST", "DELETE"] }
        action {
          allow = each.value.protected ? null : {}
          deny  = each.value.protected ? {} : null
        }
      }
    }
  }
  dynamic "api_rate_limit" {
    for_each = var.category == "rate" && each.value.protected ? [1] : []
    content {
      api_endpoint_rules {
        any_domain        = {}
        api_endpoint_path = "/httpbin/anything/rate-limit"
        api_endpoint_method { methods = ["GET"] }
        inline_rate_limiter {
          threshold           = 20
          unit                = "MINUTE"
          use_http_lb_user_id = {}
        }
      }
    }
  }
  dynamic "routes" {
    for_each = ["/juice-shop/socket.io/", "/dvga/subscriptions"]
    content {
      simple_route {
        http_method = "ANY"
        path { prefix = routes.value }
        origin_pools {
          pool {
            name      = var.origin_pool_name
            namespace = var.namespace
          }
          weight   = 1
          priority = 1
        }
        advanced_options {
          priority = "DEFAULT"
          web_socket_config { use_websocket = true }
        }
      }
    }
  }
  advertise_on_public_default_vip = {}
  round_robin                     = {}
}
output "endpoints" {
  value = {
    for phase, endpoint in local.endpoints : phase => {
      url                      = "https://${endpoint.name}.f5-sales-demo.com"
      domain                   = "${endpoint.name}.f5-sales-demo.com"
      loadbalancer_name        = xcsh_http_loadbalancer.this[phase].name
      app_firewall_name        = xcsh_app_firewall.this[phase].name
      user_identification_name = xcsh_user_identification.this[phase].name
      origin_pool_name         = var.origin_pool_name
      namespace                = var.namespace
      protected                = endpoint.protected
    }
  }
}
