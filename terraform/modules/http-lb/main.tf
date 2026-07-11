# HTTP load balancer + origin pool (with health check) pointing at the Azure
# origin server this plan deploys (modules/origin-server).
#
# Based on the acceptance-tested provider examples
# examples/resources/xcsh_http_loadbalancer/with-origin-pool.tf,
# examples/resources/xcsh_origin_pool/public-ip.tf and
# examples/resources/xcsh_origin_pool/with-healthcheck-ref.tf.
#
# The origin server's nginx serves HTTP 200 on port 80 (health endpoint /health),
# so the pool connects to the origin in plaintext (no_tls). For an HTTPS origin,
# replace `no_tls {}` with a `use_tls { sni = <host>  volterra_trusted_ca {} }`
# block and set origin_port 443.
#
# Extension seam (later iterations, provider already supports these):
#   - WAF:            add resource "xcsh_app_firewall" and an `app_firewall {}`
#                     reference block on the load balancer.
#   - API protection: add resource "xcsh_api_definition" and the load balancer's
#                     `api_definition` / `enable_api_discovery {}` blocks.

resource "xcsh_healthcheck" "origin" {
  name      = "origin-healthcheck"
  namespace = var.namespace
  labels    = var.labels

  healthy_threshold   = 3
  unhealthy_threshold = 1
  timeout             = 3
  interval            = 15

  http_health_check {
    # The origin server's nginx returns 200 on /health for any Host, so no
    # host_header override is needed (unlike the previous public_name origin).
    path                  = var.health_check_path
    expected_status_codes = ["200"]
  }
}

resource "xcsh_origin_pool" "origin" {
  name      = "origin-pool"
  namespace = var.namespace
  labels    = var.labels

  port = var.origin_port

  origin_servers {
    labels {}
    public_ip {
      ip = var.origin_ip
    }
  }

  healthcheck {
    name      = xcsh_healthcheck.origin.name
    namespace = xcsh_healthcheck.origin.namespace
  }

  no_tls {}
  same_as_endpoint_port {}
}

# Web application firewall attached to the load balancer below.
#
# Import-cleanliness rule (verified by round-trip import against the live tenant):
# only declare oneof-default markers that the provider does NOT suppress on import.
# The provider's import-default-suppressions.json strips these AppFirewall markers:
#   allow_all_response_codes, default_anonymization, default_bot_setting,
#   use_default_blocking_page, disable_ai_enhancements
# so declaring them (as the acceptance-tested blocking.tf example does) causes
# import drift (config has them, imported state does not). We therefore declare
# ONLY the non-suppressed blocks: default_detection_settings + the enforcement
# mode (blocking/monitoring). Enforcement mode is var-driven (exactly one emitted).
# NOTE (lock-step provider gap): examples/resources/xcsh_app_firewall/blocking.tf
# declares the suppressed markers and is thus NOT import-round-trip-clean.
resource "xcsh_app_firewall" "this" {
  name      = "webapp-api-protection-waf"
  namespace = var.namespace
  labels    = var.labels

  default_detection_settings {}

  dynamic "blocking" {
    for_each = var.waf_mode == "blocking" ? [1] : []
    content {}
  }
  dynamic "monitoring" {
    for_each = var.waf_mode == "monitoring" ? [1] : []
    content {}
  }
}

# Malicious User Detection mitigation policy — the actions F5 XC takes once a user
# is scored into a threat level. Referenced by the load balancer's enable_challenge
# block below (there is no top-level malicious_user_mitigation field on the LB; the
# reference lives inside the challenge oneof). Escalating response by threat level:
# low → JavaScript challenge, medium → CAPTCHA, high → temporary block. Based on the
# acceptance-tested example xcsh_malicious_user_mitigation/with-mitigation-type.tf.
resource "xcsh_malicious_user_mitigation" "mud" {
  count     = var.mud_enabled ? 1 : 0
  name      = "webapp-api-protection-mud"
  namespace = var.namespace
  labels    = var.labels

  # One static rule per threat level (low/medium/high); the ACTION within each is chosen
  # by var.mud_mitigation. The rules list is kept static (3 entries) because a dynamic
  # rules list produces an unknown-typed value the generated provider model cannot handle
  # (mitigation_type.rules → []RulesModel, not a ListValue). Action is a oneof; emit the
  # selected member as an empty marker.
  mitigation_type {
    rules {
      threat_level {
        low {}
      }
      mitigation_action {
        dynamic "block_temporarily" {
          for_each = var.mud_mitigation.low == "block_temporarily" ? [1] : []
          content {}
        }
        dynamic "captcha_challenge" {
          for_each = var.mud_mitigation.low == "captcha_challenge" ? [1] : []
          content {}
        }
        dynamic "javascript_challenge" {
          for_each = var.mud_mitigation.low == "javascript_challenge" ? [1] : []
          content {}
        }
      }
    }
    rules {
      threat_level {
        medium {}
      }
      mitigation_action {
        dynamic "block_temporarily" {
          for_each = var.mud_mitigation.medium == "block_temporarily" ? [1] : []
          content {}
        }
        dynamic "captcha_challenge" {
          for_each = var.mud_mitigation.medium == "captcha_challenge" ? [1] : []
          content {}
        }
        dynamic "javascript_challenge" {
          for_each = var.mud_mitigation.medium == "javascript_challenge" ? [1] : []
          content {}
        }
      }
    }
    rules {
      threat_level {
        high {}
      }
      mitigation_action {
        dynamic "block_temporarily" {
          for_each = var.mud_mitigation.high == "block_temporarily" ? [1] : []
          content {}
        }
        dynamic "captcha_challenge" {
          for_each = var.mud_mitigation.high == "captcha_challenge" ? [1] : []
          content {}
        }
        dynamic "javascript_challenge" {
          for_each = var.mud_mitigation.high == "javascript_challenge" ? [1] : []
          content {}
        }
      }
    }
  }
}

resource "xcsh_http_loadbalancer" "this" {
  name      = "webapp-api-protection"
  namespace = var.namespace
  labels    = var.labels

  domains = var.lb_domains

  http {
    port = 80
    # Let F5 XC auto-manage DNS records for `domains` (www/api.f5-sales-demo.com)
    # to this LB's VIP. Prerequisite: the domain is delegated to F5 XC (it is) and
    # the zone has allow_http_lb_managed_records enabled (see the dns repo).
    dns_volterra_managed = true
  }

  default_route_pools {
    pool {
      name      = xcsh_origin_pool.origin.name
      namespace = var.namespace
    }
    weight   = 1
    priority = 1
    # F5 XC always normalizes an empty endpoint_subsets object into the API
    # response for each default_route_pools entry (verified via live API), so we
    # declare it to keep apply/plan/import consistent. This is correct config,
    # not a workaround. (Provider-side handling of server-default empty oneof
    # members on import is tracked in terraform-provider-xcsh#1003.)
    endpoint_subsets {}
  }

  advertise_on_public_default_vip {}

  # Attach the WAF (oneof: app_firewall vs disable_waf; server default disable_waf).
  app_firewall {
    name      = xcsh_app_firewall.this.name
    namespace = xcsh_app_firewall.this.namespace
  }

  # Enable API Discovery — learn the API schema from live traffic. This is the
  # discovery oneof (enable vs disable_api_discovery); independent of
  # api_specification / xcsh_api_definition (that path is enforcement, not
  # discovery), so no separate resource is required.
  #
  # A bare block is import-clean and first-apply-consistent: the provider now
  # suppresses F5 XC's server-materialized inner oneof defaults
  # (default_api_auth_discovery, disable_learn_from_redirect_traffic) on the
  # import path. That suppression was added in lock-step — see
  # terraform-provider-xcsh tools/import-default-suppressions.json (HTTPLoadBalancer).
  enable_api_discovery {}

  # Client-Side Defense — inject the F5 XC telemetry JavaScript into served pages
  # to detect Magecart/formjacking/skimming (client_side_defense oneof vs the
  # server default disable_client_side_defense). Requires the CSD tenant addon
  # (verified via the data-source guard in the root module). When csd_enabled is
  # false we emit NO block — the server applies disable_client_side_defense, which
  # the provider suppresses on import (so no drift; do not declare it).
  dynamic "client_side_defense" {
    for_each = var.csd_enabled ? [1] : []
    content {
      policy {
        js_insert_all_pages {}
      }
    }
  }

  # Malicious User Detection — score per-user behavior into threat levels
  # (malicious_user_detection oneof vs the server default disable_malicious_user_detection).
  # User identification uses the server-default client IP (user_id_client_ip); both the
  # disable marker and the client-IP default are suppressed by the provider on import, so
  # when mud_enabled is false we emit NO block (no drift; do not declare them).
  dynamic "enable_malicious_user_detection" {
    for_each = var.mud_enabled ? [1] : []
    content {}
  }

  # Auto-mitigation for detected malicious users. enable_challenge is the challenge
  # oneof arm that carries the malicious_user_mitigation reference (peer to the server
  # default no_challenge, which the provider suppresses on import). It points at the
  # mitigation policy created above.
  dynamic "enable_challenge" {
    for_each = var.mud_enabled ? [1] : []
    content {
      malicious_user_mitigation {
        name      = xcsh_malicious_user_mitigation.mud[0].name
        namespace = xcsh_malicious_user_mitigation.mud[0].namespace
      }
    }
  }
}
