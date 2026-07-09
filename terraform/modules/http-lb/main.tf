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
}
