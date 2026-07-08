# HTTP load balancer + origin pool (with health check) pointing at httpbin.
#
# Based on the acceptance-tested provider examples
# examples/resources/xcsh_http_loadbalancer/with-origin-pool.tf and
# examples/resources/xcsh_origin_pool/with-healthcheck-ref.tf, repointed at
# httpbin and parameterised for the staging-tenant namespace.
#
# httpbin serves HTTP 200 (no redirect) on port 80, so the pool connects to the
# origin in plaintext (no_tls). For an HTTPS origin, replace `no_tls {}` with a
# `use_tls { sni = <host>  volterra_trusted_ca {} }` block and set origin_port 443.
#
# Extension seam (later iterations, provider already supports these):
#   - WAF:            add resource "xcsh_app_firewall" and an `app_firewall {}`
#                     reference block on the load balancer.
#   - API protection: add resource "xcsh_api_definition" and the load balancer's
#                     `api_definition` / `enable_api_discovery {}` blocks.

resource "xcsh_healthcheck" "httpbin" {
  name      = "httpbin-healthcheck"
  namespace = var.namespace
  labels    = var.labels

  healthy_threshold   = 3
  unhealthy_threshold = 1
  timeout             = 3
  interval            = 15

  http_health_check {
    path                  = var.health_check_path
    host_header           = var.origin_dns_name
    expected_status_codes = ["200"]
  }
}

resource "xcsh_origin_pool" "httpbin" {
  name      = "httpbin-origin-pool"
  namespace = var.namespace
  labels    = var.labels

  port = var.origin_port

  origin_servers {
    labels {}
    public_name {
      dns_name = var.origin_dns_name
    }
  }

  healthcheck {
    name      = xcsh_healthcheck.httpbin.name
    namespace = xcsh_healthcheck.httpbin.namespace
  }

  no_tls {}
  same_as_endpoint_port {}
}

resource "xcsh_http_loadbalancer" "httpbin" {
  name      = "webapp-api-protection"
  namespace = var.namespace
  labels    = var.labels

  domains = [var.lb_domain]

  http {
    port = 80
  }

  default_route_pools {
    pool {
      name      = xcsh_origin_pool.httpbin.name
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
}
