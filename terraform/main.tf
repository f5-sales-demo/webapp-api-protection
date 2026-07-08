# webapp-api-protection reference plan.
#
# http-lb — an HTTP load balancer with an origin pool pointing at httpbin
# (a public request-echo service), advertised on the F5 XC public VIP. This is
# the iteration-1 scaffold: the simplest end-to-end path through the provider.
#
# Later iterations attach security controls to the same load balancer —
# app_firewall (WAF) and api_definition (API protection) — by extending the
# http-lb module; the provider already supports those resources.

module "http_lb" {
  source = "./modules/http-lb"

  namespace         = var.namespace
  lb_domain         = var.lb_domain
  origin_dns_name   = var.origin_dns_name
  origin_port       = var.origin_port
  health_check_path = var.health_check_path
  labels            = var.labels
}
