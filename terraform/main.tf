# webapp-api-protection reference plan.
#
# Full automation: this plan creates its own namespace (no dependency object is
# made out-of-band). The http-lb module's namespace input is wired from the
# created xcsh_namespace, so the namespace is created before the objects in it.
#
# http-lb — an HTTP load balancer + origin pool (httpbin) advertised on the F5 XC
# public VIP, serving www.f5-sales-demo.com and api.f5-sales-demo.com. DNS records
# for those domains are auto-managed by F5 XC because the f5-sales-demo.com zone
# has allow_http_lb_managed_records enabled (see the dns repo).
#
# Later iterations attach WAF (app_firewall) and API protection (api_definition).

resource "xcsh_namespace" "this" {
  name   = var.namespace
  labels = var.labels
}

module "http_lb" {
  source = "./modules/http-lb"

  namespace         = xcsh_namespace.this.name
  lb_domains        = var.lb_domains
  origin_dns_name   = var.origin_dns_name
  origin_port       = var.origin_port
  health_check_path = var.health_check_path
  labels            = var.labels
}
