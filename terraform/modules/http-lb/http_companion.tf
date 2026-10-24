# HTTP and HTTPS listeners render the same declared policies.
locals {
  listeners = merge(
    { primary = { name = local.lb_name, https = var.lb_https_auto_cert } },
    var.lb_https_auto_cert ? { http = { name = "${local.lb_name}-http", https = false } } : {}
  )
}
moved {
  from = xcsh_http_loadbalancer.this
  to   = xcsh_http_loadbalancer.this["primary"]
}
moved {
  from = xcsh_http_loadbalancer.http[0]
  to   = xcsh_http_loadbalancer.this["http"]
}
