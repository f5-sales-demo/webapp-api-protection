# webapp-api-protection reference plan (multi-provider: F5 XC + Azure).
#
# Full automation, one plan, one state. This plan stands up its OWN backend and
# load balancer end to end — no dependency object is created out-of-band:
#
#   modules/origin-server      Azure Linux VM (nginx + Docker: httpbin, juice-shop,
#                              dvwa, vampi, whoami, dvga, restaurant, crAPI) on :80,
#                              health endpoint /health. This is the real origin.
#   xcsh_namespace             The F5 XC namespace this plan owns.
#   modules/http-lb            F5 XC HTTP load balancer + origin pool, advertised on
#                              the public VIP, serving www/api.f5-sales-demo.com. The
#                              pool points at the origin server's Azure public IP.
#   modules/traffic-generator  Azure Linux VM (wrk/vegeta/nuclei/... ) driving
#                              continuous HTTP load at the load balancer FQDN, so the
#                              WAF / API-protection controls have live traffic.
#
# DNS records for the LB domains are auto-managed by F5 XC (the f5-sales-demo.com
# zone has allow_http_lb_managed_records enabled — see the dns repo).
#
# Later iterations attach WAF (app_firewall) and API protection (api_definition).

# --- Azure origin server (the real backend the LB forwards to) -----------------
module "origin_server" {
  source = "./modules/origin-server"

  location            = var.location
  vm_size             = var.origin_vm_size
  ssh_public_key_path = var.ssh_public_key_path
  environment         = var.environment
  deployer            = var.deployer
  tags                = var.azure_tags
}

# --- F5 XC namespace + HTTP load balancer -------------------------------------
resource "xcsh_namespace" "this" {
  name   = var.namespace
  labels = var.labels
}

module "http_lb" {
  source = "./modules/http-lb"

  namespace  = xcsh_namespace.this.name
  lb_domains = var.lb_domains
  # Point the origin pool at the Azure origin server's public IP (created above).
  # Terraform orders VM creation before the pool that references its IP.
  origin_ip         = module.origin_server.public_ip
  origin_port       = var.origin_port
  health_check_path = var.health_check_path
  labels            = var.labels
  waf_mode          = var.waf_mode
}

# --- Azure traffic generator (drives live load at the load balancer) ----------
module "traffic_generator" {
  source = "./modules/traffic-generator"

  # Target the LB FQDN, not the origin directly. lb_domains[0] is www.f5-sales-demo.com.
  target_fqdn = var.lb_domains[0]
  # Optional direct-origin baseline / bypass testing target.
  target_origin_ip = module.origin_server.public_ip

  location            = var.location
  vm_size             = var.traffic_gen_vm_size
  tool_tier           = var.traffic_gen_tool_tier
  ssh_public_key_path = var.ssh_public_key_path
  environment         = var.environment
  deployer            = var.deployer
  tags                = var.azure_tags

  # The generator is only useful once the LB exists to receive its traffic.
  depends_on = [module.http_lb]
}
