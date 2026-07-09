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
  csd_enabled       = var.csd_enabled

  # Enabling client_side_defense on the LB requires a protected domain to already
  # exist in this namespace (F5 XC generates the CSD JS config from it), so the
  # LB must be created/updated AFTER the protected domain.
  depends_on = [xcsh_protected_domain.csd]
}

# --- Client-Side Defense tenant dependency (verified, NOT managed) ------------
# CSD requires the tenant to be subscribed to the Client-Side Defense addon.
# Tenant entitlement/provisioning is owned by a separate tenant-level plan, so
# here we only ASSERT the dependency via the entitlements data source (fail fast
# if it is not subscribed) rather than managing the subscription in this app.
data "xcsh_addon_service_activation_status" "csd" {
  count         = var.csd_enabled ? 1 : 0
  addon_service = "f5xc-client-side-defense-standard"

  lifecycle {
    postcondition {
      condition     = self.state == "AS_SUBSCRIBED"
      error_message = "Client-Side Defense addon is not subscribed on this tenant (state: ${self.state}). Enable it via the tenant entitlements plan before applying CSD."
    }
  }
}

# Register the served root domain with the CSD reporting engine. CRITICAL: this
# must be in the LOAD BALANCER'S namespace (var.namespace) — F5 XC generates the
# per-namespace CSD JS configuration from it, and enabling client_side_defense on
# the LB fails (500 "Failed to get CSD JS Configuration") if no protected domain
# exists in the LB's namespace. protected_domain must be an eTLD+1 (server rule
# ves.io.schema.rules.string.etld); the object `name` is DNS-1123 (no dots).
# The generated resource's Read tolerates the CSD API's 501 GET-by-name (the API
# is list/create/delete only) — terraform-provider-xcsh#1044.
resource "xcsh_protected_domain" "csd" {
  count            = var.csd_enabled ? 1 : 0
  name             = "webapp-api-protection-root"
  namespace        = xcsh_namespace.this.name
  protected_domain = "f5-sales-demo.com"

  depends_on = [data.xcsh_addon_service_activation_status.csd]
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
