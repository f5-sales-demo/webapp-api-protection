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
  source = "./modules/azure-vm"

  component       = "origin-server"
  address_space   = ["10.200.0.0/16"]
  subnet_prefixes = ["10.200.1.0/24"]

  location            = var.location
  vm_size             = var.origin_vm_size
  disk_size_gb        = 60
  ssh_public_key_path = var.ssh_public_key_path
  environment         = var.environment
  deployer            = var.deployer
  tags                = var.azure_tags

  security_rules = [
    { name = "AllowHTTP", priority = 100, port = "80" },
    { name = "AllowHTTPS", priority = 110, port = "443" },
    { name = "AllowSSH", priority = 120, port = "22" },
    { name = "AllowCrAPI", priority = 130, port = "8888" },
  ]

  custom_data = base64encode(templatefile("${path.module}/cloud-init/origin-server.yaml", {}))
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

  # LPC-5a healthcheck parameterization passthrough (defaults reproduce the http /health check).
  health_check_type            = var.health_check_type
  hc_healthy_threshold         = var.hc_healthy_threshold
  hc_unhealthy_threshold       = var.hc_unhealthy_threshold
  hc_timeout                   = var.hc_timeout
  hc_interval                  = var.hc_interval
  hc_jitter_percent            = var.hc_jitter_percent
  hc_http_host_header          = var.hc_http_host_header
  hc_expected_status_codes     = var.hc_expected_status_codes
  hc_expected_response         = var.hc_expected_response
  hc_request_headers_to_remove = var.hc_request_headers_to_remove
  hc_tcp_send_payload          = var.hc_tcp_send_payload
  hc_tcp_expected_response     = var.hc_tcp_expected_response
  origin_lb_algorithm          = var.origin_lb_algorithm
  origin_endpoint_selection    = var.origin_endpoint_selection
  origin_connection_timeout    = var.origin_connection_timeout
  origin_http_idle_timeout     = var.origin_http_idle_timeout
  custom_routes                = var.custom_routes
  route_objects                = var.route_objects
  custom_route_ref             = var.custom_route_ref
  labels                       = var.labels
  waf_mode                     = var.waf_mode
  csd_enabled                  = var.csd_enabled

  # WAF (app_firewall) exhaustive-coverage passthrough.
  waf_allowed_response_codes_mode = var.waf_allowed_response_codes_mode
  waf_allowed_response_codes      = var.waf_allowed_response_codes
  waf_blocking_page_mode          = var.waf_blocking_page_mode
  waf_blocking_page               = var.waf_blocking_page
  waf_blocking_page_response_code = var.waf_blocking_page_response_code
  waf_bot_mode                    = var.waf_bot_mode
  waf_bot_actions                 = var.waf_bot_actions
  waf_anonymization_mode          = var.waf_anonymization_mode
  waf_ai_mode                     = var.waf_ai_mode
  waf_ai_risk_action              = var.waf_ai_risk_action
  waf_detection_mode              = var.waf_detection_mode
  waf_violation_mode              = var.waf_violation_mode
  waf_disabled_violation_types    = var.waf_disabled_violation_types
  waf_staging_mode                = var.waf_staging_mode
  waf_staging_period              = var.waf_staging_period
  waf_suppression                 = var.waf_suppression
  waf_threat_campaigns            = var.waf_threat_campaigns
  waf_detection_bot_mode          = var.waf_detection_bot_mode
  waf_signature_accuracy          = var.waf_signature_accuracy
  waf_attack_type_mode            = var.waf_attack_type_mode
  waf_disabled_attack_types       = var.waf_disabled_attack_types
  mud_enabled                     = var.mud_enabled
  mud_user_id                     = var.mud_user_id
  mud_user_id_rule                = var.mud_user_id_rule
  mud_mitigation                  = var.mud_mitigation
  challenge                       = var.challenge
  ddos                            = var.ddos

  # API Discovery & Crawler (SP1) passthrough. Defaults keep enable_api_discovery {}
  # bare (0-change). The api-discovery matrix cycles the non-default arms.
  api_discovery_choice              = var.api_discovery_choice
  api_discovery_learn_from_redirect = var.api_discovery_learn_from_redirect
  api_discovery_purge_duration      = var.api_discovery_purge_duration
  api_discovery_auth_mode           = var.api_discovery_auth_mode
  api_discovery_custom_auth_types   = var.api_discovery_custom_auth_types
  api_crawler_domains               = var.api_crawler_domains
  api_crawler_password              = var.api_crawler_password

  # API spec source-control integration (SP2) passthrough. Default disabled (0-change).
  code_base_integration_enabled      = var.code_base_integration_enabled
  code_base_integration_provider     = var.code_base_integration_provider
  code_base_integration_username     = var.code_base_integration_username
  code_base_integration_hostname     = var.code_base_integration_hostname
  code_base_integration_url          = var.code_base_integration_url
  code_base_integration_verify_ssl   = var.code_base_integration_verify_ssl
  code_base_integration_access_token = var.code_base_integration_access_token
  api_discovery_code_scan            = var.api_discovery_code_scan
  api_discovery_code_scan_repos      = var.api_discovery_code_scan_repos

  # API Definition & spec enforcement (SP2) passthrough. Default disable (0-change).
  api_definition_choice              = var.api_definition_choice
  api_definition_swagger_specs       = var.api_definition_swagger_specs
  api_definition_inventory_inclusion = var.api_definition_inventory_inclusion
  api_definition_inventory_exclusion = var.api_definition_inventory_exclusion
  api_definition_non_api_endpoints   = var.api_definition_non_api_endpoints
  api_definition_schema_origin       = var.api_definition_schema_origin
  api_specification_validation       = var.api_specification_validation

  # OpenAPI validation enforcement (Batch A) passthrough.
  api_validation_request_mode        = var.api_validation_request_mode
  api_validation_request_properties  = var.api_validation_request_properties
  api_validation_response_mode       = var.api_validation_response_mode
  api_validation_response_properties = var.api_validation_response_properties
  api_validation_fall_through        = var.api_validation_fall_through
  api_validation_oversized_body      = var.api_validation_oversized_body
  api_validation_additional_params   = var.api_validation_additional_params

  # API Protection passthrough. Defaults keep every control off/suppressed (0-change).
  rate_limit_choice                  = var.rate_limit_choice
  rate_limit_total_number            = var.rate_limit_total_number
  rate_limit_unit                    = var.rate_limit_unit
  rate_limit_period_multiplier       = var.rate_limit_period_multiplier
  rate_limit_burst_multiplier        = var.rate_limit_burst_multiplier
  rate_limit_ip_allowed_prefixes     = var.rate_limit_ip_allowed_prefixes
  rate_limit_custom_ip_prefix_sets   = var.rate_limit_custom_ip_prefix_sets
  rate_limit_policy_refs             = var.rate_limit_policy_refs
  api_rate_limit_endpoint_rules      = var.api_rate_limit_endpoint_rules
  api_rate_limit_bypass_rules        = var.api_rate_limit_bypass_rules
  api_rate_limit_server_url_rules    = var.api_rate_limit_server_url_rules
  rate_limiters                      = var.rate_limiters
  rate_limiter_policies              = var.rate_limiter_policies
  sensitive_data_compliances         = var.sensitive_data_compliances
  sensitive_data_disabled_predefined = var.sensitive_data_disabled_predefined
  sensitive_data_policy_choice       = var.sensitive_data_policy_choice
  data_types                         = var.data_types
  sensitive_data_custom_type_refs    = var.sensitive_data_custom_type_refs
  sensitive_data_disclosure_rules    = var.sensitive_data_disclosure_rules
  data_guard_rules                   = var.data_guard_rules
  api_protection_rules               = var.api_protection_rules
  api_protection_group_rules         = var.api_protection_group_rules
  app_api_groups                     = var.app_api_groups
  validation_custom_rules            = var.validation_custom_rules

  # Service policies (SPol effort) passthrough. Defaults create nothing and emit no LB
  # block (server default service_policies_from_namespace, import-suppressed => 0-change).
  service_policies              = var.service_policies
  service_policies_choice       = var.service_policies_choice
  service_policy_active         = var.service_policy_active
  service_policy_bgp_asn_sets   = var.service_policy_bgp_asn_sets
  service_policy_ip_prefix_sets = var.service_policy_ip_prefix_sets

  # Client access control (CAC) passthrough.
  trusted_clients          = var.trusted_clients
  blocked_clients          = var.blocked_clients
  ip_reputation_enabled    = var.ip_reputation_enabled
  ip_reputation_categories = var.ip_reputation_categories

  # App-layer protection (LPC-1) passthrough.
  cors_policy         = var.cors_policy
  csrf_policy_mode    = var.csrf_policy_mode
  csrf_custom_domains = var.csrf_custom_domains
  protected_cookies   = var.protected_cookies

  # Header/cookie manipulation (LPC-2) passthrough.
  request_headers_to_add      = var.request_headers_to_add
  request_headers_to_remove   = var.request_headers_to_remove
  response_headers_to_add     = var.response_headers_to_add
  response_headers_to_remove  = var.response_headers_to_remove
  request_cookies_to_remove   = var.request_cookies_to_remove
  response_cookies_to_remove  = var.response_cookies_to_remove
  disable_default_error_pages = var.disable_default_error_pages

  # GraphQL inspection (LPC-3) passthrough.
  graphql_rules            = var.graphql_rules
  jwt_validation           = var.jwt_validation
  waf_exclusion_rules      = var.waf_exclusion_rules
  waf_exclusion_policies   = var.waf_exclusion_policies
  waf_exclusion_policy_ref = var.waf_exclusion_policy_ref

  # API Testing (SP4) passthrough. Defaults keep it off (disable_api_testing
  # suppressed => 0-change) and create no standalone resource.
  api_testing_choice              = var.api_testing_choice
  api_testing_standalone_enabled  = var.api_testing_standalone_enabled
  api_testing_schedule            = var.api_testing_schedule
  api_testing_custom_header_value = var.api_testing_custom_header_value
  api_testing_domains             = var.api_testing_domains

  # Enabling client_side_defense on the LB requires a protected domain to already
  # exist in this namespace (F5 XC generates the CSD JS config from it), so the
  # LB must be created/updated AFTER the protected domain. The MUD entitlement
  # guard is a prerequisite too: fail fast if the WAAP addon is not subscribed
  # before the module creates the malicious_user_mitigation policy / LB.
  depends_on = [xcsh_protected_domain.csd, data.xcsh_addon_service_activation_status.mud]
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

# --- Malicious User Detection tenant dependency (verified, NOT managed) -------
# MUD is a Web App & API Protection (WAAP) capability: enabling
# enable_malicious_user_detection on the LB and creating the
# xcsh_malicious_user_mitigation policy require the tenant to be subscribed to the
# WAAP addon. As with CSD, tenant entitlement is owned by a separate tenant-level
# plan, so here we only ASSERT the dependency (fail fast if not subscribed) rather
# than managing the subscription. Confirmed live: the MUD feature maps to
# f5xc-waap-standard (there is no MUD-specific addon; MUD is not bot defense).
data "xcsh_addon_service_activation_status" "mud" {
  count         = var.mud_enabled ? 1 : 0
  addon_service = "f5xc-waap-standard"

  lifecycle {
    postcondition {
      condition     = self.state == "AS_SUBSCRIBED"
      error_message = "Malicious User Detection requires the WAAP addon, which is not subscribed on this tenant (state: ${self.state}). Enable it via the tenant entitlements plan before applying MUD."
    }
  }
}

# --- Azure traffic generator (drives live load at the load balancer) ----------
module "traffic_generator" {
  source = "./modules/azure-vm"

  component       = "traffic-generator"
  address_space   = ["10.201.0.0/16"]
  subnet_prefixes = ["10.201.1.0/24"]

  location            = var.location
  vm_size             = var.traffic_gen_vm_size
  disk_size_gb        = 64
  ssh_public_key_path = var.ssh_public_key_path
  environment         = var.environment
  deployer            = var.deployer
  tags                = var.azure_tags

  security_rules = [
    { name = "AllowSSH", priority = 100, port = "22" },
  ]

  # Target the LB FQDN (lb_domains[0] = www.f5-sales-demo.com), not the origin directly;
  # target_origin_ip is the optional direct-origin baseline / bypass-testing target.
  custom_data = base64encode(templatefile("${path.module}/cloud-init/traffic-generator.yaml", {
    target_fqdn      = var.lb_domains[0]
    target_origin_ip = module.origin_server.public_ip
    tool_tier        = var.traffic_gen_tool_tier
    # Emit identifiable malicious-user traffic each burst so MUD scores a user and
    # applies the configured mitigation (only meaningful when mud_enabled).
    mud_bad_traffic = var.mud_enabled && var.mud_bad_traffic
  }))

  # The generator is only useful once the LB exists to receive its traffic.
  depends_on = [module.http_lb]
}
