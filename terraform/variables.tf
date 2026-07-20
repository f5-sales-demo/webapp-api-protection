variable "namespace" {
  description = "F5 XC namespace this plan creates and deploys the load balancer / origin pool into. HTTP load balancer and origin pool objects live in a user namespace (unlike DNS objects, which are system-scoped)."
  type        = string
  default     = "webapp-api-protection"
}

variable "lb_domains" {
  description = "Domains the HTTP load balancer serves. On production these are www.f5-sales-demo.com and api.f5-sales-demo.com; F5 XC auto-manages their DNS records because the f5-sales-demo.com zone has allow_http_lb_managed_records enabled."
  type        = list(string)
}

variable "origin_port" {
  description = "TCP port on the origin. The Azure origin server serves HTTP (nginx) on 80, so plaintext to 80 is the working path."
  type        = number
  default     = 80
}

variable "health_check_path" {
  description = "HTTP path the origin-pool health check probes. The Azure origin server's nginx returns HTTP 200 JSON on /health for any Host."
  type        = string
  default     = "/health"
}

variable "labels" {
  description = "Labels applied to managed objects."
  type        = map(string)
  default = {
    managed_by = "terraform"
    use_case   = "webapp-api-protection"
  }
}

variable "waf_mode" {
  description = "App firewall enforcement mode on the load balancer: blocking (actively block malicious requests) or monitoring (detect and log only)."
  type        = string
  default     = "blocking"

  validation {
    condition     = contains(["blocking", "monitoring"], var.waf_mode)
    error_message = "waf_mode must be \"blocking\" or \"monitoring\"."
  }
}

variable "csd_enabled" {
  description = "Enable Client-Side Defense: inject the F5 XC telemetry JavaScript on all pages and register the served domain with the CSD reporting engine. Requires the tenant CSD addon (verified via a data-source guard, not managed here)."
  type        = bool
  default     = true
}

variable "mud_enabled" {
  description = "Enable Malicious User Detection: score per-user behavior into threat levels and auto-mitigate (JS challenge / CAPTCHA / temporary block) via a malicious_user_mitigation policy. Requires the tenant MUD addon (verified via a data-source guard, not managed here)."
  type        = bool
  default     = true
}

variable "mud_user_id" {
  description = "MUD user identification method: client_ip (server default) or user_identification (a policy resource)."
  type        = string
  default     = "client_ip"

  validation {
    condition     = contains(["client_ip", "user_identification"], var.mud_user_id)
    error_message = "mud_user_id must be \"client_ip\" or \"user_identification\"."
  }
}

variable "mud_user_id_rule" {
  description = "When mud_user_id=user_identification, the rule type used to identify users (one of the xcsh_user_identification rule types)."
  type        = string
  default     = "client_ip"

  validation {
    condition = contains([
      "cookie_name", "http_header_name", "ip_and_http_header_name", "jwt_claim_name",
      "query_param_key", "client_asn", "client_city", "client_country", "client_ip",
      "client_region", "tls_fingerprint", "ip_and_tls_fingerprint", "ja4_tls_fingerprint",
      "ip_and_ja4_tls_fingerprint", "none"
    ], var.mud_user_id_rule)
    error_message = "mud_user_id_rule must be one of the supported xcsh_user_identification rule types."
  }
}

variable "mud_mitigation" {
  description = "MUD mitigation action per threat level. Each ∈ block_temporarily, captcha_challenge, javascript_challenge."
  type = object({
    low    = string
    medium = string
    high   = string
  })
  default = {
    low    = "javascript_challenge"
    medium = "captcha_challenge"
    high   = "block_temporarily"
  }

  validation {
    condition = alltrue([
      for action in values(var.mud_mitigation) :
      contains(["block_temporarily", "captcha_challenge", "javascript_challenge"], action)
    ])
    error_message = "each mud_mitigation action must be block_temporarily, captcha_challenge, or javascript_challenge."
  }
}

variable "challenge" {
  description = "LB challenge configuration (owns the challenge_type oneof). See module ./modules/http-lb variables_challenge.tf. MUD uses mode enable/policy_based with attach_malicious_user_mitigation."
  type = object({
    mode                             = optional(string)
    cookie_expiry                    = optional(number)
    custom_page                      = optional(string)
    js_script_delay                  = optional(number)
    attach_malicious_user_mitigation = optional(bool, false)
  })
  default = {}
}

variable "ddos" {
  description = "L7 DDoS protection config (l7_ddos_protection). See module ./modules/http-lb variables_ddos.tf."
  type = object({
    l7_enabled         = optional(bool, false)
    rps_threshold      = optional(number)
    clientside_action  = optional(string, "none")
    cs_cookie_expiry   = optional(number)
    cs_custom_page     = optional(string)
    cs_js_script_delay = optional(number)
    mitigation_rules = optional(list(object({
      name                 = string
      source               = optional(string, "country")
      countries            = optional(list(string), [])
      as_numbers           = optional(list(number), [])
      ip_prefixes          = optional(list(string), [])
      ip_invert            = optional(bool, false)
      tls_classes          = optional(list(string), [])
      tls_exact            = optional(list(string), [])
      ja4_exact            = optional(list(string), [])
      expiration_timestamp = optional(string)
    })), [])
  })
  default = {}
}

variable "csd" {
  description = "Client-Side Defense policy (client_side_defense.policy, gated by csd_enabled). See module ./modules/http-lb variables_csd.tf."
  type = object({
    js_insert = optional(string, "all_pages")
    exclude_list = optional(list(object({
      name         = string
      description  = optional(string)
      domain_mode  = optional(string, "any")
      domain_value = optional(string)
      path_mode    = optional(string, "prefix")
      path_value   = string
    })), [])
    insertion_rules = optional(object({
      rules = optional(list(object({
        name         = string
        description  = optional(string)
        domain_mode  = optional(string, "any")
        domain_value = optional(string)
        path_mode    = optional(string, "prefix")
        path_value   = string
      })), [])
      exclude_list = optional(list(object({
        name         = string
        description  = optional(string)
        domain_mode  = optional(string, "any")
        domain_value = optional(string)
        path_mode    = optional(string, "prefix")
        path_value   = string
      })), [])
    }))
  })
  default = {}
}

variable "csd_mitigated_domains" {
  description = "CSD mitigated (blocked) domains (xcsh_mitigated_domain). See module ./modules/http-lb variables_csd_domains.tf."
  type = list(object({
    name        = string
    domain      = string
    description = optional(string)
    disable     = optional(bool, false)
    labels      = optional(map(string), {})
    annotations = optional(map(string), {})
  }))
  default = []
}

variable "csd_allowed_domains" {
  description = "CSD allowed (allowlisted) domains (xcsh_allowed_domain). See module ./modules/http-lb variables_csd_domains.tf."
  type = list(object({
    name        = string
    domain      = string
    description = optional(string)
    disable     = optional(bool, false)
    labels      = optional(map(string), {})
    annotations = optional(map(string), {})
  }))
  default = []
}

variable "lb_algorithm" {
  description = "LB load-balancing algorithm (loadbalancer_algorithm oneof). See module ./modules/http-lb variables_lb_algorithm.tf."
  type = object({
    mode = optional(string, "round_robin")
    ring_hash_policies = optional(list(object({
      header_name = optional(string)
      source_ip   = optional(bool, false)
      terminal    = optional(bool, false)
    })), [])
  })
  default = {}
}

variable "mud_bad_traffic" {
  description = "Have the traffic generator emit identifiable malicious-user traffic (WAF-triggering payloads, forbidden-path scanning, failed logins) so MUD flags a user and applies mitigation. Only takes effect when mud_enabled. Off by default to keep the baseline demo benign."
  type        = bool
  default     = false
}

# ---------------------------------------------------------
# Azure (origin server + traffic generator this plan deploys)
# ---------------------------------------------------------

variable "subscription_id" {
  description = "Azure subscription ID the origin-server and traffic-generator VMs are deployed into. Supply via TF_VAR_subscription_id / terraform.tfvars (never hardcoded in .tf). Locally derive with: az account show --query id -o tsv."
  type        = string
}

variable "location" {
  description = "Azure region for the origin server and traffic generator."
  type        = string
  default     = "eastus2"
}

variable "ssh_public_key_path" {
  description = "Path to the SSH public key installed on the Azure VMs (admin login)."
  type        = string
  default     = "~/.ssh/id_ed25519.pub"
}

variable "environment" {
  description = "Environment label used in Azure resource-group naming and tags (e.g. lab, preprod)."
  type        = string
  default     = "lab"
}

variable "deployer" {
  description = "Override for the Azure deployer identifier used in resource naming/tags. Empty = auto-resolve from Azure AD. Set explicitly for service-principal / managed-identity (CI) auth, where the AD user lookup does not resolve."
  type        = string
  default     = ""
}

variable "azure_tags" {
  description = "Extra tags merged onto the Azure resources (origin server + traffic generator)."
  type        = map(string)
  default     = {}
}

variable "origin_vm_size" {
  description = "Azure VM size for the origin server (runs Docker workloads: httpbin, juice-shop, dvwa, vampi, ...)."
  type        = string
  default     = "Standard_D16s_v3"
}

variable "traffic_gen_vm_size" {
  description = "Azure VM size for the traffic generator (load + attack tooling)."
  type        = string
  default     = "Standard_F16s_v2"
}

variable "traffic_gen_tool_tier" {
  description = "Traffic-generator tool installation tier: standard (default) or full (adds ZAP, Metasploit)."
  type        = string
  default     = "standard"
}

# ---------------------------------------------------------------------------
# WAF (app_firewall) exhaustive-coverage passthrough to modules/http-lb.
# Defaults reproduce the current live config (0-change no-op). Validation lives
# in the module; these root declarations are lean type+default passthroughs.
# ---------------------------------------------------------------------------
variable "waf_allowed_response_codes_mode" {
  description = "allowed_response_codes_choice arm: omit or list."
  type        = string
  default     = "omit"
}
variable "waf_allowed_response_codes" {
  description = "Response codes when waf_allowed_response_codes_mode=list (1-48)."
  type        = list(number)
  default     = [200]
}
variable "waf_blocking_page_mode" {
  description = "blocking_page_choice arm: omit or custom."
  type        = string
  default     = "omit"
}
variable "waf_blocking_page" {
  description = "Custom blocking page (URL/HTML, <=4096) when waf_blocking_page_mode=custom."
  type        = string
  default     = "https://www.f5-sales-demo.com/blocked.html"
}
variable "waf_blocking_page_response_code" {
  description = "HTTP status enum name for the custom blocking page."
  type        = string
  default     = "Forbidden"
}
variable "waf_bot_mode" {
  description = "Top-level bot_protection_choice arm: omit or custom."
  type        = string
  default     = "omit"
}
variable "waf_bot_actions" {
  description = "Per-class bot actions (BLOCK/REPORT/IGNORE) when waf_bot_mode=custom."
  type        = object({ good = string, malicious = string, suspicious = string })
  default     = { good = "REPORT", malicious = "BLOCK", suspicious = "REPORT" }
}
variable "waf_anonymization_mode" {
  description = "anonymization_setting arm: omit or disable (custom pending provider fix)."
  type        = string
  default     = "omit"
}
variable "waf_ai_mode" {
  description = "enhance_with_ai_choice arm: omit (=disable, server default) or enable."
  type        = string
  default     = "omit"
}
variable "waf_ai_risk_action" {
  description = "risk_score_action_choice when waf_ai_mode=enable: high or high_medium."
  type        = string
  default     = "high"
}
variable "waf_detection_mode" {
  description = "detection_setting_choice arm: default or custom."
  type        = string
  default     = "default"
}
variable "waf_violation_mode" {
  description = "detection_settings violation arm: default or custom."
  type        = string
  default     = "default"
}
variable "waf_disabled_violation_types" {
  description = "Disabled violation types when waf_violation_mode=custom (<=40)."
  type        = list(string)
  default     = []
}
variable "waf_staging_mode" {
  description = "detection_settings staging arm: disable, new, or new_and_updated."
  type        = string
  default     = "disable"
}
variable "waf_staging_period" {
  description = "Staging period (days) for new/new_and_updated staging."
  type        = number
  default     = 7
}
variable "waf_suppression" {
  description = "detection_settings false_positive_suppression: enable or disable."
  type        = string
  default     = "enable"
}
variable "waf_threat_campaigns" {
  description = "detection_settings threat_campaign_choice: enable or disable."
  type        = string
  default     = "enable"
}
variable "waf_detection_bot_mode" {
  description = "detection_settings nested bot_protection_choice arm: default or custom."
  type        = string
  default     = "default"
}
variable "waf_signature_accuracy" {
  description = "detection_settings signature accuracy: only_high, high_medium, or high_medium_low."
  type        = string
  default     = "high_medium"
}
variable "waf_attack_type_mode" {
  description = "detection_settings attack_type_setting arm: default or custom."
  type        = string
  default     = "default"
}
variable "waf_disabled_attack_types" {
  description = "Disabled attack types when waf_attack_type_mode=custom (<=22)."
  type        = list(string)
  default     = []
}
