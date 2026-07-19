variable "namespace" {
  description = "F5 XC namespace for the load balancer and origin pool."
  type        = string
}

variable "lb_domains" {
  description = "Domains the HTTP load balancer serves (matched on the Host/authority header)."
  type        = list(string)
}

variable "origin_ip" {
  description = "Public IP address of the origin server the pool forwards to (the Azure origin server's public IP)."
  type        = string
}

variable "origin_port" {
  description = "TCP port on the origin."
  type        = number
  default     = 80
}

variable "health_check_path" {
  description = "HTTP path the health check probes on the origin. The Azure origin server's nginx returns HTTP 200 on /health for any Host."
  type        = string
  default     = "/health"
}

variable "labels" {
  description = "Labels applied to the load balancer and origin pool."
  type        = map(string)
  default     = {}
}

variable "waf_mode" {
  description = "App firewall enforcement mode: blocking (actively block) or monitoring (detect only)."
  type        = string
  default     = "blocking"

  validation {
    condition     = contains(["blocking", "monitoring"], var.waf_mode)
    error_message = "waf_mode must be \"blocking\" or \"monitoring\"."
  }
}

variable "csd_enabled" {
  description = "Enable Client-Side Defense on the load balancer (inject the CSD telemetry JavaScript on all pages). Requires the CSD tenant addon."
  type        = bool
  default     = true
}

variable "mud_enabled" {
  description = "Enable Malicious User Detection on the load balancer (score per-user behavior into threat levels and auto-mitigate via a malicious_user_mitigation policy). Requires the MUD tenant addon."
  type        = bool
  default     = true
}

variable "mud_user_id" {
  description = "User identification method for MUD: client_ip (server default) or user_identification (a policy resource)."
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
  description = "Malicious-user mitigation action per threat level. Each value is block_temporarily, captcha_challenge, or javascript_challenge."
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

# The LB challenge integration (formerly mud_challenge_mode) is now the unified `challenge`
# variable — see variables_challenge.tf. MUD's use is challenge.mode = enable/policy_based
# with attach_malicious_user_mitigation = true (derived by default when mud_enabled).

# ---------------------------------------------------------------------------
# Web Application Firewall (xcsh_app_firewall) — exhaustive option coverage.
# Every variable defaults to the current live config (server-default oneof
# arms omitted, since those are import-suppressed by the provider), so a normal
# apply is a 0-change no-op. The waf-matrix harness cycles the non-default arms.
# ---------------------------------------------------------------------------

variable "waf_allowed_response_codes_mode" {
  description = "allowed_response_codes_choice: omit (server default allow_all, suppressed) or list (explicit allowed_response_codes)."
  type        = string
  default     = "omit"

  validation {
    condition     = contains(["omit", "list"], var.waf_allowed_response_codes_mode)
    error_message = "waf_allowed_response_codes_mode must be \"omit\" or \"list\"."
  }
}

variable "waf_allowed_response_codes" {
  description = "Response codes allowed when waf_allowed_response_codes_mode=list (1-48 entries)."
  type        = list(number)
  default     = [200]

  validation {
    condition     = length(var.waf_allowed_response_codes) >= 1 && length(var.waf_allowed_response_codes) <= 48
    error_message = "waf_allowed_response_codes must have between 1 and 48 entries."
  }
}

variable "waf_blocking_page_mode" {
  description = "blocking_page_choice: omit (server default use_default_blocking_page, suppressed) or custom."
  type        = string
  default     = "omit"

  validation {
    condition     = contains(["omit", "custom"], var.waf_blocking_page_mode)
    error_message = "waf_blocking_page_mode must be \"omit\" or \"custom\"."
  }
}

variable "waf_blocking_page" {
  description = "Custom blocking page (URL or inline HTML, <=4096 chars) when waf_blocking_page_mode=custom."
  type        = string
  default     = "https://www.f5-sales-demo.com/blocked.html"

  validation {
    condition     = length(var.waf_blocking_page) <= 4096
    error_message = "waf_blocking_page must be at most 4096 characters."
  }
}

variable "waf_blocking_page_response_code" {
  description = "HTTP status returned with the custom blocking page (F5 XC response-code enum name)."
  type        = string
  default     = "Forbidden"
}

variable "waf_bot_mode" {
  description = "Top-level bot_protection_choice: omit (server default default_bot_setting, suppressed) or custom (explicit per-class actions)."
  type        = string
  default     = "omit"

  validation {
    condition     = contains(["omit", "custom"], var.waf_bot_mode)
    error_message = "waf_bot_mode must be \"omit\" or \"custom\"."
  }
}

variable "waf_bot_actions" {
  description = "Per-class bot actions when waf_bot_mode=custom. Each is BLOCK, REPORT, or IGNORE."
  type = object({
    good       = string
    malicious  = string
    suspicious = string
  })
  default = {
    good       = "REPORT"
    malicious  = "BLOCK"
    suspicious = "REPORT"
  }

  validation {
    condition = alltrue([
      for a in values(var.waf_bot_actions) : contains(["BLOCK", "REPORT", "IGNORE"], a)
    ])
    error_message = "each waf_bot_actions value must be BLOCK, REPORT, or IGNORE."
  }
}

variable "waf_anonymization_mode" {
  description = "anonymization_setting: omit (server default default_anonymization, suppressed) or disable. The custom_anonymization arm is unsupported pending a provider codegen fix (see main.tf note)."
  type        = string
  default     = "omit"

  validation {
    condition     = contains(["omit", "disable"], var.waf_anonymization_mode)
    error_message = "waf_anonymization_mode must be \"omit\" or \"disable\"."
  }
}

variable "waf_ai_mode" {
  description = "enhance_with_ai_choice: omit (server default disable_ai_enhancements, suppressed) or enable. There is no explicit disable arm: omit IS disable (emitting the suppressed default drifts on import)."
  type        = string
  default     = "omit"

  validation {
    condition     = contains(["omit", "enable"], var.waf_ai_mode)
    error_message = "waf_ai_mode must be \"omit\" or \"enable\"."
  }
}

variable "waf_ai_risk_action" {
  description = "risk_score_action_choice when waf_ai_mode=enable: high (mitigate_high_risk_action) or high_medium (mitigate_high_medium_risk_action)."
  type        = string
  default     = "high"

  validation {
    condition     = contains(["high", "high_medium"], var.waf_ai_risk_action)
    error_message = "waf_ai_risk_action must be \"high\" or \"high_medium\"."
  }
}

variable "waf_detection_mode" {
  description = "detection_setting_choice: default (default_detection_settings) or custom (explicit detection_settings)."
  type        = string
  default     = "default"

  validation {
    condition     = contains(["default", "custom"], var.waf_detection_mode)
    error_message = "waf_detection_mode must be \"default\" or \"custom\"."
  }
}

variable "waf_violation_mode" {
  description = "detection_settings violation_detection_setting: default or custom (disabled_violation_types list)."
  type        = string
  default     = "default"

  validation {
    condition     = contains(["default", "custom"], var.waf_violation_mode)
    error_message = "waf_violation_mode must be \"default\" or \"custom\"."
  }
}

variable "waf_disabled_violation_types" {
  description = "Violation types to disable when waf_violation_mode=custom (<=40 entries)."
  type        = list(string)
  default     = []

  validation {
    condition     = length(var.waf_disabled_violation_types) <= 40
    error_message = "waf_disabled_violation_types must have at most 40 entries."
  }
}

variable "waf_staging_mode" {
  description = "detection_settings signatures_staging_settings: disable, new (stage_new_signatures), or new_and_updated."
  type        = string
  default     = "disable"

  validation {
    condition     = contains(["disable", "new", "new_and_updated"], var.waf_staging_mode)
    error_message = "waf_staging_mode must be \"disable\", \"new\", or \"new_and_updated\"."
  }
}

variable "waf_staging_period" {
  description = "Staging period (days) when waf_staging_mode is new or new_and_updated."
  type        = number
  default     = 7
}

variable "waf_suppression" {
  description = "detection_settings false_positive_suppression: enable or disable."
  type        = string
  default     = "enable"

  validation {
    condition     = contains(["enable", "disable"], var.waf_suppression)
    error_message = "waf_suppression must be \"enable\" or \"disable\"."
  }
}

variable "waf_threat_campaigns" {
  description = "detection_settings threat_campaign_choice: enable or disable."
  type        = string
  default     = "enable"

  validation {
    condition     = contains(["enable", "disable"], var.waf_threat_campaigns)
    error_message = "waf_threat_campaigns must be \"enable\" or \"disable\"."
  }
}

variable "waf_detection_bot_mode" {
  description = "detection_settings nested bot_protection_choice: default or custom."
  type        = string
  default     = "default"

  validation {
    condition     = contains(["default", "custom"], var.waf_detection_bot_mode)
    error_message = "waf_detection_bot_mode must be \"default\" or \"custom\"."
  }
}

variable "waf_signature_accuracy" {
  description = "detection_settings signature_selection_by_accuracy: only_high, high_medium, or high_medium_low."
  type        = string
  default     = "high_medium"

  validation {
    condition     = contains(["only_high", "high_medium", "high_medium_low"], var.waf_signature_accuracy)
    error_message = "waf_signature_accuracy must be only_high, high_medium, or high_medium_low."
  }
}

variable "waf_attack_type_mode" {
  description = "detection_settings attack_type_setting: default or custom (disabled_attack_types list)."
  type        = string
  default     = "default"

  validation {
    condition     = contains(["default", "custom"], var.waf_attack_type_mode)
    error_message = "waf_attack_type_mode must be \"default\" or \"custom\"."
  }
}

variable "waf_disabled_attack_types" {
  description = "Attack types to disable when waf_attack_type_mode=custom (<=22 entries)."
  type        = list(string)
  default     = []

  validation {
    condition     = length(var.waf_disabled_attack_types) <= 22
    error_message = "waf_disabled_attack_types must have at most 22 entries."
  }
}
