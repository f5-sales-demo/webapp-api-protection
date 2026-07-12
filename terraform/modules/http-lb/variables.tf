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

variable "mud_challenge_mode" {
  description = "LB challenge integration for MUD auto-mitigation: none, enable_challenge, or policy_based_challenge."
  type        = string
  default     = "enable_challenge"

  validation {
    condition     = contains(["none", "enable_challenge", "policy_based_challenge"], var.mud_challenge_mode)
    error_message = "mud_challenge_mode must be none, enable_challenge, or policy_based_challenge."
  }
}
