# Client access control (CAC effort) on the HTTP LB: trusted_clients / blocked_clients
# (client match rules by IP prefix / IPv6 prefix / ASN / user identifier, with optional
# SKIP_PROCESSING_* actions) and enable_ip_reputation (block clients whose source IP falls
# in the given IpThreatCategory list). Defaults create nothing and emit no LB block (0-change).
#
# Validations are self-contained per variable (no cross-variable references) to stay within
# the module's required_version >= 1.5. The SKIP_PROCESSING_* and IpThreatCategory enums are
# inlined (matching the service_policy convention).

variable "trusted_clients" {
  description = "Trusted-client rules on the LB: matched clients bypass the security processing named in actions (SKIP_PROCESSING_*). Match by exactly one of ip_prefix / ipv6_prefix / as_number / user_identifier."
  type = list(object({
    name                 = optional(string)           # metadata.name (auto-generated if unset)
    ip_prefix            = optional(string)           # IPv4 CIDR, e.g. 192.0.2.0/24
    ipv6_prefix          = optional(string)           # IPv6 CIDR
    as_number            = optional(number)           # BGP ASN
    user_identifier      = optional(string)           # match by user identifier value
    actions              = optional(list(string), []) # SKIP_PROCESSING_* (server default WAF when empty)
    expiration_timestamp = optional(string)           # RFC3339; rule ignored after this time
  }))
  default = []

  validation {
    condition = alltrue([
      for c in var.trusted_clients :
      length([for k in [c.ip_prefix, c.ipv6_prefix, c.as_number, c.user_identifier] : k if k != null]) == 1
    ])
    error_message = "each trusted_clients[] rule must set exactly one of ip_prefix, ipv6_prefix, as_number, or user_identifier."
  }
  validation {
    condition = alltrue([
      for c in var.trusted_clients : alltrue([
        for a in c.actions : contains(["SKIP_PROCESSING_WAF", "SKIP_PROCESSING_BOT", "SKIP_PROCESSING_MUM", "SKIP_PROCESSING_IP_REPUTATION", "SKIP_PROCESSING_API_PROTECTION", "SKIP_PROCESSING_OAS_VALIDATION", "SKIP_PROCESSING_DDOS_PROTECTION", "SKIP_PROCESSING_THREAT_MESH", "SKIP_PROCESSING_MALWARE_PROTECTION"], a)
      ])
    ])
    error_message = "each trusted_clients[].actions entry must be a valid SKIP_PROCESSING_* value."
  }
}

variable "blocked_clients" {
  description = "Blocked-client rules on the LB: matched clients are blocked (or have the named SKIP_PROCESSING_* actions applied). Match by exactly one of ip_prefix / ipv6_prefix / as_number / user_identifier."
  type = list(object({
    name                 = optional(string)
    ip_prefix            = optional(string)
    ipv6_prefix          = optional(string)
    as_number            = optional(number)
    user_identifier      = optional(string)
    actions              = optional(list(string), [])
    expiration_timestamp = optional(string)
  }))
  default = []

  validation {
    condition = alltrue([
      for c in var.blocked_clients :
      length([for k in [c.ip_prefix, c.ipv6_prefix, c.as_number, c.user_identifier] : k if k != null]) == 1
    ])
    error_message = "each blocked_clients[] rule must set exactly one of ip_prefix, ipv6_prefix, as_number, or user_identifier."
  }
  validation {
    condition = alltrue([
      for c in var.blocked_clients : alltrue([
        for a in c.actions : contains(["SKIP_PROCESSING_WAF", "SKIP_PROCESSING_BOT", "SKIP_PROCESSING_MUM", "SKIP_PROCESSING_IP_REPUTATION", "SKIP_PROCESSING_API_PROTECTION", "SKIP_PROCESSING_OAS_VALIDATION", "SKIP_PROCESSING_DDOS_PROTECTION", "SKIP_PROCESSING_THREAT_MESH", "SKIP_PROCESSING_MALWARE_PROTECTION"], a)
      ])
    ])
    error_message = "each blocked_clients[].actions entry must be a valid SKIP_PROCESSING_* value."
  }
}

variable "ip_reputation_enabled" {
  description = "Enable IP-reputation filtering on the LB (enable_ip_reputation). When true, clients whose source IP matches ip_reputation_categories are blocked."
  type        = bool
  default     = false
}

variable "ip_reputation_categories" {
  description = "IpThreatCategory values to block when ip_reputation_enabled (e.g. SPAM_SOURCES, BOTNETS, TOR_PROXY). Empty = the server default set."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for c in var.ip_reputation_categories : contains(["SPAM_SOURCES", "WINDOWS_EXPLOITS", "WEB_ATTACKS", "BOTNETS", "SCANNERS", "REPUTATION", "PHISHING", "PROXY", "MOBILE_THREATS", "TOR_PROXY", "DENIAL_OF_SERVICE", "NETWORK"], c)
    ])
    error_message = "each ip_reputation_categories entry must be a valid IpThreatCategory (e.g. BOTNETS, SPAM_SOURCES, TOR_PROXY)."
  }
}
