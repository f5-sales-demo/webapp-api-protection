# API protection rules (Coverage Batch D) — allow/deny access to API endpoints
# (api_endpoint_rules) or server URLs / API groups (api_protection_group_rules),
# each optionally scoped by a PER-RULE client_matcher (full oneof) and request_matcher.
# Replaces the SP3 module-level shared client_matcher. Omit a matcher for "match any"
# (any_client server default, import-suppressed). Empty lists => 0-change.
variable "api_protection_rules" {
  description = "api_protection_rules.api_endpoint_rules: {path, domain, methods, action allow|deny, per-rule client_matcher, request_matcher}."
  type = list(object({
    path           = string
    domain_mode    = optional(string, "any") # any | specific
    domain         = optional(string)
    methods        = optional(list(string), ["ANY"])
    methods_invert = optional(bool, false)
    action         = optional(string, "allow") # allow | deny
    client_matcher = optional(object({
      mode                 = optional(string) # any_ip|asn_list|asn_matcher|client_selector|ip_matcher|ip_prefix_list|ip_threat_category_list|tls_fingerprint_matcher
      as_numbers           = optional(list(number), [])
      asn_sets             = optional(list(object({ name = string, namespace = optional(string) })), [])
      selector_expressions = optional(list(string), [])
      ip_prefix_sets       = optional(list(object({ name = string, namespace = optional(string) })), [])
      ip_prefixes          = optional(list(string), [])
      ip_invert            = optional(bool, false)
      ip_threat_categories = optional(list(string), [])
      tls_classes          = optional(list(string), [])
      tls_exact_values     = optional(list(string), [])
      tls_excluded_values  = optional(list(string), [])
    }))
    request_matcher = optional(object({
      cookies      = optional(list(object({ name = string, invert = optional(bool, false), presence = optional(string, "match"), exact_values = optional(list(string), []), regex_values = optional(list(string), []) })), [])
      headers      = optional(list(object({ name = string, invert = optional(bool, false), presence = optional(string, "match"), exact_values = optional(list(string), []), regex_values = optional(list(string), []) })), [])
      jwt_claims   = optional(list(object({ name = string, invert = optional(bool, false), presence = optional(string, "match"), exact_values = optional(list(string), []), regex_values = optional(list(string), []) })), [])
      query_params = optional(list(object({ name = string, invert = optional(bool, false), presence = optional(string, "match"), exact_values = optional(list(string), []), regex_values = optional(list(string), []) })), [])
    }))
  }))
  default = []

  validation {
    condition = alltrue([
      for r in var.api_protection_rules : contains(["any", "specific"], r.domain_mode)
    ])
    error_message = "each api_protection_rules domain_mode must be any or specific."
  }

  validation {
    condition = alltrue([
      for r in var.api_protection_rules : r.domain_mode == "any" || r.domain != null
    ])
    error_message = "api_protection_rules with domain_mode specific require a domain."
  }

  validation {
    condition = alltrue([
      for r in var.api_protection_rules : contains(["allow", "deny"], r.action)
    ])
    error_message = "each api_protection_rules action must be allow or deny."
  }

  validation {
    condition = alltrue([
      for r in var.api_protection_rules : alltrue([
        for m in r.methods :
        contains(["ANY", "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH", "COPY"], m)
      ])
    ])
    error_message = "each api_protection_rules method must be a valid HTTP method."
  }

  validation {
    condition = alltrue([
      for r in var.api_protection_rules :
      r.client_matcher == null || r.client_matcher.mode == null || contains(["any_ip", "asn_list", "asn_matcher", "client_selector", "ip_matcher", "ip_prefix_list", "ip_threat_category_list", "tls_fingerprint_matcher"], r.client_matcher.mode)
    ])
    error_message = "api_protection_rules client_matcher.mode is invalid (omit=any_client)."
  }

  validation {
    condition = alltrue([
      for r in var.api_protection_rules :
      r.client_matcher == null || r.client_matcher.mode == null || (
        (r.client_matcher.mode != "asn_list" || length(r.client_matcher.as_numbers) > 0) &&
        (r.client_matcher.mode != "asn_matcher" || length(r.client_matcher.asn_sets) > 0) &&
        (r.client_matcher.mode != "client_selector" || length(r.client_matcher.selector_expressions) > 0) &&
        (r.client_matcher.mode != "ip_matcher" || length(r.client_matcher.ip_prefix_sets) > 0) &&
        (r.client_matcher.mode != "ip_prefix_list" || length(r.client_matcher.ip_prefixes) > 0) &&
        (r.client_matcher.mode != "ip_threat_category_list" || length(r.client_matcher.ip_threat_categories) > 0)
      )
    ])
    error_message = "api_protection_rules: a selected client_matcher.mode needs its payload list (asn_list⇒as_numbers, asn_matcher⇒asn_sets, client_selector⇒selector_expressions, ip_matcher⇒ip_prefix_sets, ip_prefix_list⇒ip_prefixes, ip_threat_category_list⇒ip_threat_categories)."
  }

  validation {
    condition = alltrue([
      for r in var.api_protection_rules :
      r.client_matcher == null || alltrue([
        for c in r.client_matcher.tls_classes :
        contains(["TLS_FINGERPRINT_NONE", "ANY_MALICIOUS_FINGERPRINT", "ADWARE", "ADWIND", "DRIDEX", "GOOTKIT", "GOZI", "JBIFROST", "QUAKBOT", "RANSOMWARE", "TROLDESH", "TOFSEE", "TORRENTLOCKER", "TRICKBOT"], c)
      ])
    ])
    error_message = "api_protection_rules client_matcher.tls_classes must be valid KnownTlsFingerprintClass enums (e.g. ANY_MALICIOUS_FINGERPRINT, TRICKBOT)."
  }

  validation {
    condition = alltrue([
      for r in var.api_protection_rules :
      r.client_matcher == null || alltrue([
        for c in r.client_matcher.ip_threat_categories :
        contains(["SPAM_SOURCES", "WINDOWS_EXPLOITS", "WEB_ATTACKS", "BOTNETS", "SCANNERS", "REPUTATION", "PHISHING", "PROXY", "MOBILE_THREATS", "TOR_PROXY", "DENIAL_OF_SERVICE", "NETWORK"], c)
      ])
    ])
    error_message = "api_protection_rules client_matcher.ip_threat_categories must be valid F5 XC IP threat category enums."
  }

  validation {
    condition = alltrue([
      for r in var.api_protection_rules :
      r.request_matcher == null || alltrue([
        for m in concat(r.request_matcher.cookies, r.request_matcher.headers, r.request_matcher.jwt_claims, r.request_matcher.query_params) :
        contains(["present", "absent", "match"], m.presence)
      ])
    ])
    error_message = "api_protection_rules request_matcher presence must be present, absent, or match."
  }
}

variable "api_protection_group_rules" {
  description = "api_protection_rules.api_groups_rules: {api_group, base_path, domain, action allow|deny, per-rule client_matcher, request_matcher}."
  type = list(object({
    api_group   = optional(string)
    base_path   = optional(string)
    domain_mode = optional(string, "any") # any | specific
    domain      = optional(string)
    action      = optional(string, "allow") # allow | deny
    client_matcher = optional(object({
      mode                 = optional(string)
      as_numbers           = optional(list(number), [])
      asn_sets             = optional(list(object({ name = string, namespace = optional(string) })), [])
      selector_expressions = optional(list(string), [])
      ip_prefix_sets       = optional(list(object({ name = string, namespace = optional(string) })), [])
      ip_prefixes          = optional(list(string), [])
      ip_invert            = optional(bool, false)
      ip_threat_categories = optional(list(string), [])
      tls_classes          = optional(list(string), [])
      tls_exact_values     = optional(list(string), [])
      tls_excluded_values  = optional(list(string), [])
    }))
    request_matcher = optional(object({
      cookies      = optional(list(object({ name = string, invert = optional(bool, false), presence = optional(string, "match"), exact_values = optional(list(string), []), regex_values = optional(list(string), []) })), [])
      headers      = optional(list(object({ name = string, invert = optional(bool, false), presence = optional(string, "match"), exact_values = optional(list(string), []), regex_values = optional(list(string), []) })), [])
      jwt_claims   = optional(list(object({ name = string, invert = optional(bool, false), presence = optional(string, "match"), exact_values = optional(list(string), []), regex_values = optional(list(string), []) })), [])
      query_params = optional(list(object({ name = string, invert = optional(bool, false), presence = optional(string, "match"), exact_values = optional(list(string), []), regex_values = optional(list(string), []) })), [])
    }))
  }))
  default = []

  validation {
    condition = alltrue([
      for r in var.api_protection_group_rules : contains(["any", "specific"], r.domain_mode)
    ])
    error_message = "each api_protection_group_rules domain_mode must be any or specific."
  }

  validation {
    condition = alltrue([
      for r in var.api_protection_group_rules : r.domain_mode == "any" || r.domain != null
    ])
    error_message = "api_protection_group_rules with domain_mode specific require a domain."
  }

  validation {
    condition = alltrue([
      for r in var.api_protection_group_rules : contains(["allow", "deny"], r.action)
    ])
    error_message = "each api_protection_group_rules action must be allow or deny."
  }

  validation {
    condition = alltrue([
      for r in var.api_protection_group_rules : r.api_group != null || r.base_path != null
    ])
    error_message = "each api_protection_group_rules must set api_group or base_path."
  }

  validation {
    condition = alltrue([
      for r in var.api_protection_group_rules :
      r.client_matcher == null || r.client_matcher.mode == null || contains(["any_ip", "asn_list", "asn_matcher", "client_selector", "ip_matcher", "ip_prefix_list", "ip_threat_category_list", "tls_fingerprint_matcher"], r.client_matcher.mode)
    ])
    error_message = "api_protection_group_rules client_matcher.mode is invalid (omit=any_client)."
  }

  validation {
    condition = alltrue([
      for r in var.api_protection_group_rules :
      r.client_matcher == null || r.client_matcher.mode == null || (
        (r.client_matcher.mode != "asn_list" || length(r.client_matcher.as_numbers) > 0) &&
        (r.client_matcher.mode != "asn_matcher" || length(r.client_matcher.asn_sets) > 0) &&
        (r.client_matcher.mode != "client_selector" || length(r.client_matcher.selector_expressions) > 0) &&
        (r.client_matcher.mode != "ip_matcher" || length(r.client_matcher.ip_prefix_sets) > 0) &&
        (r.client_matcher.mode != "ip_prefix_list" || length(r.client_matcher.ip_prefixes) > 0) &&
        (r.client_matcher.mode != "ip_threat_category_list" || length(r.client_matcher.ip_threat_categories) > 0)
      )
    ])
    error_message = "api_protection_group_rules: a selected client_matcher.mode needs its payload list (see api_protection_rules message)."
  }

  validation {
    condition = alltrue([
      for r in var.api_protection_group_rules :
      r.client_matcher == null || alltrue([
        for c in r.client_matcher.tls_classes :
        contains(["TLS_FINGERPRINT_NONE", "ANY_MALICIOUS_FINGERPRINT", "ADWARE", "ADWIND", "DRIDEX", "GOOTKIT", "GOZI", "JBIFROST", "QUAKBOT", "RANSOMWARE", "TROLDESH", "TOFSEE", "TORRENTLOCKER", "TRICKBOT"], c)
      ])
    ])
    error_message = "api_protection_group_rules client_matcher.tls_classes must be valid KnownTlsFingerprintClass enums."
  }

  validation {
    condition = alltrue([
      for r in var.api_protection_group_rules :
      r.client_matcher == null || alltrue([
        for c in r.client_matcher.ip_threat_categories :
        contains(["SPAM_SOURCES", "WINDOWS_EXPLOITS", "WEB_ATTACKS", "BOTNETS", "SCANNERS", "REPUTATION", "PHISHING", "PROXY", "MOBILE_THREATS", "TOR_PROXY", "DENIAL_OF_SERVICE", "NETWORK"], c)
      ])
    ])
    error_message = "api_protection_group_rules client_matcher.ip_threat_categories must be valid F5 XC IP threat category enums."
  }

  validation {
    condition = alltrue([
      for r in var.api_protection_group_rules :
      r.request_matcher == null || alltrue([
        for m in concat(r.request_matcher.cookies, r.request_matcher.headers, r.request_matcher.jwt_claims, r.request_matcher.query_params) :
        contains(["present", "absent", "match"], m.presence)
      ])
    ])
    error_message = "api_protection_group_rules request_matcher presence must be present, absent, or match."
  }
}
