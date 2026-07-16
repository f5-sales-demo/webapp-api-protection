# Service policies (SPol effort). Standalone xcsh_service_policy objects created by
# service_policy.tf (for_each by name), attached to the LB via the service_policies_choice
# oneof in main.tf. SPol-1 (foundation) covers the two outer oneofs — rule-handling and
# server scope — plus a minimal rule_list; per-rule matchers/actions/constraints land in
# SPol-2..4. Defaults create nothing and emit no LB block (0-change; server default
# service_policies_from_namespace, import-suppressed).

variable "service_policies" {
  description = "Standalone xcsh_service_policy objects to create. Each selects a rule-handling arm and a server-scope arm; rule_list supplies inline rules."
  type = list(object({
    name              = string
    rule_handling     = optional(string, "allow_all")  # allow_all|deny_all|allow_list|deny_list|rule_list
    server_scope      = optional(string, "any_server") # any_server|name|name_matcher|selector
    server_name       = optional(string)
    server_name_exact = optional(list(string), [])
    server_name_regex = optional(list(string), [])
    server_selector   = optional(list(string), [])
    rules = optional(list(object({
      name   = string
      action = optional(string, "DENY") # DENY|ALLOW|NEXT_POLICY (provider-validated)
      # SPol-2 client matcher oneof: any (default, omit -> server any_client) | selector |
      # name | name_matcher | ip_threat. Concrete arms; the server echoes any_client
      # alongside, suppressed on import.
      client               = optional(string, "any") # any|selector|name|name_matcher|ip_threat
      client_selector      = optional(list(string), [])
      client_name          = optional(string)
      client_name_exact    = optional(list(string), [])
      client_name_regex    = optional(list(string), [])
      ip_threat_categories = optional(list(string), [])
      # SPol-2 ASN matcher oneof: any (default) | list (inline as_numbers). asn_matcher
      # (bgp_asn_set ref) is SPol-2b.
      asn         = optional(string, "any") # any|list
      asn_numbers = optional(list(number), [])
      # SPol-2 IP matcher oneof: any (default) | prefix_list (inline). ip_matcher
      # (ip_prefix_set ref) is SPol-2b.
      ip          = optional(string, "any") # any|prefix_list
      ip_prefixes = optional(list(string), [])
      ip_invert   = optional(bool, false)
      # SPol-2 TLS-fingerprint matcher oneof: none (default, omit) | matcher (classes/exact/
      # excluded) | ja4 (exact JA4 hashes).
      tls          = optional(string, "none") # none|matcher|ja4
      tls_classes  = optional(list(string), [])
      tls_exact    = optional(list(string), [])
      tls_excluded = optional(list(string), [])
      ja4_exact    = optional(list(string), [])
    })), [])
  }))
  default = []

  validation {
    condition     = alltrue([for p in var.service_policies : contains(["allow_all", "deny_all", "allow_list", "deny_list", "rule_list"], p.rule_handling)])
    error_message = "each service_policies[].rule_handling must be allow_all, deny_all, allow_list, deny_list, or rule_list."
  }

  validation {
    condition     = alltrue([for p in var.service_policies : contains(["any_server", "name", "name_matcher", "selector"], p.server_scope)])
    error_message = "each service_policies[].server_scope must be any_server, name, name_matcher, or selector."
  }

  # rule_list is the only arm that carries rules; a stray rules list on another arm is a
  # config error (the rule would be silently dropped).
  validation {
    condition     = alltrue([for p in var.service_policies : length(coalesce(p.rules, [])) == 0 || p.rule_handling == "rule_list"])
    error_message = "service_policies[].rules is only valid when rule_handling=\"rule_list\"."
  }

  # SPol-2 matcher selectors.
  validation {
    condition = alltrue([for p in var.service_policies : alltrue([
      for r in coalesce(p.rules, []) : contains(["any", "selector", "name", "name_matcher", "ip_threat"], r.client)
    ])])
    error_message = "each rule.client must be any, selector, name, name_matcher, or ip_threat."
  }
  validation {
    condition = alltrue([for p in var.service_policies : alltrue([
      for r in coalesce(p.rules, []) : contains(["any", "list"], r.asn)
    ])])
    error_message = "each rule.asn must be any or list."
  }
  validation {
    condition = alltrue([for p in var.service_policies : alltrue([
      for r in coalesce(p.rules, []) : contains(["any", "prefix_list"], r.ip)
    ])])
    error_message = "each rule.ip must be any or prefix_list."
  }
  validation {
    condition = alltrue([for p in var.service_policies : alltrue([
      for r in coalesce(p.rules, []) : contains(["none", "matcher", "ja4"], r.tls)
    ])])
    error_message = "each rule.tls must be none, matcher, or ja4."
  }

  # ip_threat_categories enum (ves.io.schema.policy IpThreatCategory) — fail fast at plan
  # instead of a live 400.
  validation {
    condition = alltrue([for p in var.service_policies : alltrue([
      for r in coalesce(p.rules, []) : alltrue([
        for c in coalesce(r.ip_threat_categories, []) : contains([
          "SPAM_SOURCES", "WINDOWS_EXPLOITS", "WEB_ATTACKS", "BOTNETS", "SCANNERS",
          "REPUTATION", "PHISHING", "PROXY", "MOBILE_THREATS", "TOR_PROXY",
          "DENIAL_OF_SERVICE", "NETWORK"
        ], c)
      ])
    ])])
    error_message = "each rule.ip_threat_categories entry must be a valid IpThreatCategory (e.g. BOTNETS, SPAM_SOURCES, TOR_PROXY)."
  }

  # tls_fingerprint_classes enum (KnownTlsFingerprintClass).
  validation {
    condition = alltrue([for p in var.service_policies : alltrue([
      for r in coalesce(p.rules, []) : alltrue([
        for c in coalesce(r.tls_classes, []) : contains([
          "TLS_FINGERPRINT_NONE", "ANY_MALICIOUS_FINGERPRINT", "ADWARE", "ADWIND",
          "DRIDEX", "GOOTKIT", "GOZI", "JBIFROST", "QUAKBOT", "RANSOMWARE",
          "TROLDESH", "TOFSEE", "TORRENTLOCKER", "TRICKBOT"
        ], c)
      ])
    ])])
    error_message = "each rule.tls_classes entry must be a valid KnownTlsFingerprintClass (e.g. TRICKBOT, ANY_MALICIOUS_FINGERPRINT)."
  }
}

variable "service_policies_choice" {
  description = "LB service_policies_choice arm: omit (server default service_policies_from_namespace, import-clean), none (no_service_policies), or active (active_service_policies referencing service_policy_active)."
  type        = string
  default     = "omit"

  validation {
    condition     = contains(["omit", "none", "active"], var.service_policies_choice)
    error_message = "service_policies_choice must be omit, none, or active."
  }
}

variable "service_policy_active" {
  description = "Ordered service policy names (from service_policies) to attach when service_policies_choice=active. Order is load-bearing: policies are evaluated top-to-bottom."
  type        = list(string)
  default     = []
}
