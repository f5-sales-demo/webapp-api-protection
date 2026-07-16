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
      # ASN matcher oneof: any (default) | list (inline as_numbers) | matcher (asn_matcher
      # referencing bgp_asn_set objects by name, SPol-2b). asn_sets names must be defined in
      # var.service_policy_bgp_asn_sets.
      asn         = optional(string, "any") # any|list|matcher
      asn_numbers = optional(list(number), [])
      asn_sets    = optional(list(string), [])
      # IP matcher oneof: any (default) | prefix_list (inline) | matcher (ip_matcher
      # referencing ip_prefix_set objects by name, SPol-2b). ip_prefix_sets names must be
      # defined in var.service_policy_ip_prefix_sets.
      ip             = optional(string, "any") # any|prefix_list|matcher
      ip_prefixes    = optional(list(string), [])
      ip_prefix_sets = optional(list(string), [])
      ip_invert      = optional(bool, false)
      # SPol-2 TLS-fingerprint matcher oneof: none (default, omit) | matcher (classes/exact/
      # excluded) | ja4 (exact JA4 hashes).
      tls          = optional(string, "none") # none|matcher|ja4
      tls_classes  = optional(list(string), [])
      tls_exact    = optional(list(string), [])
      tls_excluded = optional(list(string), [])
      ja4_exact    = optional(list(string), [])
      # SPol-3 request matchers (additive AND within a rule; omitted = no constraint).
      http_methods        = optional(list(string), []) # ANY|GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH|COPY
      http_methods_invert = optional(bool, false)
      path_exact          = optional(list(string), []) # path oneof: parallel *_values lists
      path_prefix         = optional(list(string), [])
      path_regex          = optional(list(string), [])
      path_suffix         = optional(list(string), [])
      path_invert         = optional(bool, false)
      domain_exact        = optional(list(string), [])
      domain_regex        = optional(list(string), [])
      headers = optional(list(object({
        name         = string
        presence     = optional(string, "match") # match|present|absent
        invert       = optional(bool, false)
        exact_values = optional(list(string), [])
        regex_values = optional(list(string), [])
      })), [])
      query_params = optional(list(object({
        key          = string
        presence     = optional(string, "match") # match|present|absent
        invert       = optional(bool, false)
        exact_values = optional(list(string), [])
        regex_values = optional(list(string), [])
      })), [])
      # Action-side waf_action oneof (required on every rule): none default | skip =
      # waf_skip_processing | detection_control = app_firewall_detection_control. skip and
      # detection_control require action != DENY (F5 XC: "WAF Action cannot be configured for
      # a rule with action DENY" — live-verified). bot_action/mum_action are omitted by
      # default (server returns null; a concrete skip arm emits the block) and are INDEPENDENT
      # of waf_action and each other (the SPol-4a all-or-nothing precondition was a
      # misdiagnosis of the DENY rejection — corrected here).
      waf_action_mode = optional(string, "none") # none|skip|detection_control
      bot_action_mode = optional(string, "omit") # omit|skip
      mum_action_mode = optional(string, "omit") # omit|skip
      # SPol-4b detection_control (waf_action_mode="detection_control") exclusion lists. Each
      # entry excludes a signature/violation/attack-type/bot-name from triggering. context
      # defaults CONTEXT_ANY and context_name "" (server-filled) — emitted explicitly to stay
      # import-clean. Requires >= 1 exclusion when the mode is selected.
      waf_exclude_attack_type_contexts = optional(list(object({
        context             = optional(string, "CONTEXT_ANY")
        context_name        = optional(string, "")
        exclude_attack_type = string
      })), [])
      waf_exclude_violation_contexts = optional(list(object({
        context           = optional(string, "CONTEXT_ANY")
        context_name      = optional(string, "")
        exclude_violation = string
      })), [])
      waf_exclude_signature_contexts = optional(list(object({
        context      = optional(string, "CONTEXT_ANY")
        context_name = optional(string, "")
        signature_id = number # 0 or 200000001-299999999
      })), [])
      waf_exclude_bot_names = optional(list(string), [])
      # SPol-4b segment_policy source/destination markers (src_segments/dst_segments Segment
      # refs deferred to a later ref slice). Any combination is accepted; the block is emitted
      # only when a marker is selected. Read-back is exact (no provider change).
      segment_src   = optional(string, "omit") # omit|any
      segment_dst   = optional(string, "omit") # omit|any
      segment_intra = optional(bool, false)
      # SPol-4b request_constraints: when enabled, ALL 13 dimensions are emitted (a set max_*
      # value => max_*_exceeds, an unset one => max_*_none marker). The server echoes the none
      # marker for every unset dimension, so emitting all 13 keeps the plan import-clean.
      request_constraints_enabled = optional(bool, false)
      max_cookie_count            = optional(number)
      max_cookie_key_size         = optional(number)
      max_cookie_value_size       = optional(number)
      max_header_count            = optional(number)
      max_header_key_size         = optional(number)
      max_header_value_size       = optional(number)
      max_parameter_count         = optional(number)
      max_parameter_name_size     = optional(number)
      max_parameter_value_size    = optional(number)
      max_query_size              = optional(number)
      max_request_line_size       = optional(number)
      max_request_size            = optional(number)
      max_url_size                = optional(number)
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
      for r in coalesce(p.rules, []) : contains(["any", "list", "matcher"], r.asn)
    ])])
    error_message = "each rule.asn must be any, list, or matcher."
  }
  validation {
    condition = alltrue([for p in var.service_policies : alltrue([
      for r in coalesce(p.rules, []) : contains(["any", "prefix_list", "matcher"], r.ip)
    ])])
    error_message = "each rule.ip must be any, prefix_list, or matcher."
  }
  # SPol-2b ref-arm integrity: a matcher arm needs >= 1 referenced set, and every referenced
  # name must be defined in the corresponding set variable (fail fast instead of a live 404).
  validation {
    condition = alltrue([for p in var.service_policies : alltrue([
      for r in coalesce(p.rules, []) :
      r.asn != "matcher" || (length(r.asn_sets) > 0 && alltrue([
        for n in r.asn_sets : contains([for s in var.service_policy_bgp_asn_sets : s.name], n)
      ]))
    ])])
    error_message = "rule.asn=\"matcher\" requires asn_sets to name >= 1 set defined in service_policy_bgp_asn_sets."
  }
  validation {
    condition = alltrue([for p in var.service_policies : alltrue([
      for r in coalesce(p.rules, []) :
      r.ip != "matcher" || (length(r.ip_prefix_sets) > 0 && alltrue([
        for n in r.ip_prefix_sets : contains([for s in var.service_policy_ip_prefix_sets : s.name], n)
      ]))
    ])])
    error_message = "rule.ip=\"matcher\" requires ip_prefix_sets to name >= 1 set defined in service_policy_ip_prefix_sets."
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

  # SPol-3 http_method enum (ves.io.schema.HttpMethod).
  validation {
    condition = alltrue([for p in var.service_policies : alltrue([
      for r in coalesce(p.rules, []) : alltrue([
        for m in coalesce(r.http_methods, []) : contains([
          "ANY", "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH", "COPY"
        ], m)
      ])
    ])])
    error_message = "each rule.http_methods entry must be a valid HTTP method (GET, POST, DELETE, ANY, ...)."
  }

  # SPol-3 header/query-param presence selector (match=item exact/regex, present/absent=marker).
  validation {
    condition = alltrue([for p in var.service_policies : alltrue([
      for r in coalesce(p.rules, []) : alltrue(concat(
        [for h in coalesce(r.headers, []) : contains(["match", "present", "absent"], h.presence)],
        [for q in coalesce(r.query_params, []) : contains(["match", "present", "absent"], q.presence)]
      ))
    ])])
    error_message = "each rule.headers[]/query_params[] presence must be match, present, or absent."
  }

  # Action-side selectors.
  validation {
    condition = alltrue([for p in var.service_policies : alltrue([
      for r in coalesce(p.rules, []) : contains(["none", "skip", "detection_control"], r.waf_action_mode)
    ])])
    error_message = "each rule.waf_action_mode must be none, skip, or detection_control."
  }
  validation {
    condition = alltrue([for p in var.service_policies : alltrue([
      for r in coalesce(p.rules, []) : contains(["omit", "skip"], r.bot_action_mode) && contains(["omit", "skip"], r.mum_action_mode)
    ])])
    error_message = "each rule.bot_action_mode / mum_action_mode must be omit or skip."
  }

  # F5 XC: a configured WAF action (waf_skip_processing or app_firewall_detection_control)
  # cannot be attached to a DENY rule — "WAF Action cannot be configured for a rule with
  # action DENY" (live-verified). waf_action_mode=none is unconstrained; bot_action and
  # mum_action are independent of waf_action and of each other.
  validation {
    condition = alltrue([for p in var.service_policies : alltrue([
      for r in coalesce(p.rules, []) :
      r.waf_action_mode == "none" || r.action != "DENY"
    ])])
    error_message = "rule.waf_action_mode \"skip\"/\"detection_control\" requires action != DENY (F5 XC rejects a WAF action on a DENY rule)."
  }

  # SPol-4b detection_control needs at least one exclusion when selected (an empty block is
  # meaningless), and the exclusion lists are only valid under that mode.
  validation {
    condition = alltrue([for p in var.service_policies : alltrue([
      for r in coalesce(p.rules, []) :
      r.waf_action_mode != "detection_control" || (
        length(r.waf_exclude_attack_type_contexts) + length(r.waf_exclude_violation_contexts) +
        length(r.waf_exclude_signature_contexts) + length(r.waf_exclude_bot_names) > 0
      )
    ])])
    error_message = "rule.waf_action_mode=\"detection_control\" requires at least one waf_exclude_* entry."
  }
  validation {
    condition = alltrue([for p in var.service_policies : alltrue([
      for r in coalesce(p.rules, []) :
      r.waf_action_mode == "detection_control" || (
        length(r.waf_exclude_attack_type_contexts) + length(r.waf_exclude_violation_contexts) +
        length(r.waf_exclude_signature_contexts) + length(r.waf_exclude_bot_names) == 0
      )
    ])])
    error_message = "rule.waf_exclude_* is only valid when waf_action_mode=\"detection_control\"."
  }

  # SPol-4b detection_control enum validations (fail fast at plan instead of a live 400).
  validation {
    condition = alltrue([for p in var.service_policies : alltrue([
      for r in coalesce(p.rules, []) : alltrue([
        for c in concat(r.waf_exclude_attack_type_contexts, r.waf_exclude_violation_contexts, r.waf_exclude_signature_contexts) :
        contains([
          "CONTEXT_ANY", "CONTEXT_BODY", "CONTEXT_REQUEST", "CONTEXT_RESPONSE", "CONTEXT_PARAMETER",
          "CONTEXT_HEADER", "CONTEXT_COOKIE", "CONTEXT_URL", "CONTEXT_URI"
        ], c.context)
      ])
    ])])
    error_message = "each waf_exclude_*.context must be a valid WAF exclusion context (CONTEXT_ANY, CONTEXT_HEADER, CONTEXT_URL, ...)."
  }
  validation {
    condition = alltrue([for p in var.service_policies : alltrue([
      for r in coalesce(p.rules, []) : alltrue([
        for c in r.waf_exclude_attack_type_contexts : contains([
          "ATTACK_TYPE_NONE", "ATTACK_TYPE_NON_BROWSER_CLIENT", "ATTACK_TYPE_OTHER_APPLICATION_ATTACKS",
          "ATTACK_TYPE_TROJAN_BACKDOOR_SPYWARE", "ATTACK_TYPE_DETECTION_EVASION", "ATTACK_TYPE_VULNERABILITY_SCAN",
          "ATTACK_TYPE_ABUSE_OF_FUNCTIONALITY", "ATTACK_TYPE_AUTHENTICATION_AUTHORIZATION_ATTACKS",
          "ATTACK_TYPE_BUFFER_OVERFLOW", "ATTACK_TYPE_PREDICTABLE_RESOURCE_LOCATION", "ATTACK_TYPE_INFORMATION_LEAKAGE",
          "ATTACK_TYPE_DIRECTORY_INDEXING", "ATTACK_TYPE_PATH_TRAVERSAL", "ATTACK_TYPE_XPATH_INJECTION",
          "ATTACK_TYPE_LDAP_INJECTION", "ATTACK_TYPE_SERVER_SIDE_CODE_INJECTION", "ATTACK_TYPE_COMMAND_EXECUTION",
          "ATTACK_TYPE_SQL_INJECTION", "ATTACK_TYPE_CROSS_SITE_SCRIPTING", "ATTACK_TYPE_DENIAL_OF_SERVICE",
          "ATTACK_TYPE_HTTP_PARSER_ATTACK", "ATTACK_TYPE_SESSION_HIJACKING", "ATTACK_TYPE_HTTP_RESPONSE_SPLITTING",
          "ATTACK_TYPE_FORCEFUL_BROWSING", "ATTACK_TYPE_REMOTE_FILE_INCLUDE", "ATTACK_TYPE_MALICIOUS_FILE_UPLOAD",
          "ATTACK_TYPE_GRAPHQL_PARSER_ATTACK"
        ], c.exclude_attack_type)
      ])
    ])])
    error_message = "each waf_exclude_attack_type_contexts[].exclude_attack_type must be a valid ATTACK_TYPE_* value."
  }
  validation {
    condition = alltrue([for p in var.service_policies : alltrue([
      for r in coalesce(p.rules, []) : alltrue([
        for c in r.waf_exclude_violation_contexts : contains([
          "VIOL_NONE", "VIOL_FILETYPE", "VIOL_METHOD", "VIOL_MANDATORY_HEADER", "VIOL_HTTP_RESPONSE_STATUS",
          "VIOL_REQUEST_MAX_LENGTH", "VIOL_FILE_UPLOAD", "VIOL_FILE_UPLOAD_IN_BODY", "VIOL_XML_MALFORMED",
          "VIOL_JSON_MALFORMED", "VIOL_ASM_COOKIE_MODIFIED", "VIOL_HTTP_PROTOCOL_MULTIPLE_HOST_HEADERS",
          "VIOL_HTTP_PROTOCOL_BAD_HOST_HEADER_VALUE", "VIOL_HTTP_PROTOCOL_UNPARSABLE_REQUEST_CONTENT",
          "VIOL_HTTP_PROTOCOL_NULL_IN_REQUEST", "VIOL_HTTP_PROTOCOL_BAD_HTTP_VERSION",
          "VIOL_HTTP_PROTOCOL_SEVERAL_CONTENT_LENGTH_HEADERS", "VIOL_EVASION_DIRECTORY_TRAVERSALS",
          "VIOL_MALFORMED_REQUEST", "VIOL_EVASION_MULTIPLE_DECODING", "VIOL_DATA_GUARD",
          "VIOL_EVASION_APACHE_WHITESPACE", "VIOL_COOKIE_MODIFIED", "VIOL_EVASION_IIS_UNICODE_CODEPOINTS",
          "VIOL_EVASION_IIS_BACKSLASHES", "VIOL_EVASION_PERCENT_U_DECODING", "VIOL_EVASION_BARE_BYTE_DECODING",
          "VIOL_EVASION_BAD_UNESCAPE", "VIOL_HTTP_PROTOCOL_BODY_IN_GET_OR_HEAD_REQUEST", "VIOL_ENCODING",
          "VIOL_COOKIE_MALFORMED", "VIOL_GRAPHQL_FORMAT", "VIOL_GRAPHQL_MALFORMED", "VIOL_GRAPHQL_INTROSPECTION_QUERY"
        ], c.exclude_violation)
      ])
    ])])
    error_message = "each waf_exclude_violation_contexts[].exclude_violation must be a valid VIOL_* value."
  }
  validation {
    condition = alltrue([for p in var.service_policies : alltrue([
      for r in coalesce(p.rules, []) : alltrue([
        for c in r.waf_exclude_signature_contexts : c.signature_id == 0 || (c.signature_id >= 200000001 && c.signature_id <= 299999999)
      ])
    ])])
    error_message = "each waf_exclude_signature_contexts[].signature_id must be 0 or in 200000001-299999999."
  }

  # SPol-4b segment_policy source/destination marker selectors.
  validation {
    condition = alltrue([for p in var.service_policies : alltrue([
      for r in coalesce(p.rules, []) : contains(["omit", "any"], r.segment_src) && contains(["omit", "any"], r.segment_dst)
    ])])
    error_message = "each rule.segment_src / segment_dst must be omit or any (segments refs are deferred)."
  }
}

variable "service_policy_bgp_asn_sets" {
  description = "bgp_asn_set objects to create for SPol-2b asn_matcher ref arms. Referenced by name from a rule's asn_sets when asn=\"matcher\"."
  type = list(object({
    name       = string
    as_numbers = list(number)
  }))
  default = []
}

variable "service_policy_ip_prefix_sets" {
  description = "ip_prefix_set objects to create for SPol-2b ip_matcher ref arms. Referenced by name from a rule's ip_prefix_sets when ip=\"matcher\"."
  type = list(object({
    name          = string
    ipv4_prefixes = list(string)
  }))
  default = []
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
