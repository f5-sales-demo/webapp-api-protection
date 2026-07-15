# ---------------------------------------------------------------------------
# Per-endpoint API rate limiting (Coverage Batch B) — the api_rate_limit arm of
# rate_limit_choice (the 3rd arm alongside rate_limit and the disable default).
# Selected with rate_limit_choice = "api_rate_limit". Carries:
#   api_endpoint_rules[]        - per endpoint: path/domain/method + a limiter
#                                 (ref or inline) + client_matcher + request_matcher
#   bypass_rate_limiting_rules[]- exempt endpoints/URLs/groups from rate limiting
#   server_url_rules[]          - per base_path/api_group + limiter + client_matcher
#
# The client_matcher oneof (shared by all three rule kinds) selects on the caller:
#   any_client (omit) | any_ip | asn_list | asn_matcher | client_selector |
#   ip_matcher | ip_prefix_list | ip_threat_category_list | tls_fingerprint_matcher
# Server-default any_client/any_ip markers are import-suppressed, so omit=0-change.
# ---------------------------------------------------------------------------

variable "api_rate_limit_endpoint_rules" {
  description = "api_rate_limit.api_endpoint_rules: per-endpoint rate limits (path/method/domain + ref_rate_limiter or inline limiter + optional client_matcher/request_matcher)."
  type = list(object({
    api_endpoint_path = string
    methods           = optional(list(string), [])
    methods_invert    = optional(bool, false)
    specific_domain   = optional(string) # null => any_domain
    # limiter oneof: ref_rate_limiter (a var.rate_limiters name) OR inline_*
    ref_rate_limiter = optional(string)
    inline_threshold = optional(number)
    inline_unit      = optional(string, "MINUTE")  # SECOND | MINUTE | HOUR
    inline_user_id   = optional(string, "http_lb") # http_lb | ref
    inline_user_ref  = optional(string)            # user_identification ref name (inline_user_id=ref)
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
      for r in var.api_rate_limit_endpoint_rules :
      (r.ref_rate_limiter != null) != (r.inline_threshold != null)
    ])
    error_message = "each api_rate_limit_endpoint_rules entry must set exactly one of ref_rate_limiter or inline_threshold."
  }

  validation {
    condition = alltrue([
      for r in var.api_rate_limit_endpoint_rules :
      r.inline_threshold == null || contains(["SECOND", "MINUTE", "HOUR"], r.inline_unit)
    ])
    error_message = "api_rate_limit_endpoint_rules inline_unit must be SECOND, MINUTE, or HOUR."
  }

  validation {
    condition = alltrue([
      for r in var.api_rate_limit_endpoint_rules :
      r.inline_user_id == "http_lb" || (r.inline_user_id == "ref" && r.inline_user_ref != null)
    ])
    error_message = "api_rate_limit_endpoint_rules inline_user_id must be http_lb, or ref with inline_user_ref set."
  }

  validation {
    condition = alltrue([
      for r in var.api_rate_limit_endpoint_rules :
      r.client_matcher == null || r.client_matcher.mode == null || contains(["any_ip", "asn_list", "asn_matcher", "client_selector", "ip_matcher", "ip_prefix_list", "ip_threat_category_list", "tls_fingerprint_matcher"], r.client_matcher.mode)
    ])
    error_message = "api_rate_limit_endpoint_rules client_matcher.mode is invalid (omit=any_client)."
  }

  validation {
    condition = alltrue([
      for r in var.api_rate_limit_endpoint_rules :
      r.client_matcher == null || r.client_matcher.mode == null || (
        (r.client_matcher.mode != "asn_list" || length(r.client_matcher.as_numbers) > 0) &&
        (r.client_matcher.mode != "asn_matcher" || length(r.client_matcher.asn_sets) > 0) &&
        (r.client_matcher.mode != "client_selector" || length(r.client_matcher.selector_expressions) > 0) &&
        (r.client_matcher.mode != "ip_matcher" || length(r.client_matcher.ip_prefix_sets) > 0) &&
        (r.client_matcher.mode != "ip_prefix_list" || length(r.client_matcher.ip_prefixes) > 0) &&
        (r.client_matcher.mode != "ip_threat_category_list" || length(r.client_matcher.ip_threat_categories) > 0)
      )
    ])
    error_message = "api_rate_limit_endpoint_rules: a selected client_matcher.mode needs its payload list (asn_list⇒as_numbers, asn_matcher⇒asn_sets, client_selector⇒selector_expressions, ip_matcher⇒ip_prefix_sets, ip_prefix_list⇒ip_prefixes, ip_threat_category_list⇒ip_threat_categories)."
  }
}

variable "api_rate_limit_bypass_rules" {
  description = "api_rate_limit.bypass_rate_limiting_rules: endpoints/URLs/API groups exempt from rate limiting."
  type = list(object({
    specific_domain = optional(string) # null => any_domain
    # url oneof: any_url | base_path (prefix) | api_endpoint {path, methods} | api_groups
    target           = optional(string, "any_url") # any_url | base_path | api_endpoint | api_groups
    base_path        = optional(string)            # required when target=base_path
    endpoint_path    = optional(string)
    endpoint_methods = optional(list(string), [])
    api_groups       = optional(list(string), [])
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
  }))
  default = []

  validation {
    condition = alltrue([
      for r in var.api_rate_limit_bypass_rules : contains(["any_url", "base_path", "api_endpoint", "api_groups"], r.target)
    ])
    error_message = "api_rate_limit_bypass_rules target must be any_url, base_path, api_endpoint, or api_groups."
  }

  validation {
    condition = alltrue([
      for r in var.api_rate_limit_bypass_rules : r.target != "base_path" || r.base_path != null
    ])
    error_message = "api_rate_limit_bypass_rules with target=base_path require base_path."
  }

  validation {
    condition = alltrue([
      for r in var.api_rate_limit_bypass_rules : r.target != "api_endpoint" || r.endpoint_path != null
    ])
    error_message = "api_rate_limit_bypass_rules with target=api_endpoint require endpoint_path."
  }

  validation {
    condition = alltrue([
      for r in var.api_rate_limit_bypass_rules : r.target != "api_groups" || length(r.api_groups) > 0
    ])
    error_message = "api_rate_limit_bypass_rules with target=api_groups require a non-empty api_groups list."
  }

  validation {
    condition = alltrue([
      for r in var.api_rate_limit_bypass_rules :
      r.client_matcher == null || r.client_matcher.mode == null || contains(["any_ip", "asn_list", "asn_matcher", "client_selector", "ip_matcher", "ip_prefix_list", "ip_threat_category_list", "tls_fingerprint_matcher"], r.client_matcher.mode)
    ])
    error_message = "api_rate_limit_bypass_rules client_matcher.mode is invalid (omit=any_client)."
  }

  validation {
    condition = alltrue([
      for r in var.api_rate_limit_bypass_rules :
      r.client_matcher == null || r.client_matcher.mode == null || (
        (r.client_matcher.mode != "asn_list" || length(r.client_matcher.as_numbers) > 0) &&
        (r.client_matcher.mode != "asn_matcher" || length(r.client_matcher.asn_sets) > 0) &&
        (r.client_matcher.mode != "client_selector" || length(r.client_matcher.selector_expressions) > 0) &&
        (r.client_matcher.mode != "ip_matcher" || length(r.client_matcher.ip_prefix_sets) > 0) &&
        (r.client_matcher.mode != "ip_prefix_list" || length(r.client_matcher.ip_prefixes) > 0) &&
        (r.client_matcher.mode != "ip_threat_category_list" || length(r.client_matcher.ip_threat_categories) > 0)
      )
    ])
    error_message = "api_rate_limit_bypass_rules: a selected client_matcher.mode needs its payload list (see endpoint-rules message)."
  }
}

variable "api_rate_limit_server_url_rules" {
  description = "api_rate_limit.server_url_rules: per base_path/api_group rate limits (limiter + optional client_matcher)."
  type = list(object({
    api_group        = optional(string)
    base_path        = optional(string)
    specific_domain  = optional(string) # null => any_domain
    ref_rate_limiter = optional(string)
    inline_threshold = optional(number)
    inline_unit      = optional(string, "MINUTE")
    inline_user_id   = optional(string, "http_lb")
    inline_user_ref  = optional(string)
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
  }))
  default = []

  validation {
    condition = alltrue([
      for r in var.api_rate_limit_server_url_rules :
      (r.ref_rate_limiter != null) != (r.inline_threshold != null)
    ])
    error_message = "each api_rate_limit_server_url_rules entry must set exactly one of ref_rate_limiter or inline_threshold."
  }

  validation {
    condition = alltrue([
      for r in var.api_rate_limit_server_url_rules :
      r.inline_threshold == null || contains(["SECOND", "MINUTE", "HOUR"], r.inline_unit)
    ])
    error_message = "api_rate_limit_server_url_rules inline_unit must be SECOND, MINUTE, or HOUR."
  }

  validation {
    condition = alltrue([
      for r in var.api_rate_limit_server_url_rules :
      r.inline_user_id == "http_lb" || (r.inline_user_id == "ref" && r.inline_user_ref != null)
    ])
    error_message = "api_rate_limit_server_url_rules inline_user_id must be http_lb, or ref with inline_user_ref set."
  }

  validation {
    condition = alltrue([
      for r in var.api_rate_limit_server_url_rules :
      r.client_matcher == null || r.client_matcher.mode == null || contains(["any_ip", "asn_list", "asn_matcher", "client_selector", "ip_matcher", "ip_prefix_list", "ip_threat_category_list", "tls_fingerprint_matcher"], r.client_matcher.mode)
    ])
    error_message = "api_rate_limit_server_url_rules client_matcher.mode is invalid (omit=any_client)."
  }

  validation {
    condition = alltrue([
      for r in var.api_rate_limit_server_url_rules :
      r.client_matcher == null || r.client_matcher.mode == null || (
        (r.client_matcher.mode != "asn_list" || length(r.client_matcher.as_numbers) > 0) &&
        (r.client_matcher.mode != "asn_matcher" || length(r.client_matcher.asn_sets) > 0) &&
        (r.client_matcher.mode != "client_selector" || length(r.client_matcher.selector_expressions) > 0) &&
        (r.client_matcher.mode != "ip_matcher" || length(r.client_matcher.ip_prefix_sets) > 0) &&
        (r.client_matcher.mode != "ip_prefix_list" || length(r.client_matcher.ip_prefixes) > 0) &&
        (r.client_matcher.mode != "ip_threat_category_list" || length(r.client_matcher.ip_threat_categories) > 0)
      )
    ])
    error_message = "api_rate_limit_server_url_rules: a selected client_matcher.mode needs its payload list (see endpoint-rules message)."
  }
}
