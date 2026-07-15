# Root passthrough for the per-endpoint api_rate_limit arm (Coverage Batch B).
# Validation lives in the module (modules/http-lb/variables_api_rate_limit.tf).
# Empty defaults keep rate_limit_choice at its default (0-change).
variable "api_rate_limit_endpoint_rules" {
  description = "api_rate_limit.api_endpoint_rules passthrough."
  type = list(object({
    api_endpoint_path = string
    methods           = optional(list(string), [])
    methods_invert    = optional(bool, false)
    specific_domain   = optional(string)
    ref_rate_limiter  = optional(string)
    inline_threshold  = optional(number)
    inline_unit       = optional(string, "MINUTE")
    inline_user_id    = optional(string, "http_lb")
    inline_user_ref   = optional(string)
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
}

variable "api_rate_limit_bypass_rules" {
  description = "api_rate_limit.bypass_rate_limiting_rules passthrough."
  type = list(object({
    base_path        = optional(string)
    specific_domain  = optional(string)
    target           = optional(string, "any_url")
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
}

variable "api_rate_limit_server_url_rules" {
  description = "api_rate_limit.server_url_rules passthrough."
  type = list(object({
    api_group        = optional(string)
    base_path        = optional(string)
    specific_domain  = optional(string)
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
}
