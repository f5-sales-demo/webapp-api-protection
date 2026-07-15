# Root-level API Protection (SP3) inputs, passed through to modules/http-lb.
# Defaults mirror the module and keep every control off/suppressed (0-change). The
# api-protection matrix supplies these via -var-file per variant. Validation lives
# in the module.

variable "rate_limit_choice" {
  description = "rate_limit_choice: disable or rate_limit."
  type        = string
  default     = "disable"
}

variable "rate_limit_total_number" {
  description = "rate_limit.rate_limiter.total_number."
  type        = number
  default     = 100
}

variable "rate_limit_unit" {
  description = "rate_limit.rate_limiter.unit (SECOND|MINUTE|HOUR|DAY)."
  type        = string
  default     = "MINUTE"
}

variable "rate_limit_period_multiplier" {
  description = "rate_limit.rate_limiter.period_multiplier."
  type        = number
  default     = 1
}

variable "rate_limit_burst_multiplier" {
  description = "rate_limit.rate_limiter.burst_multiplier."
  type        = number
  default     = 1
}

variable "sensitive_data_compliances" {
  description = "Compliance frameworks on the sensitive_data_policy."
  type        = list(string)
  default     = []
}

variable "sensitive_data_disabled_predefined" {
  description = "Predefined sensitive-data types to disable."
  type        = list(string)
  default     = []
}

variable "sensitive_data_policy_choice" {
  description = "sensitive_data_policy_choice: default or custom."
  type        = string
  default     = "default"
}

variable "data_guard_rules" {
  description = "data_guard_rules: list of {domain_mode any|exact|suffix, domain, path, apply}."
  type = list(object({
    domain_mode = optional(string, "any")
    domain      = optional(string)
    path        = string
    apply       = optional(bool, true)
  }))
  default = []
}

# API protection rules (Coverage Batch D) root passthrough — per-rule client_matcher
# + request_matcher on api_endpoint_rules, plus api_groups_rules. Validation lives in
# the module (modules/http-lb/variables_api_protection_rules.tf).
variable "api_protection_rules" {
  description = "api_protection_rules.api_endpoint_rules passthrough."
  type = list(object({
    path           = string
    domain_mode    = optional(string, "any")
    domain         = optional(string)
    methods        = optional(list(string), ["ANY"])
    methods_invert = optional(bool, false)
    action         = optional(string, "allow")
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

variable "api_protection_group_rules" {
  description = "api_protection_rules.api_groups_rules passthrough."
  type = list(object({
    api_group   = optional(string)
    base_path   = optional(string)
    domain_mode = optional(string, "any")
    domain      = optional(string)
    action      = optional(string, "allow")
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

variable "validation_custom_rules" {
  description = "validation_custom_list.open_api_validation_rules: list of {path, methods, action block|report|skip}."
  type = list(object({
    path    = string
    methods = optional(list(string), ["ANY"])
    action  = optional(string, "report")
  }))
  default = []
}

# LB rate_limit allow-list + policy refs (Coverage Batch B) root passthrough.
# Validation lives in the module. Empty defaults keep no_ip_allowed_list + no_policies.
variable "rate_limit_ip_allowed_prefixes" {
  description = "rate_limit.ip_allowed_list.prefixes: IP prefixes exempt from rate limiting."
  type        = list(string)
  default     = []
}

variable "rate_limit_custom_ip_prefix_sets" {
  description = "rate_limit.custom_ip_allowed_list refs to existing ip_prefix_set objects."
  type = list(object({
    name      = string
    namespace = optional(string)
  }))
  default = []
}

variable "rate_limit_policy_refs" {
  description = "rate_limit.policies: names of rate_limiter_policies to attach to the LB."
  type        = list(string)
  default     = []
}
