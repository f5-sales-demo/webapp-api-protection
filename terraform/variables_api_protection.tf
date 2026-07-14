# Root-level API Protection (SP3) inputs, passed through to modules/http-lb.
# Defaults mirror the module and keep every control off/suppressed (0-change). The
# api-protection matrix supplies these via -var-file per variant. Validation lives
# in the module.

variable "client_matcher" {
  description = "Shared client matcher (any | ip_prefix | ip_threat) for api_protection_rules."
  type = object({
    mode                 = optional(string, "any")
    ip_prefixes          = optional(list(string), [])
    invert               = optional(bool, false)
    ip_threat_categories = optional(list(string), [])
  })
  default = { mode = "any" }
}

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

variable "sensitive_data_policy_enabled" {
  description = "Create a standalone xcsh_sensitive_data_policy."
  type        = bool
  default     = false
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

variable "api_protection_rules" {
  description = "api_protection_rules: list of {path, domain_mode any|specific, domain, methods, action allow|deny}."
  type = list(object({
    path        = string
    domain_mode = optional(string, "any")
    domain      = optional(string)
    methods     = optional(list(string), ["ANY"])
    action      = optional(string, "allow")
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
