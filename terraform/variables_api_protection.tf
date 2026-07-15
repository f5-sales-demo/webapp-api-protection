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
  type        = any
  default     = []
}

# API protection rules (Coverage Batch D) root passthrough. Thin passthrough: the
# full object type + validation live once in the module
# (modules/http-lb/variables_api_protection_rules.tf), so the root wrapper uses
# type=any to avoid redeclaring (and drifting from) the module's contract.
variable "api_protection_rules" {
  description = "api_protection_rules.api_endpoint_rules passthrough (typed+validated in the module)."
  type        = any
  default     = []
}

variable "api_protection_group_rules" {
  description = "api_protection_rules.api_groups_rules passthrough (typed+validated in the module)."
  type        = any
  default     = []
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
