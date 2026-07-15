# Root passthrough for the sensitive-data surface (Coverage Batch C). Validation
# lives in the module. Defaults keep everything off (0-change).
variable "data_types" {
  description = "Standalone xcsh_data_type definitions (referenced by sensitive_data_policy custom_data_types)."
  type = list(object({
    name              = string
    compliances       = optional(list(string), [])
    is_pii            = optional(bool, false)
    is_sensitive_data = optional(bool, false)
    rules = optional(list(object({
      type            = string
      key_matcher     = optional(string)
      key_regex       = optional(string)
      key_substring   = optional(string)
      key_exact       = optional(list(string), [])
      value_matcher   = optional(string)
      value_regex     = optional(string)
      value_substring = optional(string)
      value_exact     = optional(list(string), [])
    })), [])
  }))
  default = []
}

variable "sensitive_data_custom_type_refs" {
  description = "Names of data_types to attach to the sensitive_data_policy custom_data_types."
  type        = list(string)
  default     = []
}

variable "sensitive_data_disclosure_rules" {
  description = "LB response sensitive-data disclosure rules: {path, methods, fields, action mask|report}."
  type = list(object({
    path    = string
    methods = optional(list(string), [])
    fields  = optional(list(string), [])
    action  = optional(string, "mask")
  }))
  default = []
}
