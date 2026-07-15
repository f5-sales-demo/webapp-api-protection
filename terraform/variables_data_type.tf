# Root passthrough for the sensitive-data surface (Coverage Batch C). Thin
# passthrough: the full object types + validation live once in the module
# (modules/http-lb/variables_data_type.tf + variables_sensitive_data.tf).
variable "data_types" {
  description = "Standalone xcsh_data_type definitions passthrough (typed+validated in the module)."
  type        = any
  default     = []
}

variable "sensitive_data_custom_type_refs" {
  description = "Names of data_types to attach to the sensitive_data_policy custom_data_types."
  type        = list(string)
  default     = []
}

variable "sensitive_data_disclosure_rules" {
  description = "LB response sensitive-data disclosure rules passthrough (typed+validated in the module)."
  type        = any
  default     = []
}
