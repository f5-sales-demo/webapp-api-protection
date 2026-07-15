# ---------------------------------------------------------------------------
# Standalone custom data types (Coverage Batch C). Creates xcsh_data_type objects
# referenced by the sensitive_data_policy custom_data_types arm. Each data type
# carries compliance tags + is_pii/is_sensitive_data flags and rules[] that match
# request/response key-value pairs:
#   type = "key"       -> key_pattern   { <matcher> }
#          "value"     -> value_pattern { <matcher> }
#          "key_value" -> key_value_pattern { key_pattern{<km>} value_pattern{<vm>} }
# where each <matcher> is one of: regex | substring | exact (exact_values list).
# Default [] creates none (0-change).
# ---------------------------------------------------------------------------
variable "data_types" {
  description = "Standalone xcsh_data_type definitions (referenced by sensitive_data_policy custom_data_types), keyed by name."
  type = list(object({
    name              = string
    compliances       = optional(list(string), [])
    is_pii            = optional(bool, false)
    is_sensitive_data = optional(bool, false)
    rules = optional(list(object({
      type            = string           # key | value | key_value
      key_matcher     = optional(string) # regex | substring | exact
      key_regex       = optional(string)
      key_substring   = optional(string)
      key_exact       = optional(list(string), [])
      value_matcher   = optional(string) # regex | substring | exact
      value_regex     = optional(string)
      value_substring = optional(string)
      value_exact     = optional(list(string), [])
    })), [])
  }))
  default = []

  validation {
    condition     = length(var.data_types) == length(distinct([for d in var.data_types : d.name]))
    error_message = "data_types names must be unique."
  }

  validation {
    condition = alltrue([
      for d in var.data_types : alltrue([
        for c in d.compliances :
        contains(["GDPR", "CCPA", "PIPEDA", "LGPD", "DPA_UK", "PDPA_SG", "APPI", "HIPAA", "CPRA_2023", "CPA_CO", "SOC2", "PCI_DSS", "ISO_IEC_27001", "ISO_IEC_27701", "EPRIVACY_DIRECTIVE", "GLBA", "SOX"], c)
      ])
    ])
    error_message = "each data_types compliances value must be a valid F5 XC compliance framework."
  }

  validation {
    condition = alltrue([
      for d in var.data_types : alltrue([
        for r in d.rules : contains(["key", "value", "key_value"], r.type)
      ])
    ])
    error_message = "data_types rules.type must be key, value, or key_value."
  }

  validation {
    condition = alltrue([
      for d in var.data_types : alltrue([
        for r in d.rules :
        (r.type == "value" || (r.key_matcher != null && contains(["regex", "substring", "exact"], r.key_matcher))) &&
        (r.type == "key" || (r.value_matcher != null && contains(["regex", "substring", "exact"], r.value_matcher)))
      ])
    ])
    error_message = "data_types rules require key_matcher (type key/key_value) and/or value_matcher (type value/key_value) to be regex, substring, or exact."
  }

  validation {
    condition = alltrue([
      for d in var.data_types : alltrue([
        for r in d.rules : (
          (r.type == "value" || (
            (r.key_matcher != "regex" || r.key_regex != null) &&
            (r.key_matcher != "substring" || r.key_substring != null) &&
            (r.key_matcher != "exact" || length(r.key_exact) > 0)
          )) &&
          (r.type == "key" || (
            (r.value_matcher != "regex" || r.value_regex != null) &&
            (r.value_matcher != "substring" || r.value_substring != null) &&
            (r.value_matcher != "exact" || length(r.value_exact) > 0)
          ))
        )
      ])
    ])
    error_message = "data_types rules: the chosen matcher needs its payload (regex⇒*_regex, substring⇒*_substring, exact⇒*_exact non-empty)."
  }
}
