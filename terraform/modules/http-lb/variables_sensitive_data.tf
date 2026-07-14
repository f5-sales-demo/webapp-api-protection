# Sensitive data & data guard (SP3). The LB sensitive_data_policy_choice defaults to
# the server default default_sensitive_data_policy (import-suppressed => omit =>
# 0-change); "custom" references the standalone xcsh_sensitive_data_policy created
# here. data_guard_rules and sensitive_data_disclosure_rules are optional lists
# (omitted when empty). custom_data_types on the policy are object-refs to separate
# xcsh_custom_data_type objects — deferred this cycle (see sp3-findings.md).

variable "sensitive_data_compliances" {
  description = "Compliance frameworks to monitor on the sensitive_data_policy (GDPR, HIPAA, PCI_DSS, ...)."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for c in var.sensitive_data_compliances :
      contains(["GDPR", "CCPA", "PIPEDA", "LGPD", "DPA_UK", "PDPA_SG", "APPI", "HIPAA", "CPRA_2023", "CPA_CO", "SOC2", "PCI_DSS", "ISO_IEC_27001", "ISO_IEC_27701", "EPRIVACY_DIRECTIVE", "GLBA", "SOX"], c)
    ])
    error_message = "each sensitive_data_compliances value must be a valid F5 XC compliance framework."
  }
}

variable "sensitive_data_disabled_predefined" {
  description = "Predefined sensitive-data types to disable (not shown as sensitive in API discovery)."
  type        = list(string)
  default     = []
}

# sensitive_data_policy_choice: "default" (server default_sensitive_data_policy,
# suppressed => omit) or "custom" (reference the xcsh_sensitive_data_policy above).
variable "sensitive_data_policy_choice" {
  description = "sensitive_data_policy_choice: default (suppressed) or custom (reference the standalone policy)."
  type        = string
  default     = "default"

  validation {
    condition     = contains(["default", "custom"], var.sensitive_data_policy_choice)
    error_message = "sensitive_data_policy_choice must be \"default\" or \"custom\"."
  }
}

# data_guard_rules: mask sensitive data (e.g. credit-card / SSN) in responses per
# domain + path. domain = any | exact | suffix; action = apply | skip.
variable "data_guard_rules" {
  description = "data_guard_rules: list of {domain_mode any|exact|suffix, domain, path, apply}."
  type = list(object({
    domain_mode = optional(string, "any")
    domain      = optional(string)
    path        = string
    apply       = optional(bool, true)
  }))
  default = []

  validation {
    condition = alltrue([
      for r in var.data_guard_rules : contains(["any", "exact", "suffix"], r.domain_mode)
    ])
    error_message = "each data_guard_rules domain_mode must be any, exact, or suffix."
  }

  validation {
    condition = alltrue([
      for r in var.data_guard_rules : r.domain_mode == "any" || r.domain != null
    ])
    error_message = "data_guard_rules with domain_mode exact/suffix require a domain."
  }
}
