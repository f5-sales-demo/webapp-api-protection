# LPC-4b: standalone xcsh_waf_exclusion_policy resources + the LB's waf_exclusion_policy ref
# arm. A policy is authored once (a named set of exclusion rules) and referenced by the LB via
# waf_exclusion_policy_ref. The rule shape is identical to the inline waf_exclusion_rules (4a).

variable "waf_exclusion_policies" {
  description = "Standalone WAF exclusion policies (name -> ordered rules), referenceable by the LB."
  type = list(object({
    name = string
    rules = list(object({
      name                 = string
      description          = optional(string)
      domain               = optional(string, "any") # any|exact|suffix
      domain_value         = optional(string)
      path                 = optional(string, "any") # any|prefix|regex
      path_value           = optional(string)
      methods              = optional(list(string), [])
      expiration_timestamp = optional(string)
      action               = optional(string, "skip") # skip | detection_control
      exclude_signatures = optional(list(object({
        signature_id = number
        context      = optional(string, "CONTEXT_ANY")
        context_name = optional(string)
      })), [])
      exclude_violations = optional(list(object({
        violation    = string
        context      = optional(string, "CONTEXT_ANY")
        context_name = optional(string)
      })), [])
      exclude_attack_types = optional(list(object({
        attack_type  = string
        context      = optional(string, "CONTEXT_ANY")
        context_name = optional(string)
      })), [])
      exclude_bot_names = optional(list(string), [])
    }))
  }))
  default = []

  validation {
    condition = alltrue([for p in var.waf_exclusion_policies : alltrue([
      for r in p.rules : contains(["any", "exact", "suffix"], r.domain) && contains(["any", "prefix", "regex"], r.path) && contains(["skip", "detection_control"], r.action)
    ])])
    error_message = "waf_exclusion_policies[].rules[] domain/path/action must be valid selectors."
  }
  validation {
    condition = alltrue([for p in var.waf_exclusion_policies : alltrue([
      for r in p.rules : (r.domain == "any" || (r.domain_value != null && r.domain_value != "")) && (r.path == "any" || (r.path_value != null && r.path_value != ""))
    ])])
    error_message = "waf_exclusion_policies[].rules[] require domain_value/path_value for non-any selectors."
  }
  validation {
    condition = alltrue([for p in var.waf_exclusion_policies : alltrue([
      for r in p.rules : r.action != "detection_control" ||
      (length(r.exclude_signatures) + length(r.exclude_violations) + length(r.exclude_attack_types) + length(r.exclude_bot_names)) > 0
    ])])
    error_message = "waf_exclusion_policies[].rules[] with action=detection_control must define at least one exclusion."
  }
}

variable "waf_exclusion_policy_ref" {
  description = "Name of a waf_exclusion_policies entry to attach to the LB (ref arm). null = none."
  type        = string
  default     = null
}
