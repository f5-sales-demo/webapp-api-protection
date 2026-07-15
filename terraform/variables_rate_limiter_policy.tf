# Root passthrough for standalone rate-limiter policies (Coverage Batch B).
# Validation lives in the module (modules/http-lb/variables_rate_limiter_policy.tf).
# Default [] creates no policies (0-change).
variable "rate_limiter_policies" {
  description = "Standalone xcsh_rate_limiter_policy definitions (referenced by LB rate_limit.policies)."
  type = list(object({
    name              = string
    server_scope      = optional(string, "any_server")
    server_name_exact = optional(list(string), [])
    server_name_regex = optional(list(string), [])
    server_selector   = optional(list(string), [])
    rules = optional(list(object({
      name                = string
      action              = optional(string, "apply")
      custom_rate_limiter = optional(string)
      asn                 = optional(string)
      asn_numbers         = optional(list(number), [])
      asn_sets            = optional(list(object({ name = string, namespace = optional(string) })), [])
      ip                  = optional(string)
      ip_prefixes         = optional(list(string), [])
      ip_invert           = optional(bool, false)
      ip_sets             = optional(list(object({ name = string, namespace = optional(string) })), [])
      country             = optional(string)
      countries           = optional(list(string), [])
      country_invert      = optional(bool, false)
      http_methods        = optional(list(string), [])
      http_methods_invert = optional(bool, false)
      path_exact          = optional(list(string), [])
      path_prefixes       = optional(list(string), [])
      path_regex          = optional(list(string), [])
      path_suffix         = optional(list(string), [])
      path_invert         = optional(bool, false)
      domain_exact        = optional(list(string), [])
      domain_regex        = optional(list(string), [])
      headers = optional(list(object({
        name         = string
        invert       = optional(bool, false)
        presence     = optional(string, "match")
        exact_values = optional(list(string), [])
        regex_values = optional(list(string), [])
      })), [])
    })), [])
  }))
  default = []
}
