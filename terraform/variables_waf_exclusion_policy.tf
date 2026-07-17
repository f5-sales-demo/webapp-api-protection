# Root passthrough for standalone WAF exclusion policies + LB ref selector (LPC-4b).
variable "waf_exclusion_policies" {
  description = "Standalone WAF exclusion policies (see module for shape)."
  type        = any
  default     = []
}

variable "waf_exclusion_policy_ref" {
  description = "Name of a waf_exclusion_policies entry to attach to the LB. null = none."
  type        = string
  default     = null
}
