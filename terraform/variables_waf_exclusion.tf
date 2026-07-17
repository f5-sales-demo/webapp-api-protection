# Root passthrough for inline WAF exclusion rules (LPC-4a). Object list uses type = any
# (shape in module).
variable "waf_exclusion_rules" {
  description = "Inline WAF exclusion rules on the LB (see module for shape)."
  type        = any
  default     = []
}
