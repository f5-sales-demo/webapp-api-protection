# Root passthrough for standalone rate-limiter policies (Coverage Batch B).
# Thin passthrough: the full object type + validation live once in the module
# (modules/http-lb/variables_rate_limiter_policy.tf). Default [] creates none.
variable "rate_limiter_policies" {
  description = "Standalone xcsh_rate_limiter_policy definitions passthrough (typed+validated in the module)."
  type        = any
  default     = []
}
