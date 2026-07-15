# Root passthrough for the standalone rate-limiter surface (Coverage Batch B).
# Thin passthrough: the full object type + validation live once in the module
# (modules/http-lb/variables_rate_limiter.tf). Default [] creates no limiters.
variable "rate_limiters" {
  description = "Standalone xcsh_rate_limiter definitions passthrough (typed+validated in the module)."
  type        = any
  default     = []
}
