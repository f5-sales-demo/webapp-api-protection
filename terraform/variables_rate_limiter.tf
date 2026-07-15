# Root passthrough for the standalone rate-limiter surface (Coverage Batch B).
# Validation lives in the module (modules/http-lb/variables_rate_limiter.tf).
# Default [] creates no standalone rate limiters (0-change).
variable "rate_limiters" {
  description = "Standalone xcsh_rate_limiter definitions (referenced by rate-limiter policies and the api_rate_limit arm)."
  type = list(object({
    name = string
    limits = optional(list(object({
      total_number          = number
      unit                  = optional(string, "MINUTE")
      burst_multiplier      = optional(number)
      period_multiplier     = optional(number)
      action                = optional(string)
      action_block_unit     = optional(string, "seconds")
      action_block_duration = optional(number)
      algorithm             = optional(string)
    })), [])
    user_identification = optional(list(object({
      name      = string
      namespace = optional(string)
    })), [])
  }))
  default = []
}
