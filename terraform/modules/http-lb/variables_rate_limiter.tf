# ---------------------------------------------------------------------------
# Standalone reusable rate limiters (Coverage Batch B). Creates xcsh_rate_limiter
# objects that other resources reference by name: xcsh_rate_limiter_policy rules
# (apply_rate_limiter / custom_rate_limiter) and the LB api_rate_limit arm
# (ref_rate_limiter). Default [] creates none (0-change).
#
# Each limits[] entry carries two INDEPENDENT server oneofs plus the rate scalars:
#   - action:    "block" -> action_block { <action_block_unit> { duration } }
#                "disabled" -> disabled {}                 (null omits the arm)
#   - algorithm: "leaky_bucket" | "token_bucket"           (null omits => server default)
# unit is SECOND | MINUTE | HOUR (the standalone schema does NOT accept DAY).
# ---------------------------------------------------------------------------
variable "rate_limiters" {
  description = "Standalone xcsh_rate_limiter definitions (referenced by rate-limiter policies and the api_rate_limit arm), keyed by name."
  type = list(object({
    name = string
    limits = optional(list(object({
      total_number          = number
      unit                  = optional(string, "MINUTE") # SECOND | MINUTE | HOUR
      burst_multiplier      = optional(number)
      period_multiplier     = optional(number)
      action                = optional(string)            # block | disabled | null(omit)
      action_block_unit     = optional(string, "seconds") # hours | minutes | seconds
      action_block_duration = optional(number)
      algorithm             = optional(string) # leaky_bucket | token_bucket | null(omit)
    })), [])
    user_identification = optional(list(object({
      name      = string
      namespace = optional(string) # defaults to the LB namespace
    })), [])
  }))
  default = []

  validation {
    condition     = length(var.rate_limiters) == length(distinct([for rl in var.rate_limiters : rl.name]))
    error_message = "rate_limiters names must be unique."
  }

  validation {
    condition = alltrue([
      for rl in var.rate_limiters : alltrue([
        for l in rl.limits : contains(["SECOND", "MINUTE", "HOUR"], l.unit)
      ])
    ])
    error_message = "rate_limiters limits.unit must be SECOND, MINUTE, or HOUR (DAY is not accepted by xcsh_rate_limiter)."
  }

  validation {
    condition = alltrue([
      for rl in var.rate_limiters : alltrue([
        for l in rl.limits : l.total_number >= 1
      ])
    ])
    error_message = "rate_limiters limits.total_number must be >= 1."
  }

  validation {
    condition = alltrue([
      for rl in var.rate_limiters : alltrue([
        for l in rl.limits : l.action == null || contains(["block", "disabled"], l.action)
      ])
    ])
    error_message = "rate_limiters limits.action must be \"block\", \"disabled\", or null."
  }

  validation {
    condition = alltrue([
      for rl in var.rate_limiters : alltrue([
        for l in rl.limits : l.action != "block" || (l.action_block_duration != null && contains(["hours", "minutes", "seconds"], l.action_block_unit))
      ])
    ])
    error_message = "when limits.action=\"block\", action_block_duration is required and action_block_unit must be hours, minutes, or seconds."
  }

  validation {
    condition = alltrue([
      for rl in var.rate_limiters : alltrue([
        for l in rl.limits : l.algorithm == null || contains(["leaky_bucket", "token_bucket"], l.algorithm)
      ])
    ])
    error_message = "rate_limiters limits.algorithm must be \"leaky_bucket\", \"token_bucket\", or null."
  }
}
