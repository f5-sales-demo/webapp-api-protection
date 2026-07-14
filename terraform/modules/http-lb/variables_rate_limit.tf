# Rate limiting (SP3) — LB rate_limit_choice. Default "disable" = server default
# disable_rate_limit (import-suppressed) => omit the block => 0-change.
#
# "rate_limit" emits the self-contained inline request rate limiter
# (rate_limit.rate_limiter) with no IP-allow-list and no policy refs. The
# per-endpoint api_rate_limit arm and the standalone xcsh_rate_limiter_policy
# (server-scoped, references a separate xcsh_rate_limiter) are advanced paths
# deferred this cycle — see docs/superpowers/plans/sp3-findings.md.
variable "rate_limit_choice" {
  description = "rate_limit_choice: disable (server default, suppressed) or rate_limit (inline request rate limiter)."
  type        = string
  default     = "disable"

  validation {
    condition     = contains(["disable", "rate_limit"], var.rate_limit_choice)
    error_message = "rate_limit_choice must be \"disable\" or \"rate_limit\"."
  }
}

variable "rate_limit_total_number" {
  description = "rate_limit.rate_limiter.total_number: max requests per period."
  type        = number
  default     = 100

  validation {
    condition     = var.rate_limit_total_number >= 1
    error_message = "rate_limit_total_number must be >= 1."
  }
}

variable "rate_limit_unit" {
  description = "rate_limit.rate_limiter.unit: SECOND, MINUTE, HOUR, or DAY."
  type        = string
  default     = "MINUTE"

  validation {
    condition     = contains(["SECOND", "MINUTE", "HOUR", "DAY"], var.rate_limit_unit)
    error_message = "rate_limit_unit must be SECOND, MINUTE, HOUR, or DAY."
  }
}

variable "rate_limit_period_multiplier" {
  description = "rate_limit.rate_limiter.period_multiplier: the period is period_multiplier x unit."
  type        = number
  default     = 1

  validation {
    condition     = var.rate_limit_period_multiplier >= 1
    error_message = "rate_limit_period_multiplier must be >= 1."
  }
}

variable "rate_limit_burst_multiplier" {
  description = "rate_limit.rate_limiter.burst_multiplier: allowed burst is burst_multiplier x total_number."
  type        = number
  default     = 1

  validation {
    condition     = var.rate_limit_burst_multiplier >= 1
    error_message = "rate_limit_burst_multiplier must be >= 1."
  }
}
