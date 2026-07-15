# Rate limiting (SP3) — LB rate_limit_choice. Default "disable" = server default
# disable_rate_limit (import-suppressed) => omit the block => 0-change.
#
# "rate_limit" emits the self-contained inline request rate limiter
# (rate_limit.rate_limiter) with no IP-allow-list and no policy refs. The
# per-endpoint api_rate_limit arm and the standalone xcsh_rate_limiter_policy
# (server-scoped, references a separate xcsh_rate_limiter) are advanced paths
# deferred this cycle — see docs/superpowers/plans/sp3-findings.md.
variable "rate_limit_choice" {
  description = "rate_limit_choice: disable (server default, suppressed), rate_limit (inline request rate limiter), or api_rate_limit (per-endpoint rules)."
  type        = string
  default     = "disable"

  validation {
    condition     = contains(["disable", "rate_limit", "api_rate_limit"], var.rate_limit_choice)
    error_message = "rate_limit_choice must be \"disable\", \"rate_limit\", or \"api_rate_limit\"."
  }
}

variable "rate_limit_total_number" {
  description = "rate_limit.rate_limiter.total_number: max requests per period."
  type        = number
  default     = 100

  validation {
    condition     = var.rate_limit_total_number >= 1 && var.rate_limit_total_number <= 8192
    error_message = "rate_limit_total_number must be between 1 and 8192 (F5 XC inline rate_limiter cap)."
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

# --- LB rate_limit allow-list + policy refs (Coverage Batch B) ---
# The rate_limit block carries an IP-allow-list oneof (no_ip_allowed_list default |
# ip_allowed_list inline prefixes | custom_ip_allowed_list refs to ip_prefix_set) and a
# policies oneof (no_policies default | policies refs to xcsh_rate_limiter_policy).
# Empty defaults keep the SP3 behavior (no_ip_allowed_list + no_policies), 0-change.
variable "rate_limit_ip_allowed_prefixes" {
  description = "rate_limit.ip_allowed_list.prefixes: IP prefixes exempt from rate limiting. Empty => no_ip_allowed_list (unless custom sets are used)."
  type        = list(string)
  default     = []
}

variable "rate_limit_custom_ip_prefix_sets" {
  description = "rate_limit.custom_ip_allowed_list.rate_limiter_allowed_prefixes: references to existing ip_prefix_set objects exempt from rate limiting."
  type = list(object({
    name      = string
    namespace = optional(string)
  }))
  default = []
}

variable "rate_limit_policy_refs" {
  description = "rate_limit.policies: names of var.rate_limiter_policies to attach. Empty => no_policies."
  type        = list(string)
  default     = []
}
