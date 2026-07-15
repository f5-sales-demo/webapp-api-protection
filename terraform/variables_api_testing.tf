# API Testing (SP4) root passthrough. Validations live in the module
# (modules/http-lb/variables_api_testing.tf); the root just forwards. Defaults keep
# API testing off (0-change) and create no standalone resource.

variable "api_testing_choice" {
  description = "LB api_testing_choice: disable (suppressed server default) or enabled (inline api_testing block)."
  type        = string
  default     = "disable"
}

variable "api_testing_standalone_enabled" {
  description = "Create a standalone xcsh_api_testing resource (scheduled API tests)."
  type        = bool
  default     = false
}

variable "api_testing_schedule" {
  description = "Standalone xcsh_api_testing schedule: every_week (suppressed default) | every_day | every_month."
  type        = string
  default     = "every_week"
}

variable "api_testing_custom_header_value" {
  description = "x-F5-API-testing-identifier header value on test traffic (required by xcsh_api_testing; defaulted)."
  type        = string
  default     = "f5xc-api-testing"
}

variable "api_testing_domains" {
  description = "Testing domains + credentials (see modules/http-lb/variables_api_testing.tf for the shape and validations)."
  type = list(object({
    domain                    = string
    allow_destructive_methods = optional(bool, false)
    credentials = optional(list(object({
      credential_name = string
      auth_type       = string
      api_key_name    = optional(string)
      user            = optional(string)
      secret = optional(object({
        method    = optional(string, "clear")
        plaintext = optional(string)
        location  = optional(string)
      }))
    })), [])
  }))
  default   = []
  sensitive = true
}
