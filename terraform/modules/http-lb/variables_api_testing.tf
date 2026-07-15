# ---------------------------------------------------------------------------
# API Testing (SP4) — inputs. Two surfaces share one domains/credentials shape:
#   * standalone xcsh_api_testing (api_testing_standalone_enabled) + schedule oneof
#   * LB api_testing_choice inline api_testing block (vs suppressed disable_api_testing)
# Defaults reproduce the current bare LB (disable_api_testing suppressed => 0-change)
# and create no standalone resource. Credentials reuse the clear/blindfold SecretType
# convention (variables_api.tf / locals_api.tf). See docs/superpowers (local).
# ---------------------------------------------------------------------------

# LB api_testing_choice oneof: "disable" (server default disable_api_testing,
# import-suppressed => omit => 0-change) or "enabled" (inline api_testing block).
variable "api_testing_choice" {
  description = "LB api_testing_choice: disable (suppressed server default) or enabled (inline api_testing block)."
  type        = string
  default     = "disable"

  validation {
    condition     = contains(["disable", "enabled"], var.api_testing_choice)
    error_message = "api_testing_choice must be \"disable\" or \"enabled\"."
  }
}

# Gate the standalone xcsh_api_testing resource (single knob: count derives from this,
# no separate reference selector to desync — cf. SP3 sensitive-data review lesson).
variable "api_testing_standalone_enabled" {
  description = "Create a standalone xcsh_api_testing resource (scheduled API tests) in addition to / instead of the LB inline block."
  type        = bool
  default     = false
}

# Standalone schedule oneof. "every_week" is the server default (import-suppressed =>
# omit); "every_day"/"every_month" are explicit non-default choices.
variable "api_testing_schedule" {
  description = "Standalone xcsh_api_testing run schedule: every_week (suppressed default) | every_day | every_month."
  type        = string
  default     = "every_week"

  validation {
    condition     = contains(["every_week", "every_day", "every_month"], var.api_testing_schedule)
    error_message = "api_testing_schedule must be every_week, every_day, or every_month."
  }
}

variable "api_testing_custom_header_value" {
  description = "x-F5-API-testing-identifier header value added to test traffic (custom_header_value). Required by xcsh_api_testing; defaulted so test traffic is always identifiable."
  type        = string
  default     = "f5xc-api-testing"

  validation {
    condition     = length(var.api_testing_custom_header_value) > 0
    error_message = "api_testing_custom_header_value must be non-empty (it is a required attribute)."
  }
}

# Shared testing domains + credentials, consumed by BOTH surfaces (DRY). Each
# credential selects exactly one auth arm; the secret arms (api_key value /
# basic_auth password / bearer_token token) carry a clear/blindfold SecretType.
# allow_destructive_methods defaults false (destructive tests can DELETE data).
variable "api_testing_domains" {
  description = "Testing domains: {domain, allow_destructive_methods, credentials[]}. credentials: {credential_name, auth_type admin|standard|api_key|basic_auth|bearer_token, api_key_name, user, secret {method,plaintext,location}}."
  type = list(object({
    domain                    = string
    allow_destructive_methods = optional(bool, false)
    credentials = optional(list(object({
      credential_name = string
      auth_type       = string           # admin | standard | api_key | basic_auth | bearer_token
      api_key_name    = optional(string) # api_key: header/query key name
      user            = optional(string) # basic_auth: username
      secret = optional(object({         # api_key value / basic_auth password / bearer_token token
        method    = optional(string, "clear")
        plaintext = optional(string)
        location  = optional(string)
      }))
    })), [])
  }))
  default   = []
  sensitive = true # credentials carry secret plaintext

  validation {
    condition = alltrue(flatten([
      for d in var.api_testing_domains : [
        for c in d.credentials :
        contains(["admin", "standard", "api_key", "basic_auth", "bearer_token"], c.auth_type)
      ]
    ]))
    error_message = "each credential auth_type must be admin, standard, api_key, basic_auth, or bearer_token."
  }

  validation {
    condition = alltrue(flatten([
      for d in var.api_testing_domains : [
        for c in d.credentials :
        # secret-bearing arms require a secret; marker arms (admin/standard) must not carry one
        (contains(["api_key", "basic_auth", "bearer_token"], c.auth_type)) == (c.secret != null)
      ]
    ]))
    error_message = "api_key/basic_auth/bearer_token require a secret{}; admin/standard must omit it."
  }

  validation {
    condition = alltrue(flatten([
      for d in var.api_testing_domains : [
        for c in d.credentials :
        c.secret == null || contains(["clear", "blindfold"], c.secret.method)
      ]
    ]))
    error_message = "credential secret.method must be \"clear\" or \"blindfold\"."
  }

  validation {
    condition = alltrue(flatten([
      for d in var.api_testing_domains : [
        for c in d.credentials :
        c.secret == null || c.secret.method != "blindfold" || c.secret.location != null
      ]
    ]))
    error_message = "blindfold credential secret requires a pre-sealed location (scripts/blindfold-seal.sh)."
  }

  validation {
    condition = alltrue(flatten([
      for d in var.api_testing_domains : [
        for c in d.credentials : c.auth_type != "basic_auth" || c.user != null
      ]
    ]))
    error_message = "basic_auth credential requires user."
  }

  validation {
    condition = alltrue(flatten([
      for d in var.api_testing_domains : [
        for c in d.credentials : c.auth_type != "api_key" || c.api_key_name != null
      ]
    ]))
    error_message = "api_key credential requires api_key_name."
  }
}
