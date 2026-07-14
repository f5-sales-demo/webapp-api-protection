# ---------------------------------------------------------------------------
# API Discovery & Crawler (SP1) — inputs. Defaults reproduce the current bare
# enable_api_discovery {} (0-change / import-clean); non-default arms are cycled
# by the api-discovery matrix. See docs/superpowers/specs + plans (local).
# ---------------------------------------------------------------------------

# Reusable clear/blindfold SecretType input shape. This exact object type + the
# locals renderer (locals_api.tf) + the dynamic blindfold/clear blocks are the
# DRY convention reused for every secret-bearing option (crawler password now;
# SCM access_token / TLS keys later). method=clear emits clear_secret_info{url};
# method=blindfold seals plaintext OFFLINE via provider::xcsh::blindfold and emits
# blindfold_secret_info{location} (cleartext never leaves the machine).
variable "api_crawler_password" {
  description = "API crawler login password as a selectable clear/blindfold secret."
  type = object({
    method                     = optional(string, "clear")
    plaintext                  = optional(string)
    blindfold_policy_namespace = optional(string, "shared")
    blindfold_policy_name      = optional(string, "ves-io-allow-volterra")
  })
  default   = { method = "clear", plaintext = null }
  sensitive = true

  validation {
    condition     = contains(["clear", "blindfold"], var.api_crawler_password.method)
    error_message = "api_crawler_password.method must be \"clear\" or \"blindfold\"."
  }
}

variable "api_crawler_domains" {
  description = "Authenticated domains for the inline API crawler (enable_api_discovery.api_crawler.api_crawler_config). Empty = no crawler (server default disable_api_crawler, suppressed on import)."
  type = list(object({
    domain = string
    user   = string
  }))
  default = []
}

# api_discovery_choice oneof: enable_api_discovery vs disable_api_discovery.
# Default "enable" reproduces the current bare enable_api_discovery {} (0-change).
variable "api_discovery_choice" {
  description = "api_discovery_choice: enable (learn the API schema) or disable."
  type        = string
  default     = "enable"

  validation {
    condition     = contains(["enable", "disable"], var.api_discovery_choice)
    error_message = "api_discovery_choice must be \"enable\" or \"disable\"."
  }
}

# learn_from_redirect_traffic oneof. omit = server default disable_learn_from_redirect_traffic
# (import-suppressed, so we emit NEITHER arm); enable = enable_learn_from_redirect_traffic.
variable "api_discovery_learn_from_redirect" {
  description = "enable_api_discovery learn-from-redirect: omit (server default disable, suppressed) or enable."
  type        = string
  default     = "omit"

  validation {
    condition     = contains(["omit", "enable"], var.api_discovery_learn_from_redirect)
    error_message = "api_discovery_learn_from_redirect must be \"omit\" or \"enable\"."
  }
}

# discovered_api_settings.purge_duration_for_inactive_discovered_apis. null = omit the
# discovered_api_settings block entirely (server default, no drift).
variable "api_discovery_purge_duration" {
  description = "Days to purge inactive discovered APIs (discovered_api_settings.purge_duration_for_inactive_discovered_apis). null = omit."
  type        = number
  default     = null
}
