# ---------------------------------------------------------------------------
# API Discovery & Crawler (SP1) — inputs. Defaults reproduce the current bare
# enable_api_discovery {} (0-change / import-clean); non-default arms are cycled
# by the api-discovery matrix. See docs/superpowers/specs + plans (local).
# ---------------------------------------------------------------------------

# Reusable clear/blindfold SecretType input shape. This exact object type + the
# locals renderer (locals_api.tf) + the dynamic blindfold/clear blocks are the
# DRY convention reused for every secret-bearing option (crawler password now;
# SCM access_token / TLS keys later).
#   method=clear      -> clear_secret_info { url = "string:///<base64 plaintext>" }
#   method=blindfold  -> blindfold_secret_info { location = <pre-sealed value> }
# IMPORTANT: provider::xcsh::blindfold seals with a random data key, so calling it
# inline every plan would re-seal and drift (non-idempotent). Blindfold secrets are
# therefore sealed ONCE, offline, and the resulting "string:///..." location is
# pinned here (produced by scripts/blindfold-seal.sh). This is the F5-documented
# offline-blindfold pattern and is idempotent + import-clean.
variable "api_crawler_password" {
  description = "API crawler login password. clear: set plaintext (or provider_ref for an external secret-mgmt provider). blindfold: set location to a pre-sealed 'string:///...' value from scripts/blindfold-seal.sh (optionally store_provider/decryption_provider for an external secret backend)."
  type = object({
    method    = optional(string, "clear")
    plaintext = optional(string) # clear arm
    location  = optional(string) # blindfold arm: pre-sealed string:///...
    # Optional external secret-management backend refs (Batch G):
    store_provider      = optional(string) # blindfold: store the sealed secret lives in
    decryption_provider = optional(string) # blindfold: provider that decrypts it
    provider_ref        = optional(string) # clear: secret-mgmt provider serving the value
  })
  default   = { method = "clear", plaintext = null }
  sensitive = true

  validation {
    condition     = contains(["clear", "blindfold"], var.api_crawler_password.method)
    error_message = "api_crawler_password.method must be \"clear\" or \"blindfold\"."
  }

  validation {
    condition     = var.api_crawler_password.method != "blindfold" || var.api_crawler_password.location != null
    error_message = "blindfold method requires a pre-sealed location (run scripts/blindfold-seal.sh)."
  }

  validation {
    condition     = var.api_crawler_password.method == "blindfold" || (var.api_crawler_password.store_provider == null && var.api_crawler_password.decryption_provider == null)
    error_message = "store_provider/decryption_provider are blindfold-only secret backends."
  }

  validation {
    condition     = var.api_crawler_password.method == "clear" || var.api_crawler_password.provider_ref == null
    error_message = "provider_ref is a clear-secret backend only."
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
# discovered_api_settings block entirely (server default, no drift). Server validation
# rule ves.io.schema.rules.uint32 gte=1 lte=7, so mirror it here to fail fast at plan
# instead of a live 400 BAD_REQUEST.
variable "api_discovery_purge_duration" {
  description = "Days (1-7) to purge inactive discovered APIs (discovered_api_settings.purge_duration_for_inactive_discovered_apis). null = omit."
  type        = number
  default     = null

  validation {
    condition     = var.api_discovery_purge_duration == null || (var.api_discovery_purge_duration >= 1 && var.api_discovery_purge_duration <= 7)
    error_message = "api_discovery_purge_duration must be between 1 and 7 (days), or null to omit."
  }
}

# api-auth-discovery oneof. default = server default default_api_auth_discovery
# (import-suppressed, so we emit NEITHER arm). custom = create a standalone
# xcsh_api_discovery object and reference it via custom_api_auth_discovery.api_discovery_ref.
variable "api_discovery_auth_mode" {
  description = "enable_api_discovery auth-discovery: default (suppressed server default) or custom (custom_auth_types via a referenced xcsh_api_discovery)."
  type        = string
  default     = "default"

  validation {
    condition     = contains(["default", "custom"], var.api_discovery_auth_mode)
    error_message = "api_discovery_auth_mode must be \"default\" or \"custom\"."
  }
}

variable "api_discovery_custom_auth_types" {
  description = "Custom auth types for the referenced xcsh_api_discovery when api_discovery_auth_mode=custom."
  type = list(object({
    parameter_name = string
    parameter_type = string
  }))
  default = []

  validation {
    condition = alltrue([
      for t in var.api_discovery_custom_auth_types :
      contains(["QUERY_PARAMETER", "HEADER", "COOKIE"], t.parameter_type)
    ])
    error_message = "each parameter_type must be QUERY_PARAMETER, HEADER, or COOKIE."
  }
}
