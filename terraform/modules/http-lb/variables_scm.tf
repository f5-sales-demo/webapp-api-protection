# API spec source-control integration (SP2): xcsh_code_base_integration (github arm).
# F5 XC pulls OpenAPI specs from the repo; the LB selects repos via
# api_discovery_from_code_scan (LB wiring lands with provider #1091). access_token
# reuses the clear/blindfold SecretType convention (locals_api.tf rendered_secret) —
# the identical SecretType shape as the crawler password (DRY, second consumer).

variable "code_base_integration_enabled" {
  description = "Create an xcsh_code_base_integration (github) F5 XC uses to pull API specs from source control (e.g. the api-catalog repo)."
  type        = bool
  default     = false
}

variable "code_base_integration_username" {
  description = "GitHub username for the code_base_integration (github arm)."
  type        = string
  default     = ""
}

variable "code_base_integration_access_token" {
  description = "GitHub access token as a selectable clear/blindfold secret. clear: set plaintext. blindfold: set location to a pre-sealed 'string:///...' from scripts/blindfold-seal.sh."
  type = object({
    method    = optional(string, "clear")
    plaintext = optional(string)
    location  = optional(string)
  })
  default   = { method = "clear", plaintext = null }
  sensitive = true

  validation {
    condition     = contains(["clear", "blindfold"], var.code_base_integration_access_token.method)
    error_message = "code_base_integration_access_token.method must be \"clear\" or \"blindfold\"."
  }

  validation {
    condition     = var.code_base_integration_access_token.method != "blindfold" || var.code_base_integration_access_token.location != null
    error_message = "blindfold method requires a pre-sealed location (run scripts/blindfold-seal.sh)."
  }
}

# API discovery from source-code scan (SP2): wire enable_api_discovery.
# api_discovery_from_code_scan.code_base_integrations[] to the code_base_integration.
# "off" (default) emits no block (0-change). "selected" scans the repos in
# api_discovery_code_scan_repos; "all" scans every repo the integration can see.
variable "api_discovery_code_scan" {
  description = "API discovery from code scan: off, selected (scan api_discovery_code_scan_repos), or all (all repos)."
  type        = string
  default     = "off"

  validation {
    condition     = contains(["off", "selected", "all"], var.api_discovery_code_scan)
    error_message = "api_discovery_code_scan must be \"off\", \"selected\", or \"all\"."
  }
}

variable "api_discovery_code_scan_repos" {
  description = "Repositories to scan when api_discovery_code_scan=selected (e.g. [\"api-catalog\"])."
  type        = list(string)
  default     = []
}
