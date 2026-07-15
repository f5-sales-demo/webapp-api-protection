# API spec source-control integration (SP2): xcsh_code_base_integration (github arm).
# F5 XC pulls OpenAPI specs from the repo; the LB selects repos via
# api_discovery_from_code_scan (LB wiring lands with provider #1091). access_token
# reuses the clear/blindfold SecretType convention (locals_api.tf rendered_secret) —
# the identical SecretType shape as the crawler password (DRY, second consumer).

variable "code_base_integration_enabled" {
  description = "Create an xcsh_code_base_integration F5 XC uses to pull API specs from source control (e.g. the api-catalog repo)."
  type        = bool
  default     = false
}

# Coverage Batch E: SCM provider selector. The token (code_base_integration_access_token)
# is sent as access_token for github/github_enterprise/gitlab/gitlab_enterprise/azure_repos
# and as passwd for bitbucket/bitbucket_server. Per-arm fields: username (github,
# github_enterprise, bitbucket, bitbucket_server), hostname (github_enterprise),
# url (gitlab_enterprise, bitbucket_server), verify_ssl (github, bitbucket_server).
variable "code_base_integration_provider" {
  description = "SCM provider: github | github_enterprise | gitlab | gitlab_enterprise | azure_repos | bitbucket | bitbucket_server."
  type        = string
  default     = "github"

  validation {
    condition     = contains(["github", "github_enterprise", "gitlab", "gitlab_enterprise", "azure_repos", "bitbucket", "bitbucket_server"], var.code_base_integration_provider)
    error_message = "code_base_integration_provider must be one of github, github_enterprise, gitlab, gitlab_enterprise, azure_repos, bitbucket, bitbucket_server."
  }
}

variable "code_base_integration_username" {
  description = "SCM username (github, github_enterprise, bitbucket, bitbucket_server arms)."
  type        = string
  default     = ""
}

variable "code_base_integration_hostname" {
  description = "SCM hostname (github_enterprise arm)."
  type        = string
  default     = ""
}

variable "code_base_integration_url" {
  description = "SCM base URL (gitlab_enterprise, bitbucket_server arms)."
  type        = string
  default     = ""
}

variable "code_base_integration_verify_ssl" {
  description = "Verify the SCM server TLS certificate (github, bitbucket_server arms)."
  type        = bool
  default     = true
}

variable "code_base_integration_access_token" {
  description = "SCM access token/passwd as a selectable clear/blindfold secret. clear: set plaintext (or provider_ref). blindfold: set location to a pre-sealed 'string:///...' from scripts/blindfold-seal.sh (optionally store_provider/decryption_provider for an external secret backend)."
  type = object({
    method    = optional(string, "clear")
    plaintext = optional(string)
    location  = optional(string)
    # Optional external secret-management backend refs (Batch G):
    store_provider      = optional(string)
    decryption_provider = optional(string)
    provider_ref        = optional(string)
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

  validation {
    condition     = var.code_base_integration_access_token.method == "blindfold" || (var.code_base_integration_access_token.store_provider == null && var.code_base_integration_access_token.decryption_provider == null)
    error_message = "store_provider/decryption_provider are blindfold-only secret backends."
  }

  validation {
    condition     = var.code_base_integration_access_token.method == "clear" || var.code_base_integration_access_token.provider_ref == null
    error_message = "provider_ref is a clear-secret backend only."
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
