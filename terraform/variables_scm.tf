# Root-level SCM (code_base_integration) inputs for SP2, passed to modules/http-lb.
# Defaults keep it disabled (0-change). Matrix supplies these via -var-file.

variable "code_base_integration_enabled" {
  description = "Create an xcsh_code_base_integration (github) to pull API specs from source control (api-catalog)."
  type        = bool
  default     = false
}

variable "code_base_integration_username" {
  description = "GitHub username for the code_base_integration."
  type        = string
  default     = ""
}

variable "code_base_integration_access_token" {
  description = "GitHub access token as a selectable clear/blindfold secret (clear: plaintext; blindfold: pre-sealed location)."
  type = object({
    method    = optional(string, "clear")
    plaintext = optional(string)
    location  = optional(string)
  })
  default   = { method = "clear", plaintext = null }
  sensitive = true
}
