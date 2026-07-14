# Root-level API Discovery & Crawler (SP1) inputs, passed through to modules/http-lb.
# Defaults mirror the module and reproduce the current bare enable_api_discovery {}
# (0-change). The api-discovery matrix supplies these via -var-file per variant.

variable "api_discovery_choice" {
  description = "api_discovery_choice: enable or disable."
  type        = string
  default     = "enable"
}

variable "api_discovery_learn_from_redirect" {
  description = "enable_api_discovery learn-from-redirect: omit or enable."
  type        = string
  default     = "omit"
}

variable "api_discovery_purge_duration" {
  description = "discovered_api_settings purge duration (days); null = omit."
  type        = number
  default     = null
}

variable "api_discovery_auth_mode" {
  description = "api-auth-discovery: default or custom."
  type        = string
  default     = "default"
}

variable "api_discovery_custom_auth_types" {
  description = "Custom auth types when api_discovery_auth_mode=custom."
  type = list(object({
    parameter_name = string
    parameter_type = string
  }))
  default = []
}

variable "api_crawler_domains" {
  description = "Authenticated domains for the inline API crawler; empty = no crawler."
  type = list(object({
    domain = string
    user   = string
  }))
  default = []
}

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
}
