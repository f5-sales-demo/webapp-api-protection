# Root-level client access control (CAC) passthrough to modules/http-lb. The full typed
# objects + validations live once in the module (modules/http-lb/variables_client_access.tf),
# so object vars use type = any; the scalar knobs mirror the module defaults. Defaults create
# nothing and emit no LB block (0-change).

variable "trusted_clients" {
  description = "Trusted-client rules on the LB (see module for the object shape)."
  type        = any
  default     = []
}

variable "blocked_clients" {
  description = "Blocked-client rules on the LB (see module for the object shape)."
  type        = any
  default     = []
}

variable "ip_reputation_enabled" {
  description = "Enable IP-reputation filtering on the LB."
  type        = bool
  default     = false
}

variable "ip_reputation_categories" {
  description = "IpThreatCategory values to block when ip_reputation_enabled."
  type        = list(string)
  default     = []
}
