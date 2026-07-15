# Root passthrough for the per-endpoint api_rate_limit arm (Coverage Batch B).
# Thin passthrough: the full object type + validation live once in the module
# (modules/http-lb/variables_api_rate_limit.tf), so the root wrapper uses type=any
# to avoid redeclaring the module's contract. Empty defaults keep the arm off.
variable "api_rate_limit_endpoint_rules" {
  description = "api_rate_limit.api_endpoint_rules passthrough (typed+validated in the module)."
  type        = any
  default     = []
}

variable "api_rate_limit_bypass_rules" {
  description = "api_rate_limit.bypass_rate_limiting_rules passthrough (typed+validated in the module)."
  type        = any
  default     = []
}

variable "api_rate_limit_server_url_rules" {
  description = "api_rate_limit.server_url_rules passthrough (typed+validated in the module)."
  type        = any
  default     = []
}
