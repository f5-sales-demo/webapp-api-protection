# Root passthrough for app-layer protection (LPC-1) to modules/http-lb. Typed objects use
# type = any (full shape + validation live in the module). Defaults = 0-change.

variable "cors_policy" {
  description = "CORS policy on the LB (see module for the object shape)."
  type        = any
  default     = null
}

variable "csrf_policy_mode" {
  description = "CSRF policy oneof: omit | all_domains | custom | disabled."
  type        = string
  default     = "omit"
}

variable "csrf_custom_domains" {
  description = "Allowed source domains when csrf_policy_mode=custom."
  type        = list(string)
  default     = []
}

variable "protected_cookies" {
  description = "Per-cookie protection rules on the LB (see module for the object shape)."
  type        = any
  default     = []
}
