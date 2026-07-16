# Root-level service-policy (SPol effort) passthrough to modules/http-lb. The full typed
# object + validation live once in the module (modules/http-lb/variables_service_policy.tf),
# so the object var uses type = any; scalar knobs mirror the module defaults. Defaults
# create nothing and emit no LB block (0-change).

variable "service_policies" {
  description = "Standalone xcsh_service_policy objects to create (see module for the object shape)."
  type        = any
  default     = []
}

variable "service_policies_choice" {
  description = "LB service_policies_choice: omit | none | active. Validated in the module."
  type        = string
  default     = "omit"
}

variable "service_policy_active" {
  description = "Ordered service policy names to attach when service_policies_choice=active."
  type        = list(string)
  default     = []
}
