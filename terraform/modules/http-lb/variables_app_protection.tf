# App-layer response/cookie protection (LPC-1) on the HTTP LB: cors_policy, csrf_policy,
# and protected_cookies. All top-level LB features (apply to the default-route LB — no
# custom routes needed). Defaults create nothing and emit no LB block (0-change).

variable "cors_policy" {
  description = "CORS policy on the LB. Set to configure access-control-* response headers; null omits the block."
  type = object({
    allow_origin       = optional(list(string), [])
    allow_origin_regex = optional(list(string), [])
    allow_methods      = optional(string) # access-control-allow-methods content
    allow_headers      = optional(string)
    expose_headers     = optional(string)
    maximum_age        = optional(number) # access-control-max-age seconds
    allow_credentials  = optional(bool, false)
    disabled           = optional(bool, false)
  })
  default = null
}

variable "csrf_policy_mode" {
  description = "CSRF policy oneof: omit (no block) | all_domains (all_load_balancer_domains) | custom (custom_domain_list) | disabled."
  type        = string
  default     = "omit"

  validation {
    condition     = contains(["omit", "all_domains", "custom", "disabled"], var.csrf_policy_mode)
    error_message = "csrf_policy_mode must be omit, all_domains, custom, or disabled."
  }
}

variable "csrf_custom_domains" {
  description = "Allowed source domains when csrf_policy_mode=\"custom\" (custom_domain_list.domains)."
  type        = list(string)
  default     = []
}

variable "protected_cookies" {
  description = "Per-cookie protection rules on the LB. Each names a cookie and selects attribute handling (httponly/secure/samesite/tampering) via single-knob selectors."
  type = list(object({
    name           = string
    max_age_value  = optional(number)
    httponly       = optional(string, "omit") # omit|add|ignore
    secure         = optional(string, "omit") # omit|add|ignore
    samesite       = optional(string, "omit") # omit|lax|none|strict|ignore
    tampering      = optional(string, "omit") # omit|enable|disable
    ignore_max_age = optional(bool, false)
  }))
  default = []

  validation {
    condition = alltrue([
      for c in var.protected_cookies :
      contains(["omit", "add", "ignore"], c.httponly) && contains(["omit", "add", "ignore"], c.secure)
    ])
    error_message = "each protected_cookies[].httponly / secure must be omit, add, or ignore."
  }
  validation {
    condition = alltrue([
      for c in var.protected_cookies : contains(["omit", "lax", "none", "strict", "ignore"], c.samesite)
    ])
    error_message = "each protected_cookies[].samesite must be omit, lax, none, strict, or ignore."
  }
  validation {
    condition = alltrue([
      for c in var.protected_cookies : contains(["omit", "enable", "disable"], c.tampering)
    ])
    error_message = "each protected_cookies[].tampering must be omit, enable, or disable."
  }
}
