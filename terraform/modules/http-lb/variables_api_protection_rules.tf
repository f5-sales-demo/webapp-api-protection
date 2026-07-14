# API protection rules (SP3) — api_protection_rules.api_endpoint_rules[]: allow or
# deny access to specific API endpoints, optionally scoped by the shared
# client-matcher (var.client_matcher). Omitted when the list is empty (0-change).
# Each rule: {path, domain (any|specific), methods, action allow|deny}. The shared
# client-matcher applies to every rule (module-level client scope).
variable "api_protection_rules" {
  description = "api_protection_rules.api_endpoint_rules: list of {path, domain_mode any|specific, domain, methods, action allow|deny}."
  type = list(object({
    path        = string
    domain_mode = optional(string, "any")
    domain      = optional(string)
    methods     = optional(list(string), ["ANY"])
    action      = optional(string, "allow")
  }))
  default = []

  validation {
    condition = alltrue([
      for r in var.api_protection_rules : contains(["any", "specific"], r.domain_mode)
    ])
    error_message = "each api_protection_rules domain_mode must be any or specific."
  }

  validation {
    condition = alltrue([
      for r in var.api_protection_rules : r.domain_mode == "any" || r.domain != null
    ])
    error_message = "api_protection_rules with domain_mode specific require a domain."
  }

  validation {
    condition = alltrue([
      for r in var.api_protection_rules : contains(["allow", "deny"], r.action)
    ])
    error_message = "each api_protection_rules action must be allow or deny."
  }

  validation {
    condition = alltrue([
      for r in var.api_protection_rules : alltrue([
        for m in r.methods :
        contains(["ANY", "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH", "COPY"], m)
      ])
    ])
    error_message = "each api_protection_rules method must be a valid HTTP method."
  }
}
