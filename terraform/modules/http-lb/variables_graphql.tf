# GraphQL inspection (LPC-3) via the LB top-level graphql_rules[]. Each rule targets a
# GraphQL endpoint (path + domain + method) and applies limits + introspection control.
# Default creates nothing (0-change).

variable "graphql_rules" {
  description = "GraphQL inspection rules on the LB. Each matches a path/domain/method and sets query limits + introspection."
  type = list(object({
    name                = string                   # metadata.name
    exact_path          = optional(string)         # the GraphQL endpoint path, e.g. /graphql
    domain              = optional(string, "any")  # any|exact|suffix
    domain_value        = optional(string)         # value for domain=exact|suffix
    method              = optional(string, "post") # get|post
    max_batched_queries = optional(number)
    max_depth           = optional(number)
    max_total_length    = optional(number)
    max_value_length    = optional(number)
    policy_name         = optional(string)
    introspection       = optional(string, "omit") # omit|enable|disable
  }))
  default = []

  validation {
    condition     = alltrue([for r in var.graphql_rules : contains(["any", "exact", "suffix"], r.domain)])
    error_message = "each graphql_rules[].domain must be any, exact, or suffix."
  }
  validation {
    condition     = alltrue([for r in var.graphql_rules : contains(["get", "post"], r.method)])
    error_message = "each graphql_rules[].method must be get or post."
  }
  validation {
    condition     = alltrue([for r in var.graphql_rules : contains(["omit", "enable", "disable"], r.introspection)])
    error_message = "each graphql_rules[].introspection must be omit, enable, or disable."
  }
  validation {
    condition     = alltrue([for r in var.graphql_rules : r.domain == "any" || (r.domain_value != null && r.domain_value != "")])
    error_message = "graphql_rules[].domain_value is required when domain is exact or suffix."
  }
}
