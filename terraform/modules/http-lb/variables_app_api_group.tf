# App API Groups (Coverage Batch F). Each entry becomes an xcsh_app_api_group scoping
# endpoints on this LB; its name is referenceable from api_protection_group_rules.api_group.
variable "app_api_groups" {
  description = "xcsh_app_api_group definitions: {name, elements[{path_regex, methods}]}. Referenceable by api_protection_group_rules.api_group."
  type = list(object({
    name = string
    elements = optional(list(object({
      path_regex = string
      methods    = optional(list(string), ["ANY"])
    })), [])
  }))
  default = []

  validation {
    condition     = length(var.app_api_groups) == length(distinct([for g in var.app_api_groups : g.name]))
    error_message = "app_api_groups names must be unique."
  }

  validation {
    condition = alltrue([
      for g in var.app_api_groups : alltrue([
        for e in g.elements : alltrue([
          for m in e.methods :
          contains(["ANY", "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH", "COPY"], m)
        ])
      ])
    ])
    error_message = "app_api_groups elements.methods must be valid HTTP methods (ANY, GET, POST, ...)."
  }

  validation {
    condition = alltrue([
      for g in var.app_api_groups : alltrue([
        for e in g.elements : e.path_regex != null && e.path_regex != ""
      ])
    ])
    error_message = "app_api_groups elements require a non-empty path_regex."
  }
}
