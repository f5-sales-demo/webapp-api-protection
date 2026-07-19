# CR-5: standalone xcsh_route objects, referenceable by the LB via a custom_route (route_ref).
# A route object is authored once (a match -> direct-response) and attached to the LB. Kept
# minimal (match path prefix -> direct_response code+body); the route object's full surface
# mirrors the inline routes covered in CR-1..CR-4. Empty list creates nothing (0-change).

variable "route_objects" {
  description = "Standalone xcsh_route objects (name -> match prefix -> direct response), referenceable by the LB."
  type = list(object({
    name          = string
    path_prefix   = string # routes[].match[].path.prefix
    response_code = optional(number, 200)
    response_body = optional(string, "routed via xcsh_route")
  }))
  default = []

  validation {
    condition     = alltrue([for r in var.route_objects : startswith(r.path_prefix, "/")])
    error_message = "route_objects[].path_prefix must start with '/'."
  }
}

variable "custom_route_ref" {
  description = "Name of a route_objects entry to attach to the LB as a custom_route. null = none."
  type        = string
  default     = null
}
