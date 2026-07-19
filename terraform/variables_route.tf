# Root passthrough for standalone route objects + LB custom_route ref (CR-5).
variable "route_objects" {
  description = "Standalone xcsh_route objects (see module for shape)."
  type        = any
  default     = []
}

variable "custom_route_ref" {
  description = "Name of a route_objects entry to attach to the LB as a custom_route. null = none."
  type        = string
  default     = null
}
