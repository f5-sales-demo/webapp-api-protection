# Root passthrough for custom LB routes (CR effort). Object list uses type = any (shape in module).
variable "custom_routes" {
  description = "Custom LB routes (see module for shape)."
  type        = any
  default     = []
}
