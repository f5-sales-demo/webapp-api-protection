# Root passthrough for GraphQL inspection (LPC-3). Object list uses type = any (shape in module).
variable "graphql_rules" {
  description = "GraphQL inspection rules on the LB (see module for shape)."
  type        = any
  default     = []
}
