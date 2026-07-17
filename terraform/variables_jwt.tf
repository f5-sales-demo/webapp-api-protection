# Root passthrough for JWT validation (LPC-3). Object uses type = any (shape in module).
variable "jwt_validation" {
  description = "JWT validation on the LB (see module for shape). null omits."
  type        = any
  default     = null
}
