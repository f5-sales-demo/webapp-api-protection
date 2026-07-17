# Root passthrough for header/cookie manipulation (LPC-2) to modules/http-lb. Object lists
# use type = any (shape lives in the module). Defaults = 0-change.

variable "request_headers_to_add" {
  description = "Request headers to add (see module for shape)."
  type        = any
  default     = []
}
variable "request_headers_to_remove" {
  description = "Request header names to remove."
  type        = list(string)
  default     = []
}
variable "response_headers_to_add" {
  description = "Response headers to add (see module for shape)."
  type        = any
  default     = []
}
variable "response_headers_to_remove" {
  description = "Response header names to remove."
  type        = list(string)
  default     = []
}
variable "request_cookies_to_remove" {
  description = "Request cookie names to remove."
  type        = list(string)
  default     = []
}
variable "response_cookies_to_remove" {
  description = "Response cookie names to remove."
  type        = list(string)
  default     = []
}

variable "disable_default_error_pages" {
  description = "Disable the LB's default error pages (more_option)."
  type        = bool
  default     = false
}
