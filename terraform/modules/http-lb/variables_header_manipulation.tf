# Header/cookie manipulation (LPC-2) via the LB top-level more_option block: add/remove
# request and response headers (and cookies). secret_value (blindfold-sealed header value)
# is deferred. Defaults create nothing and emit no more_option block (0-change).

variable "request_headers_to_add" {
  description = "Request headers to add/append toward the origin (more_option.request_headers_to_add)."
  type = list(object({
    name   = string
    value  = string
    append = optional(bool, false)
  }))
  default = []
}

variable "request_headers_to_remove" {
  description = "Request header names to remove toward the origin."
  type        = list(string)
  default     = []
}

variable "response_headers_to_add" {
  description = "Response headers to add/append toward the client (more_option.response_headers_to_add)."
  type = list(object({
    name   = string
    value  = string
    append = optional(bool, false)
  }))
  default = []
}

variable "response_headers_to_remove" {
  description = "Response header names to remove toward the client."
  type        = list(string)
  default     = []
}

variable "request_cookies_to_remove" {
  description = "Request cookie names to remove toward the origin (more_option.request_cookies_to_remove)."
  type        = list(string)
  default     = []
}

variable "response_cookies_to_remove" {
  description = "Response cookie names to remove toward the client (more_option.response_cookies_to_remove)."
  type        = list(string)
  default     = []
}
