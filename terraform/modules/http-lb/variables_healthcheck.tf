# LPC-5a: xcsh_healthcheck.origin parameterization. Defaults reproduce today's config exactly
# (http health check on health_check_path expecting 200; thresholds 3/1/3/15) so a plain apply
# is 0-change. The check must keep the HTTP origin healthy — udp_icmp is intentionally not
# offered (it would mark the origin down and stop the LB serving).

variable "health_check_type" {
  description = "Health check type: http or tcp. (udp_icmp is unsupported here — it breaks the HTTP origin.)"
  type        = string
  default     = "http"
  validation {
    condition     = contains(["http", "tcp"], var.health_check_type)
    error_message = "health_check_type must be http or tcp."
  }
}

variable "hc_healthy_threshold" {
  description = "Consecutive successful checks to mark the origin healthy."
  type        = number
  default     = 3
}

variable "hc_unhealthy_threshold" {
  description = "Consecutive failed checks to mark the origin unhealthy."
  type        = number
  default     = 1
}

variable "hc_timeout" {
  description = "Health check timeout (seconds)."
  type        = number
  default     = 3
}

variable "hc_interval" {
  description = "Health check interval (seconds)."
  type        = number
  default     = 15
}

variable "hc_jitter_percent" {
  description = "Jitter percent applied to the interval. null omits (server default)."
  type        = number
  default     = null
}

# --- http_health_check fields ---
# Host handling is the http host oneof: set hc_http_host_header to send an explicit Host header;
# leave it null to use the origin server name (use_origin_server_name {}), which is the F5 XC
# server default whenever no host_header is set. The module emits exactly one arm to match the
# server, so the import round-trip stays clean.
variable "hc_http_host_header" {
  description = "Host header for the health check. null => use_origin_server_name (server default)."
  type        = string
  default     = null
}

variable "hc_expected_status_codes" {
  description = "HTTP status codes considered healthy (single codes or start-end ranges)."
  type        = list(string)
  default     = ["200"]
}

variable "hc_expected_response" {
  description = "Hex-encoded raw bytes expected in the response body. null = not checked."
  type        = string
  default     = null
}

variable "hc_request_headers_to_remove" {
  description = "HTTP headers removed from each health-check request."
  type        = list(string)
  default     = []
}

# use_http2 is intentionally not exposed: the provider import-suppresses it on Healthcheck, so a
# module-emitted value cannot round-trip cleanly (tracked for a follow-up provider rework). The
# server default (HTTP/1.1) stands.

# --- tcp_health_check fields ---
variable "hc_tcp_send_payload" {
  description = "Hex-encoded bytes to send (tcp). Empty = connect-only check."
  type        = string
  default     = null
}

variable "hc_tcp_expected_response" {
  description = "Hex-encoded bytes expected in the tcp response. null = connect-only."
  type        = string
  default     = null
}
