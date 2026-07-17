# LPC-5b: xcsh_origin_pool.origin tuning. origin_servers (public_ip) and TLS (no_tls) are the
# live serving path and are NOT parameterized here. Defaults reproduce today's pool
# (ROUND_ROBIN, DISTRIBUTED, no advanced_options) so a plain apply is 0-change.

variable "origin_lb_algorithm" {
  description = "Origin pool load-balancing algorithm: ROUND_ROBIN | LEAST_REQUEST | RANDOM."
  type        = string
  default     = "ROUND_ROBIN"
  validation {
    # RING_HASH / LB_OVERRIDE need companion route hash/override config, so they are excluded.
    condition     = contains(["ROUND_ROBIN", "LEAST_REQUEST", "RANDOM"], var.origin_lb_algorithm)
    error_message = "origin_lb_algorithm must be ROUND_ROBIN, LEAST_REQUEST, or RANDOM."
  }
}

variable "origin_endpoint_selection" {
  description = "Endpoint selection policy: DISTRIBUTED | LOCAL_ONLY | LOCAL_PREFERRED."
  type        = string
  default     = "DISTRIBUTED"
  validation {
    condition     = contains(["DISTRIBUTED", "LOCAL_ONLY", "LOCAL_PREFERRED"], var.origin_endpoint_selection)
    error_message = "origin_endpoint_selection must be DISTRIBUTED, LOCAL_ONLY, or LOCAL_PREFERRED."
  }
}

variable "origin_connection_timeout" {
  description = "advanced_options.connection_timeout (ms) for new connections. null omits advanced_options."
  type        = number
  default     = null
}

variable "origin_http_idle_timeout" {
  description = "advanced_options.http_idle_timeout (ms) for idle upstream connections. null omits."
  type        = number
  default     = null
}
