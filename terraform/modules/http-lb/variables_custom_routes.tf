# Custom LB routes[] (CR effort). CR-1 wired a simple_route (path prefix -> origin pool). CR-2
# adds the full match surface: path oneof (prefix/exact/regex), header matches, and incoming
# port match. simple_route routes to the module's own origin pool (origin-pool); custom routes
# are additive to default_route_pools (the default route keeps serving). Later slices (CR-3..5)
# add advanced_options, redirect/direct-response, and custom (route_ref) arms. Empty list omits
# routes[] (0-change).

variable "custom_routes" {
  description = "Custom LB routes (simple_route match -> origin pool). Empty omits routes[]."
  type = list(object({
    # match: path oneof (prefix|exact|regex)
    path_mode  = optional(string, "prefix") # prefix|exact|regex
    path_value = string
    # match: http method (server defaults ANY; Optional-not-Computed, so emit explicitly)
    http_method = optional(string, "ANY")
    # match: header matches. mode presence|exact|regex; invert flips the match.
    headers = optional(list(object({
      name         = string
      mode         = optional(string, "presence") # presence|exact|regex
      value        = optional(string)             # required for exact|regex
      invert_match = optional(bool, false)
    })), [])
    # match: incoming port (null = match any port, i.e. no incoming_port block)
    incoming_port = optional(number)
    # --- advanced_options (CR-3): per-route action tuning. All optional; when any is set the
    # block is emitted. Heavy sub-blocks (cors/csrf/retry/mirror/hash/buffer/websocket/bot-js)
    # are deferred. WAF selector: inherited (default) | app_firewall (module WAF) | disable.
    prefix_rewrite = optional(string)            # advanced_options.prefix_rewrite
    priority       = optional(string, "DEFAULT") # advanced_options.priority DEFAULT|HIGH
    # (Optional-not-Computed, server defaults DEFAULT, so emit explicitly)
    disable_location_add = optional(bool, false) # advanced_options.disable_location_add
    timeout_ms           = optional(number)      # advanced_options.timeout
    req_headers_add      = optional(list(object({ name = string, value = string, append = optional(bool, false) })), [])
    req_headers_remove   = optional(list(string), [])
    resp_headers_add     = optional(list(object({ name = string, value = string, append = optional(bool, false) })), [])
    resp_headers_remove  = optional(list(string), [])
    req_cookies_remove   = optional(list(string), [])
    resp_cookies_remove  = optional(list(string), [])
    # inherited (route uses the LB WAF, default) | app_firewall (per-route WAF override to the
    # module's app_firewall). "disable" is intentionally omitted: the route-level disable_waf {}
    # collides with the LB-level disable_waf import-suppression (matched by leaf name at any
    # depth), so it cannot round-trip cleanly until the provider suppression is path-aware.
    waf_mode = optional(string, "inherited") # inherited | app_firewall
  }))
  default = []

  validation {
    condition     = alltrue([for r in var.custom_routes : contains(["prefix", "exact", "regex"], r.path_mode)])
    error_message = "custom_routes[].path_mode must be prefix, exact, or regex."
  }
  validation {
    condition     = alltrue([for r in var.custom_routes : r.path_value != null && r.path_value != ""])
    error_message = "custom_routes[].path_value is required."
  }
  validation {
    condition     = alltrue([for r in var.custom_routes : r.path_mode == "regex" || startswith(r.path_value, "/")])
    error_message = "custom_routes[].path_value must start with '/' (except regex mode)."
  }
  validation {
    condition = alltrue([for r in var.custom_routes :
      contains(["ANY", "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH", "COPY"], r.http_method)
    ])
    error_message = "custom_routes[].http_method must be a valid HTTP method (ANY/GET/HEAD/POST/PUT/DELETE/CONNECT/OPTIONS/TRACE/PATCH/COPY)."
  }
  validation {
    condition     = alltrue([for r in var.custom_routes : alltrue([for h in r.headers : contains(["presence", "exact", "regex"], h.mode)])])
    error_message = "custom_routes[].headers[].mode must be presence, exact, or regex."
  }
  validation {
    condition     = alltrue([for r in var.custom_routes : alltrue([for h in r.headers : h.mode == "presence" || (h.value != null && h.value != "")])])
    error_message = "custom_routes[].headers[].value is required for exact/regex mode."
  }
  validation {
    condition     = alltrue([for r in var.custom_routes : contains(["inherited", "app_firewall"], r.waf_mode)])
    error_message = "custom_routes[].waf_mode must be inherited or app_firewall."
  }
  validation {
    condition     = alltrue([for r in var.custom_routes : contains(["DEFAULT", "HIGH"], r.priority)])
    error_message = "custom_routes[].priority must be DEFAULT or HIGH."
  }
}
