# CR-1 (custom routes foundation): LB routes[] custom routing. CR-1 covers a simple_route that
# matches a path prefix and routes to the module's own origin pool (origin-pool). Custom routes
# are additive to default_route_pools (the default route keeps serving). Later slices (CR-2..5)
# extend this object with full match criteria, advanced_options, redirect/direct-response, and
# custom (route_ref) arms. Empty list omits routes[] (0-change).

variable "custom_routes" {
  description = "Custom LB routes. CR-1: simple_route path-prefix -> the module origin pool."
  type = list(object({
    path_prefix = string                  # simple_route.path.prefix match criterion
    http_method = optional(string, "ANY") # simple_route.http_method (server defaults ANY;
    # schema is Optional-not-Computed, so a null config produces an inconsistent-result apply)
  }))
  default = []

  validation {
    condition     = alltrue([for r in var.custom_routes : startswith(r.path_prefix, "/")])
    error_message = "custom_routes[].path_prefix must start with '/'."
  }
  validation {
    condition = alltrue([for r in var.custom_routes :
      contains(["ANY", "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH", "COPY"], r.http_method)
    ])
    error_message = "custom_routes[].http_method must be a valid HTTP method (ANY/GET/HEAD/POST/PUT/DELETE/CONNECT/OPTIONS/TRACE/PATCH/COPY)."
  }
}
