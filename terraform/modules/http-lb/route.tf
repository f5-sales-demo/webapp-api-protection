# Standalone WAF/route objects (CR-5). for_each keyed by name so the LB custom_route arm can
# reference a specific route via xcsh_route.this[<name>]. Minimal: one route matching a path
# prefix and returning a direct response (the object's full surface mirrors the inline routes).
resource "xcsh_route" "this" {
  for_each = { for r in var.route_objects : r.name => r }

  name      = each.value.name
  namespace = var.namespace

  routes {
    # disable_location_add is Optional-not-Computed with a server default — emit explicitly.
    disable_location_add = false
    match {
      # http_method is the server-default "ANY" (Optional-not-Computed) — emit explicitly.
      http_method = "ANY"
      path {
        prefix = each.value.path_prefix
      }
    }
    route_direct_response {
      response_code = each.value.response_code
      # response_body_encoded is a string:///<base64> URI ref (same as the inline direct route).
      response_body_encoded = "string:///${base64encode(each.value.response_body)}"
    }
    # waf_type is a required oneof the server materializes on apply (was-absent-now-present);
    # emit the inherit arm so the route uses the LB WAF and the apply is consistent.
    waf_type {
      inherit_waf {}
    }
  }
}
