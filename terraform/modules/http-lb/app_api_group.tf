# Standalone App API Groups (Coverage Batch F) — xcsh_app_api_group objects that make
# api_protection_rules.api_groups_rules.api_group referenceable. Each group scopes a
# set of endpoints on THIS LB via elements (path_regex + methods) and is associated to
# the load balancer by name. Default [] creates none (0-change).
#
# The group references the LB by the static local.lb_name (NOT xcsh_http_loadbalancer.this)
# so there is no resource-dependency cycle: the LB's api_groups_rules validates the group
# by name at apply, so groups must exist first — enforced by the LB's depends_on below.
resource "xcsh_app_api_group" "this" {
  for_each = { for g in var.app_api_groups : g.name => g }

  name      = each.value.name
  namespace = var.namespace

  http_loadbalancer {
    http_loadbalancer {
      name      = local.lb_name
      namespace = var.namespace
    }
  }

  dynamic "elements" {
    for_each = each.value.elements
    content {
      path_regex = elements.value.path_regex
      methods    = length(elements.value.methods) > 0 ? elements.value.methods : null
    }
  }
}

output "app_api_group_names" {
  description = "Names of the standalone xcsh_app_api_group resources created."
  value       = sort([for g in xcsh_app_api_group.this : g.name])
}

output "app_api_group_count" {
  description = "Number of standalone xcsh_app_api_group resources created."
  value       = length(xcsh_app_api_group.this)
}
