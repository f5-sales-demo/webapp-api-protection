# Standalone service policies (SPol effort). See variables_service_policy.tf.
# for_each keyed by name so the LB active_service_policies arm can reference a specific
# policy via xcsh_service_policy.this[<name>].
#
# Optional list attributes are emitted as null (not []) when empty: F5 XC omits empty
# lists on read, so forcing [] into the plan drifts against the read-back. null matches
# the API's omit.
#
# Server-scope oneof: omitting every arm (server_scope="any_server") leaves the server to
# apply its default any_server {}, which the provider suppresses on import (SPol-1 Layer 1
# seed) — so we emit NO server block for that arm and stay import-clean.
resource "xcsh_service_policy" "this" {
  for_each = { for p in var.service_policies : p.name => p }

  name      = each.value.name
  namespace = var.namespace

  # --- server scope oneof (omit any_server => server default, import-suppressed) ---
  server_name = each.value.server_scope == "name" ? each.value.server_name : null

  dynamic "server_name_matcher" {
    for_each = each.value.server_scope == "name_matcher" ? [1] : []
    content {
      exact_values = length(each.value.server_name_exact) > 0 ? each.value.server_name_exact : null
      regex_values = length(each.value.server_name_regex) > 0 ? each.value.server_name_regex : null
    }
  }
  dynamic "server_selector" {
    for_each = each.value.server_scope == "selector" ? [1] : []
    content {
      expressions = length(each.value.server_selector) > 0 ? each.value.server_selector : null
    }
  }

  # --- rule-handling oneof (exactly one arm) ---
  dynamic "allow_all_requests" {
    for_each = each.value.rule_handling == "allow_all" ? [1] : []
    content {}
  }
  dynamic "deny_all_requests" {
    for_each = each.value.rule_handling == "deny_all" ? [1] : []
    content {}
  }
  dynamic "allow_list" {
    for_each = each.value.rule_handling == "allow_list" ? [1] : []
    content {}
  }
  dynamic "deny_list" {
    for_each = each.value.rule_handling == "deny_list" ? [1] : []
    content {}
  }
  dynamic "rule_list" {
    for_each = each.value.rule_handling == "rule_list" ? [1] : []
    content {
      dynamic "rules" {
        for_each = each.value.rules
        content {
          metadata {
            name = rules.value.name
          }
          spec {
            action = rules.value.action
          }
        }
      }
    }
  }

  # rule_list must carry at least one rule (an empty rule_list {} is meaningless and the
  # API rejects it); server_scope="name" needs a server_name.
  lifecycle {
    precondition {
      condition     = each.value.rule_handling != "rule_list" || length(each.value.rules) > 0
      error_message = "service_policy '${each.value.name}' uses rule_handling=\"rule_list\" but has no rules."
    }
    precondition {
      condition     = each.value.server_scope != "name" || (each.value.server_name != null && each.value.server_name != "")
      error_message = "service_policy '${each.value.name}' uses server_scope=\"name\" but server_name is unset."
    }
  }
}
