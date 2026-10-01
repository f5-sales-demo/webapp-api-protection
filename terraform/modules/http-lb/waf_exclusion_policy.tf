# Standalone WAF exclusion policies (LPC-4b). See variables_waf_exclusion_policy.tf. for_each
# keyed by name so the LB waf_exclusion.waf_exclusion_policy arm can reference a specific policy
# via xcsh_waf_exclusion_policy.this[<name>]. The rule shape mirrors the inline arm (4a).
resource "xcsh_waf_exclusion_policy" "this" {
  for_each = { for p in var.waf_exclusion_policies : p.name => p }

  name      = each.value.name
  namespace = var.namespace

  dynamic "waf_exclusion_rules" {
    for_each = each.value.rules
    iterator = rule
    content {
      metadata {
        name             = rule.value.name
        description_spec = rule.value.description
      }
      any_domain           = rule.value.domain == "any" ? {} : null
      exact_value          = rule.value.domain == "exact" ? rule.value.domain_value : null
      suffix_value         = rule.value.domain == "suffix" ? rule.value.domain_value : null
      any_path             = rule.value.path == "any" ? {} : null
      path_prefix          = rule.value.path == "prefix" ? rule.value.path_value : null
      path_regex           = rule.value.path == "regex" ? rule.value.path_value : null
      methods              = length(rule.value.methods) > 0 ? rule.value.methods : null
      expiration_timestamp = rule.value.expiration_timestamp
      waf_skip_processing  = rule.value.action == "skip" ? {} : null
      dynamic "app_firewall_detection_control" {
        for_each = rule.value.action == "detection_control" ? [1] : []
        content {
          dynamic "exclude_signature_contexts" {
            for_each = rule.value.exclude_signatures
            iterator = s
            content {
              signature_id = s.value.signature_id
              context      = s.value.context
              context_name = s.value.context_name
            }
          }
          dynamic "exclude_violation_contexts" {
            for_each = rule.value.exclude_violations
            iterator = v
            content {
              exclude_violation = v.value.violation
              context           = v.value.context
              context_name      = v.value.context_name
            }
          }
          dynamic "exclude_attack_type_contexts" {
            for_each = rule.value.exclude_attack_types
            iterator = a
            content {
              exclude_attack_type = a.value.attack_type
              context             = a.value.context
              context_name        = a.value.context_name
            }
          }
          dynamic "exclude_bot_name_contexts" {
            for_each = rule.value.exclude_bot_names
            iterator = b
            content {
              bot_name = b.value
            }
          }
        }
      }
    }
  }
}
