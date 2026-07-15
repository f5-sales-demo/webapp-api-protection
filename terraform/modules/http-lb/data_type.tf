# Standalone custom data types (Coverage Batch C). See variables_data_type.tf.
# for_each keyed by name so the sensitive_data_policy custom_data_types arm can
# reference a specific type via xcsh_data_type.this[<name>].
resource "xcsh_data_type" "this" {
  for_each = { for d in var.data_types : d.name => d }

  name      = each.value.name
  namespace = var.namespace
  # compliances/is_pii/is_sensitive_data are Required on xcsh_data_type — always set
  # (compliances defaults to [] rather than null).
  compliances       = each.value.compliances
  is_pii            = each.value.is_pii
  is_sensitive_data = each.value.is_sensitive_data

  dynamic "rules" {
    for_each = each.value.rules
    content {
      # type=key -> key_pattern matcher
      dynamic "key_pattern" {
        for_each = rules.value.type == "key" ? [1] : []
        content {
          regex_value     = rules.value.key_matcher == "regex" ? rules.value.key_regex : null
          substring_value = rules.value.key_matcher == "substring" ? rules.value.key_substring : null
          dynamic "exact_values" {
            for_each = rules.value.key_matcher == "exact" ? [1] : []
            content {
              exact_values = rules.value.key_exact
            }
          }
        }
      }
      # type=value -> value_pattern matcher
      dynamic "value_pattern" {
        for_each = rules.value.type == "value" ? [1] : []
        content {
          regex_value     = rules.value.value_matcher == "regex" ? rules.value.value_regex : null
          substring_value = rules.value.value_matcher == "substring" ? rules.value.value_substring : null
          dynamic "exact_values" {
            for_each = rules.value.value_matcher == "exact" ? [1] : []
            content {
              exact_values = rules.value.value_exact
            }
          }
        }
      }
      # type=key_value -> both key_pattern and value_pattern
      dynamic "key_value_pattern" {
        for_each = rules.value.type == "key_value" ? [1] : []
        content {
          key_pattern {
            regex_value     = rules.value.key_matcher == "regex" ? rules.value.key_regex : null
            substring_value = rules.value.key_matcher == "substring" ? rules.value.key_substring : null
            dynamic "exact_values" {
              for_each = rules.value.key_matcher == "exact" ? [1] : []
              content {
                exact_values = rules.value.key_exact
              }
            }
          }
          value_pattern {
            regex_value     = rules.value.value_matcher == "regex" ? rules.value.value_regex : null
            substring_value = rules.value.value_matcher == "substring" ? rules.value.value_substring : null
            dynamic "exact_values" {
              for_each = rules.value.value_matcher == "exact" ? [1] : []
              content {
                exact_values = rules.value.value_exact
              }
            }
          }
        }
      }
    }
  }
}
