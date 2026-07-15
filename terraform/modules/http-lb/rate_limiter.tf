# Standalone reusable rate limiters (Coverage Batch B). See variables_rate_limiter.tf.
# for_each keyed by name so policies/api_rate_limit can reference a specific limiter
# via xcsh_rate_limiter.this[<name>].
resource "xcsh_rate_limiter" "this" {
  for_each = { for rl in var.rate_limiters : rl.name => rl }

  name      = each.value.name
  namespace = var.namespace

  dynamic "limits" {
    for_each = each.value.limits
    content {
      total_number      = limits.value.total_number
      unit              = limits.value.unit
      burst_multiplier  = limits.value.burst_multiplier
      period_multiplier = limits.value.period_multiplier

      # action oneof: block (with a duration in the chosen unit) | disabled.
      dynamic "action_block" {
        for_each = limits.value.action == "block" ? [1] : []
        content {
          dynamic "hours" {
            for_each = limits.value.action_block_unit == "hours" ? [1] : []
            content {
              duration = limits.value.action_block_duration
            }
          }
          dynamic "minutes" {
            for_each = limits.value.action_block_unit == "minutes" ? [1] : []
            content {
              duration = limits.value.action_block_duration
            }
          }
          dynamic "seconds" {
            for_each = limits.value.action_block_unit == "seconds" ? [1] : []
            content {
              duration = limits.value.action_block_duration
            }
          }
        }
      }
      dynamic "disabled" {
        for_each = limits.value.action == "disabled" ? [1] : []
        content {}
      }

      # burst-algorithm oneof: leaky_bucket | token_bucket (omit => server default).
      dynamic "leaky_bucket" {
        for_each = limits.value.algorithm == "leaky_bucket" ? [1] : []
        content {}
      }
      dynamic "token_bucket" {
        for_each = limits.value.algorithm == "token_bucket" ? [1] : []
        content {}
      }
    }
  }

  dynamic "user_identification" {
    for_each = each.value.user_identification
    content {
      name      = user_identification.value.name
      namespace = coalesce(user_identification.value.namespace, var.namespace)
    }
  }
}
