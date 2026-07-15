# Standalone rate-limiter policies (Coverage Batch B). See variables_rate_limiter_policy.tf.
# for_each keyed by name so the LB rate_limit.policies arm can reference a specific
# policy via xcsh_rate_limiter_policy.this[<name>].
#
# Optional list attributes are emitted as null (not []) when empty: F5 XC omits empty
# lists on read, so forcing [] into the plan drifts against the read-back (plan []
# vs state null => "inconsistent result after apply"). null matches the API's omit.
resource "xcsh_rate_limiter_policy" "this" {
  for_each = { for p in var.rate_limiter_policies : p.name => p }

  name      = each.value.name
  namespace = var.namespace

  # server scope oneof
  dynamic "any_server" {
    for_each = each.value.server_scope == "any_server" ? [1] : []
    content {}
  }
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

  dynamic "rules" {
    for_each = each.value.rules
    content {
      metadata {
        name = rules.value.name
      }
      spec {
        # --- action oneof ---
        dynamic "apply_rate_limiter" {
          for_each = rules.value.action == "apply" ? [1] : []
          content {}
        }
        dynamic "bypass_rate_limiter" {
          for_each = rules.value.action == "bypass" ? [1] : []
          content {}
        }
        dynamic "custom_rate_limiter" {
          for_each = rules.value.action == "custom" ? [1] : []
          content {
            name      = xcsh_rate_limiter.this[rules.value.custom_rate_limiter].name
            namespace = var.namespace
          }
        }

        # --- ASN client matcher oneof (omit => server-default any_asn, import-suppressed) ---
        dynamic "asn_list" {
          for_each = rules.value.asn == "list" ? [1] : []
          content {
            as_numbers = rules.value.asn_numbers
          }
        }
        dynamic "asn_matcher" {
          for_each = rules.value.asn == "matcher" ? [1] : []
          content {
            dynamic "asn_sets" {
              for_each = rules.value.asn_sets
              content {
                name      = asn_sets.value.name
                namespace = coalesce(asn_sets.value.namespace, var.namespace)
              }
            }
          }
        }

        # --- IP client matcher oneof (omit => server-default any_ip, import-suppressed) ---
        dynamic "ip_prefix_list" {
          for_each = rules.value.ip == "prefix_list" ? [1] : []
          content {
            ip_prefixes  = rules.value.ip_prefixes
            invert_match = rules.value.ip_invert
          }
        }
        dynamic "ip_matcher" {
          for_each = rules.value.ip == "matcher" ? [1] : []
          content {
            invert_matcher = rules.value.ip_invert
            dynamic "prefix_sets" {
              for_each = rules.value.ip_sets
              content {
                name      = prefix_sets.value.name
                namespace = coalesce(prefix_sets.value.namespace, var.namespace)
              }
            }
          }
        }

        # --- Country client matcher oneof (omit => server-default any_country, import-suppressed) ---
        dynamic "country_list" {
          for_each = rules.value.country == "list" ? [1] : []
          content {
            country_codes = rules.value.countries
            invert_match  = rules.value.country_invert
          }
        }

        # --- request matchers ---
        dynamic "http_method" {
          for_each = length(rules.value.http_methods) > 0 ? [1] : []
          content {
            methods        = rules.value.http_methods
            invert_matcher = rules.value.http_methods_invert
          }
        }
        dynamic "path" {
          for_each = (length(rules.value.path_exact) + length(rules.value.path_prefixes) + length(rules.value.path_regex) + length(rules.value.path_suffix)) > 0 ? [1] : []
          content {
            exact_values   = length(rules.value.path_exact) > 0 ? rules.value.path_exact : null
            prefix_values  = length(rules.value.path_prefixes) > 0 ? rules.value.path_prefixes : null
            regex_values   = length(rules.value.path_regex) > 0 ? rules.value.path_regex : null
            suffix_values  = length(rules.value.path_suffix) > 0 ? rules.value.path_suffix : null
            invert_matcher = rules.value.path_invert
          }
        }
        dynamic "domain_matcher" {
          for_each = (length(rules.value.domain_exact) + length(rules.value.domain_regex)) > 0 ? [1] : []
          content {
            exact_values = length(rules.value.domain_exact) > 0 ? rules.value.domain_exact : null
            regex_values = length(rules.value.domain_regex) > 0 ? rules.value.domain_regex : null
          }
        }
        dynamic "headers" {
          for_each = rules.value.headers
          content {
            name           = headers.value.name
            invert_matcher = headers.value.invert
            dynamic "check_present" {
              for_each = headers.value.presence == "present" ? [1] : []
              content {}
            }
            dynamic "check_not_present" {
              for_each = headers.value.presence == "absent" ? [1] : []
              content {}
            }
            dynamic "item" {
              for_each = headers.value.presence == "match" ? [1] : []
              content {
                exact_values = length(headers.value.exact_values) > 0 ? headers.value.exact_values : null
                regex_values = length(headers.value.regex_values) > 0 ? headers.value.regex_values : null
              }
            }
          }
        }
      }
    }
  }

  # A rule referencing a custom rate limiter requires that limiter to exist.
  lifecycle {
    precondition {
      condition = alltrue([
        for r in each.value.rules :
        r.action != "custom" || contains(keys(xcsh_rate_limiter.this), r.custom_rate_limiter)
      ])
      error_message = "rate_limiter_policy '${each.value.name}' has a rule with action=custom referencing a custom_rate_limiter not present in var.rate_limiters."
    }
  }
}
