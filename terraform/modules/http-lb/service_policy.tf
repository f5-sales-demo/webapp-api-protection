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
            # F5 XC requires an action-side block on every rule; waf_action { none {} }
            # is the minimal "no WAF action" form (the server-default base member, which
            # the provider suppresses on import). SPol-4 parameterizes waf/bot/mum actions.
            waf_action {
              none {}
            }

            # --- SPol-2 client matcher oneof (omit => server-default any_client, suppressed) ---
            dynamic "client_selector" {
              for_each = rules.value.client == "selector" ? [1] : []
              content {
                expressions = length(rules.value.client_selector) > 0 ? rules.value.client_selector : null
              }
            }
            client_name = rules.value.client == "name" ? rules.value.client_name : null
            dynamic "client_name_matcher" {
              for_each = rules.value.client == "name_matcher" ? [1] : []
              content {
                exact_values = length(rules.value.client_name_exact) > 0 ? rules.value.client_name_exact : null
                regex_values = length(rules.value.client_name_regex) > 0 ? rules.value.client_name_regex : null
              }
            }
            dynamic "ip_threat_category_list" {
              for_each = rules.value.client == "ip_threat" ? [1] : []
              content {
                ip_threat_categories = rules.value.ip_threat_categories
              }
            }

            # --- SPol-2 ASN matcher oneof (omit => server-default any_asn, suppressed) ---
            dynamic "asn_list" {
              for_each = rules.value.asn == "list" ? [1] : []
              content {
                as_numbers = rules.value.asn_numbers
              }
            }

            # --- SPol-2 IP matcher oneof (omit => server-default any_ip, suppressed) ---
            dynamic "ip_prefix_list" {
              for_each = rules.value.ip == "prefix_list" ? [1] : []
              content {
                ip_prefixes  = rules.value.ip_prefixes
                invert_match = rules.value.ip_invert
              }
            }

            # --- SPol-2 TLS-fingerprint matcher oneof (omit => no match constraint) ---
            dynamic "tls_fingerprint_matcher" {
              for_each = rules.value.tls == "matcher" ? [1] : []
              content {
                classes         = length(rules.value.tls_classes) > 0 ? rules.value.tls_classes : null
                exact_values    = length(rules.value.tls_exact) > 0 ? rules.value.tls_exact : null
                excluded_values = length(rules.value.tls_excluded) > 0 ? rules.value.tls_excluded : null
              }
            }
            dynamic "ja4_tls_fingerprint" {
              for_each = rules.value.tls == "ja4" ? [1] : []
              content {
                exact_values = rules.value.ja4_exact
              }
            }

            # --- SPol-3 request matchers (additive AND; omitted = no constraint) ---
            dynamic "http_method" {
              for_each = length(rules.value.http_methods) > 0 ? [1] : []
              content {
                methods        = rules.value.http_methods
                invert_matcher = rules.value.http_methods_invert
              }
            }
            dynamic "path" {
              for_each = (length(rules.value.path_exact) + length(rules.value.path_prefix) + length(rules.value.path_regex) + length(rules.value.path_suffix)) > 0 ? [1] : []
              content {
                exact_values   = length(rules.value.path_exact) > 0 ? rules.value.path_exact : null
                prefix_values  = length(rules.value.path_prefix) > 0 ? rules.value.path_prefix : null
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
            dynamic "query_params" {
              for_each = rules.value.query_params
              content {
                key            = query_params.value.key
                invert_matcher = query_params.value.invert
                dynamic "check_present" {
                  for_each = query_params.value.presence == "present" ? [1] : []
                  content {}
                }
                dynamic "check_not_present" {
                  for_each = query_params.value.presence == "absent" ? [1] : []
                  content {}
                }
                dynamic "item" {
                  for_each = query_params.value.presence == "match" ? [1] : []
                  content {
                    exact_values = length(query_params.value.exact_values) > 0 ? query_params.value.exact_values : null
                    regex_values = length(query_params.value.regex_values) > 0 ? query_params.value.regex_values : null
                  }
                }
              }
            }
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
