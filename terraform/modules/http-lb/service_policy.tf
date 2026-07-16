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
            # F5 XC requires waf_action on every rule (SPol-1). Arm: none (no WAF action) |
            # skip (waf_skip_processing) | detection_control (app_firewall_detection_control
            # exclusions, SPol-4b). skip/detection_control require action != DENY (enforced in
            # variables_service_policy.tf). context is always emitted (server keeps the enum,
            # default CONTEXT_ANY); context_name is emitted null-when-empty because the provider
            # reads the server's empty string back as null (an explicit "" would drift on import).
            waf_action {
              dynamic "none" {
                for_each = rules.value.waf_action_mode == "none" ? [1] : []
                content {}
              }
              dynamic "waf_skip_processing" {
                for_each = rules.value.waf_action_mode == "skip" ? [1] : []
                content {}
              }
              dynamic "app_firewall_detection_control" {
                for_each = rules.value.waf_action_mode == "detection_control" ? [1] : []
                content {
                  dynamic "exclude_attack_type_contexts" {
                    for_each = rules.value.waf_exclude_attack_type_contexts
                    content {
                      context             = exclude_attack_type_contexts.value.context
                      context_name        = exclude_attack_type_contexts.value.context_name != "" ? exclude_attack_type_contexts.value.context_name : null
                      exclude_attack_type = exclude_attack_type_contexts.value.exclude_attack_type
                    }
                  }
                  dynamic "exclude_violation_contexts" {
                    for_each = rules.value.waf_exclude_violation_contexts
                    content {
                      context           = exclude_violation_contexts.value.context
                      context_name      = exclude_violation_contexts.value.context_name != "" ? exclude_violation_contexts.value.context_name : null
                      exclude_violation = exclude_violation_contexts.value.exclude_violation
                    }
                  }
                  dynamic "exclude_signature_contexts" {
                    for_each = rules.value.waf_exclude_signature_contexts
                    content {
                      context      = exclude_signature_contexts.value.context
                      context_name = exclude_signature_contexts.value.context_name != "" ? exclude_signature_contexts.value.context_name : null
                      signature_id = exclude_signature_contexts.value.signature_id
                    }
                  }
                  dynamic "exclude_bot_name_contexts" {
                    for_each = rules.value.waf_exclude_bot_names
                    content {
                      bot_name = exclude_bot_name_contexts.value
                    }
                  }
                }
              }
            }
            # bot_action / mum_action: omitted by default (server returns null); a concrete
            # skip arm emits the block. SPol-4b adds any further arms.
            dynamic "bot_action" {
              for_each = rules.value.bot_action_mode == "skip" ? [1] : []
              content {
                bot_skip_processing {}
              }
            }
            dynamic "mum_action" {
              for_each = rules.value.mum_action_mode == "skip" ? [1] : []
              content {
                skip_processing {}
              }
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

            # --- SPol-4b segment_policy (source/destination markers; segments refs deferred).
            # Emitted only when a marker is selected; read-back is exact (no provider change). ---
            dynamic "segment_policy" {
              for_each = (rules.value.segment_src != "omit" || rules.value.segment_dst != "omit" || rules.value.segment_intra) ? [1] : []
              content {
                dynamic "src_any" {
                  for_each = rules.value.segment_src == "any" ? [1] : []
                  content {}
                }
                dynamic "dst_any" {
                  for_each = rules.value.segment_dst == "any" ? [1] : []
                  content {}
                }
                dynamic "intra_segment" {
                  for_each = rules.value.segment_intra ? [1] : []
                  content {}
                }
              }
            }

            # --- SPol-4b request_constraints. When enabled, every dimension is emitted as a
            # oneof: a set max_* value => max_*_exceeds, an unset one => max_*_none marker. The
            # server echoes the none marker for each unset dimension, so emitting all 13 keeps
            # the plan import-clean. ---
            dynamic "request_constraints" {
              for_each = rules.value.request_constraints_enabled ? [1] : []
              content {
                max_cookie_count_exceeds = rules.value.max_cookie_count
                dynamic "max_cookie_count_none" {
                  for_each = rules.value.max_cookie_count == null ? [1] : []
                  content {}
                }
                max_cookie_key_size_exceeds = rules.value.max_cookie_key_size
                dynamic "max_cookie_key_size_none" {
                  for_each = rules.value.max_cookie_key_size == null ? [1] : []
                  content {}
                }
                max_cookie_value_size_exceeds = rules.value.max_cookie_value_size
                dynamic "max_cookie_value_size_none" {
                  for_each = rules.value.max_cookie_value_size == null ? [1] : []
                  content {}
                }
                max_header_count_exceeds = rules.value.max_header_count
                dynamic "max_header_count_none" {
                  for_each = rules.value.max_header_count == null ? [1] : []
                  content {}
                }
                max_header_key_size_exceeds = rules.value.max_header_key_size
                dynamic "max_header_key_size_none" {
                  for_each = rules.value.max_header_key_size == null ? [1] : []
                  content {}
                }
                max_header_value_size_exceeds = rules.value.max_header_value_size
                dynamic "max_header_value_size_none" {
                  for_each = rules.value.max_header_value_size == null ? [1] : []
                  content {}
                }
                max_parameter_count_exceeds = rules.value.max_parameter_count
                dynamic "max_parameter_count_none" {
                  for_each = rules.value.max_parameter_count == null ? [1] : []
                  content {}
                }
                max_parameter_name_size_exceeds = rules.value.max_parameter_name_size
                dynamic "max_parameter_name_size_none" {
                  for_each = rules.value.max_parameter_name_size == null ? [1] : []
                  content {}
                }
                max_parameter_value_size_exceeds = rules.value.max_parameter_value_size
                dynamic "max_parameter_value_size_none" {
                  for_each = rules.value.max_parameter_value_size == null ? [1] : []
                  content {}
                }
                max_query_size_exceeds = rules.value.max_query_size
                dynamic "max_query_size_none" {
                  for_each = rules.value.max_query_size == null ? [1] : []
                  content {}
                }
                max_request_line_size_exceeds = rules.value.max_request_line_size
                dynamic "max_request_line_size_none" {
                  for_each = rules.value.max_request_line_size == null ? [1] : []
                  content {}
                }
                max_request_size_exceeds = rules.value.max_request_size
                dynamic "max_request_size_none" {
                  for_each = rules.value.max_request_size == null ? [1] : []
                  content {}
                }
                max_url_size_exceeds = rules.value.max_url_size
                dynamic "max_url_size_none" {
                  for_each = rules.value.max_url_size == null ? [1] : []
                  content {}
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
