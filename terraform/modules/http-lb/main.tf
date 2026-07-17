# HTTP load balancer + origin pool (with health check) pointing at the Azure
# origin server this plan deploys (modules/origin-server).
#
# Based on the acceptance-tested provider examples
# examples/resources/xcsh_http_loadbalancer/with-origin-pool.tf,
# examples/resources/xcsh_origin_pool/public-ip.tf and
# examples/resources/xcsh_origin_pool/with-healthcheck-ref.tf.
#
# The origin server's nginx serves HTTP 200 on port 80 (health endpoint /health),
# so the pool connects to the origin in plaintext (no_tls). For an HTTPS origin,
# replace `no_tls {}` with a `use_tls { sni = <host>  volterra_trusted_ca {} }`
# block and set origin_port 443.
#
# Extension seam (later iterations, provider already supports these):
#   - WAF:            add resource "xcsh_app_firewall" and an `app_firewall {}`
#                     reference block on the load balancer.
#   - API protection: add resource "xcsh_api_definition" and the load balancer's
#                     `api_definition` / `enable_api_discovery {}` blocks.

resource "xcsh_healthcheck" "origin" {
  name      = "origin-healthcheck"
  namespace = var.namespace
  labels    = var.labels

  healthy_threshold   = 3
  unhealthy_threshold = 1
  timeout             = 3
  interval            = 15

  http_health_check {
    # The origin server's nginx returns 200 on /health for any Host, so no
    # host_header override is needed (unlike the previous public_name origin).
    path                  = var.health_check_path
    expected_status_codes = ["200"]
  }
}

resource "xcsh_origin_pool" "origin" {
  name      = "origin-pool"
  namespace = var.namespace
  labels    = var.labels

  port = var.origin_port

  origin_servers {
    labels {}
    public_ip {
      ip = var.origin_ip
    }
  }

  healthcheck {
    name      = xcsh_healthcheck.origin.name
    namespace = xcsh_healthcheck.origin.namespace
  }

  no_tls {}
  same_as_endpoint_port {}
}

# Web application firewall attached to the load balancer below.
#
# Import-cleanliness rule (verified by round-trip import against the live tenant):
# only declare oneof-default markers that the provider does NOT suppress on import.
# The provider's import-default-suppressions.json strips these AppFirewall markers:
#   allow_all_response_codes, default_anonymization, default_bot_setting,
#   use_default_blocking_page, disable_ai_enhancements
# so declaring them (as the acceptance-tested blocking.tf example does) causes
# import drift (config has them, imported state does not). We therefore declare
# ONLY the non-suppressed blocks: default_detection_settings + the enforcement
# mode (blocking/monitoring). Enforcement mode is var-driven (exactly one emitted).
# NOTE (lock-step provider gap): examples/resources/xcsh_app_firewall/blocking.tf
# declares the suppressed markers and is thus NOT import-round-trip-clean.
resource "xcsh_app_firewall" "this" {
  name      = "webapp-api-protection-waf"
  namespace = var.namespace
  labels    = var.labels

  # enforcement_mode_choice
  dynamic "blocking" {
    for_each = var.waf_mode == "blocking" ? [1] : []
    content {}
  }
  dynamic "monitoring" {
    for_each = var.waf_mode == "monitoring" ? [1] : []
    content {}
  }

  # allowed_response_codes_choice (omit => server default allow_all, suppressed)
  dynamic "allowed_response_codes" {
    for_each = var.waf_allowed_response_codes_mode == "list" ? [1] : []
    content {
      response_code = var.waf_allowed_response_codes
    }
  }

  # blocking_page_choice (omit => server default use_default_blocking_page, suppressed)
  dynamic "blocking_page" {
    for_each = var.waf_blocking_page_mode == "custom" ? [1] : []
    content {
      blocking_page = var.waf_blocking_page
      response_code = var.waf_blocking_page_response_code
    }
  }

  # bot_protection_choice, top level (omit => server default default_bot_setting, suppressed)
  dynamic "bot_protection_setting" {
    for_each = var.waf_bot_mode == "custom" ? [1] : []
    content {
      good_bot_action       = var.waf_bot_actions.good
      malicious_bot_action  = var.waf_bot_actions.malicious
      suspicious_bot_action = var.waf_bot_actions.suspicious
    }
  }

  # anonymization_setting (omit => server default default_anonymization, suppressed)
  dynamic "disable_anonymization" {
    for_each = var.waf_anonymization_mode == "disable" ? [1] : []
    content {}
  }
  # NOTE: custom_anonymization is intentionally NOT rendered. The generated provider
  # cannot build a value for its anonymization_config list-nested-block (Value
  # Conversion Error: model []AppFirewall...AnonymizationConfigModel vs expected
  # ListValue) for BOTH static and dynamic blocks — a lock-step provider codegen bug.
  # waf_anonymization_mode therefore supports omit + disable until the provider is fixed.

  # enhance_with_ai_choice. "omit" emits nothing: disable_ai_enhancements is the
  # server default AND is import-suppressed, so emitting it explicitly drifts on
  # round-trip import (config has it, imported state does not). omit therefore IS
  # the disable state. Only the non-default enable arm is emitted.
  dynamic "enable_ai_enhancements" {
    for_each = var.waf_ai_mode == "enable" ? [1] : []
    content {
      dynamic "mitigate_high_risk_action" {
        for_each = var.waf_ai_risk_action == "high" ? [1] : []
        content {}
      }
      dynamic "mitigate_high_medium_risk_action" {
        for_each = var.waf_ai_risk_action == "high_medium" ? [1] : []
        content {}
      }
    }
  }

  # detection_setting_choice
  dynamic "default_detection_settings" {
    for_each = var.waf_detection_mode == "default" ? [1] : []
    content {}
  }
  dynamic "detection_settings" {
    for_each = var.waf_detection_mode == "custom" ? [1] : []
    content {
      # violation_detection_setting
      dynamic "default_violation_settings" {
        for_each = var.waf_violation_mode == "default" ? [1] : []
        content {}
      }
      dynamic "violation_settings" {
        for_each = var.waf_violation_mode == "custom" ? [1] : []
        content {
          disabled_violation_types = var.waf_disabled_violation_types
        }
      }

      # signatures_staging_settings (disable => omit, server default)
      dynamic "stage_new_signatures" {
        for_each = var.waf_staging_mode == "new" ? [1] : []
        content {
          staging_period = var.waf_staging_period
        }
      }
      dynamic "stage_new_and_updated_signatures" {
        for_each = var.waf_staging_mode == "new_and_updated" ? [1] : []
        content {
          staging_period = var.waf_staging_period
        }
      }

      # false_positive_suppression
      dynamic "enable_suppression" {
        for_each = var.waf_suppression == "enable" ? [1] : []
        content {}
      }
      dynamic "disable_suppression" {
        for_each = var.waf_suppression == "disable" ? [1] : []
        content {}
      }

      # threat_campaign_choice
      dynamic "enable_threat_campaigns" {
        for_each = var.waf_threat_campaigns == "enable" ? [1] : []
        content {}
      }
      dynamic "disable_threat_campaigns" {
        for_each = var.waf_threat_campaigns == "disable" ? [1] : []
        content {}
      }

      # bot_protection_choice, nested. "default" omits the block: nested
      # default_bot_setting is import-suppressed (materialized by the server), so
      # emitting it drifts on round-trip import. The custom arm (bot_protection_setting)
      # requires the tenant Bot Defense add-on; without it the API silently normalizes
      # custom actions back to default_bot_setting (verified live -> guaranteed import
      # drift), so custom bot is only import-clean on Bot-Defense-entitled tenants.
      dynamic "bot_protection_setting" {
        for_each = var.waf_detection_bot_mode == "custom" ? [1] : []
        content {
          good_bot_action       = var.waf_bot_actions.good
          malicious_bot_action  = var.waf_bot_actions.malicious
          suspicious_bot_action = var.waf_bot_actions.suspicious
        }
      }

      signature_selection_setting {
        # signature_selection_by_accuracy
        dynamic "only_high_accuracy_signatures" {
          for_each = var.waf_signature_accuracy == "only_high" ? [1] : []
          content {}
        }
        dynamic "high_medium_accuracy_signatures" {
          for_each = var.waf_signature_accuracy == "high_medium" ? [1] : []
          content {}
        }
        dynamic "high_medium_low_accuracy_signatures" {
          for_each = var.waf_signature_accuracy == "high_medium_low" ? [1] : []
          content {}
        }

        # attack_type_setting
        dynamic "default_attack_type_settings" {
          for_each = var.waf_attack_type_mode == "default" ? [1] : []
          content {}
        }
        dynamic "attack_type_settings" {
          for_each = var.waf_attack_type_mode == "custom" ? [1] : []
          content {
            disabled_attack_types = var.waf_disabled_attack_types
          }
        }
      }
    }
  }
}

# Malicious User Detection mitigation policy — the actions F5 XC takes once a user
# is scored into a threat level. Referenced by the load balancer's enable_challenge
# block below (there is no top-level malicious_user_mitigation field on the LB; the
# reference lives inside the challenge oneof). Escalating response by threat level:
# low → JavaScript challenge, medium → CAPTCHA, high → temporary block. Based on the
# acceptance-tested example xcsh_malicious_user_mitigation/with-mitigation-type.tf.
resource "xcsh_malicious_user_mitigation" "mud" {
  count     = var.mud_enabled ? 1 : 0
  name      = "webapp-api-protection-mud"
  namespace = var.namespace
  labels    = var.labels

  # One static rule per threat level (low/medium/high); the ACTION within each is chosen
  # by var.mud_mitigation. The rules list is kept static (3 entries) because a dynamic
  # rules list produces an unknown-typed value the generated provider model cannot handle
  # (mitigation_type.rules → []RulesModel, not a ListValue). Action is a oneof; emit the
  # selected member as an empty marker.
  mitigation_type {
    rules {
      threat_level {
        low {}
      }
      mitigation_action {
        dynamic "block_temporarily" {
          for_each = var.mud_mitigation.low == "block_temporarily" ? [1] : []
          content {}
        }
        dynamic "captcha_challenge" {
          for_each = var.mud_mitigation.low == "captcha_challenge" ? [1] : []
          content {}
        }
        dynamic "javascript_challenge" {
          for_each = var.mud_mitigation.low == "javascript_challenge" ? [1] : []
          content {}
        }
      }
    }
    rules {
      threat_level {
        medium {}
      }
      mitigation_action {
        dynamic "block_temporarily" {
          for_each = var.mud_mitigation.medium == "block_temporarily" ? [1] : []
          content {}
        }
        dynamic "captcha_challenge" {
          for_each = var.mud_mitigation.medium == "captcha_challenge" ? [1] : []
          content {}
        }
        dynamic "javascript_challenge" {
          for_each = var.mud_mitigation.medium == "javascript_challenge" ? [1] : []
          content {}
        }
      }
    }
    rules {
      threat_level {
        high {}
      }
      mitigation_action {
        dynamic "block_temporarily" {
          for_each = var.mud_mitigation.high == "block_temporarily" ? [1] : []
          content {}
        }
        dynamic "captcha_challenge" {
          for_each = var.mud_mitigation.high == "captcha_challenge" ? [1] : []
          content {}
        }
        dynamic "javascript_challenge" {
          for_each = var.mud_mitigation.high == "javascript_challenge" ? [1] : []
          content {}
        }
      }
    }
  }
}

# User-identification policy — only when mud_user_id = user_identification. Exactly one
# rule of the selected type: keyed rule-types set the matching string attribute; marker
# rule-types are emitted as an empty block. Referenced by the LB's user_identification
# block below. When mud_user_id = client_ip we create nothing and the LB uses the
# server-default user_id_client_ip (import-suppressed).
resource "xcsh_user_identification" "mud" {
  count     = var.mud_enabled && var.mud_user_id == "user_identification" ? 1 : 0
  name      = "webapp-api-protection-mud-userid"
  namespace = var.namespace
  labels    = var.labels

  rules {
    cookie_name             = var.mud_user_id_rule == "cookie_name" ? "x-mud-user" : null
    http_header_name        = var.mud_user_id_rule == "http_header_name" ? "X-MUD-User" : null
    ip_and_http_header_name = var.mud_user_id_rule == "ip_and_http_header_name" ? "X-MUD-User" : null
    jwt_claim_name          = var.mud_user_id_rule == "jwt_claim_name" ? "sub" : null
    query_param_key         = var.mud_user_id_rule == "query_param_key" ? "mud_user" : null

    dynamic "client_asn" {
      for_each = var.mud_user_id_rule == "client_asn" ? [1] : []
      content {}
    }
    dynamic "client_city" {
      for_each = var.mud_user_id_rule == "client_city" ? [1] : []
      content {}
    }
    dynamic "client_country" {
      for_each = var.mud_user_id_rule == "client_country" ? [1] : []
      content {}
    }
    dynamic "client_ip" {
      for_each = var.mud_user_id_rule == "client_ip" ? [1] : []
      content {}
    }
    dynamic "client_region" {
      for_each = var.mud_user_id_rule == "client_region" ? [1] : []
      content {}
    }
    dynamic "tls_fingerprint" {
      for_each = var.mud_user_id_rule == "tls_fingerprint" ? [1] : []
      content {}
    }
    dynamic "ip_and_tls_fingerprint" {
      for_each = var.mud_user_id_rule == "ip_and_tls_fingerprint" ? [1] : []
      content {}
    }
    dynamic "ja4_tls_fingerprint" {
      for_each = var.mud_user_id_rule == "ja4_tls_fingerprint" ? [1] : []
      content {}
    }
    dynamic "ip_and_ja4_tls_fingerprint" {
      for_each = var.mud_user_id_rule == "ip_and_ja4_tls_fingerprint" ? [1] : []
      content {}
    }
    dynamic "none" {
      for_each = var.mud_user_id_rule == "none" ? [1] : []
      content {}
    }
  }
}

# Standalone API discovery object holding custom auth types. Created only when
# api_discovery_auth_mode=custom, and referenced by the LB's enable_api_discovery
# custom_api_auth_discovery.api_discovery_ref. When default, we create nothing and
# emit no arm (server default default_api_auth_discovery is import-suppressed).
resource "xcsh_api_discovery" "this" {
  count     = var.api_discovery_auth_mode == "custom" ? 1 : 0
  name      = "${var.namespace}-api-discovery"
  namespace = var.namespace

  dynamic "custom_auth_types" {
    for_each = var.api_discovery_custom_auth_types
    content {
      parameter_name = custom_auth_types.value.parameter_name
      parameter_type = custom_auth_types.value.parameter_type
    }
  }
}

resource "xcsh_http_loadbalancer" "this" {
  name      = local.lb_name
  namespace = var.namespace
  labels    = var.labels

  # api_groups_rules reference app_api_groups by name, which F5 XC validates at LB
  # apply — so the groups must exist first. app_api_group references the LB by static
  # name (local.lb_name), not this resource, so there is no cycle.
  depends_on = [xcsh_app_api_group.this]

  domains = var.lb_domains

  http {
    port = 80
    # Let F5 XC auto-manage DNS records for `domains` (www/api.f5-sales-demo.com)
    # to this LB's VIP. Prerequisite: the domain is delegated to F5 XC (it is) and
    # the zone has allow_http_lb_managed_records enabled (see the dns repo).
    dns_volterra_managed = true
  }

  default_route_pools {
    pool {
      name      = xcsh_origin_pool.origin.name
      namespace = var.namespace
    }
    weight   = 1
    priority = 1
    # endpoint_subsets is a server-default empty marker the API always echoes; the
    # provider suppresses it on import (#1103) and only preserves it on read when it
    # was in prior state, so the module OMITS it — declaring it {} instead forces a
    # spurious "+ endpoint_subsets {}" on every import round-trip (and cascades into
    # computed tenant re-planning on the pool/WAF refs).
  }

  advertise_on_public_default_vip {}

  # Attach the WAF (oneof: app_firewall vs disable_waf; server default disable_waf).
  app_firewall {
    name      = xcsh_app_firewall.this.name
    namespace = xcsh_app_firewall.this.namespace
  }

  # Service policies (SPol effort) — service_policies_choice oneof:
  #   omit   => emit neither arm; server applies default service_policies_from_namespace
  #             (import-suppressed) — a 0-change no-op.
  #   none   => no_service_policies {} (also import-suppressed on the empty arm).
  #   active => active_service_policies referencing var.service_policy_active in order
  #             (evaluation is top-to-bottom). tenant is Computed — omit it.
  dynamic "no_service_policies" {
    for_each = var.service_policies_choice == "none" ? [1] : []
    content {}
  }
  dynamic "active_service_policies" {
    for_each = var.service_policies_choice == "active" ? [1] : []
    content {
      dynamic "policies" {
        for_each = var.service_policy_active
        content {
          name      = xcsh_service_policy.this[policies.value].name
          namespace = var.namespace
        }
      }
    }
  }

  # Enable API Discovery — learn the API schema from live traffic. This is the
  # discovery oneof (enable vs disable_api_discovery); independent of
  # api_specification / xcsh_api_definition (that path is enforcement, not
  # discovery), so no separate resource is required.
  #
  # A bare block is import-clean and first-apply-consistent: the provider now
  # suppresses F5 XC's server-materialized inner oneof defaults
  # (default_api_auth_discovery, disable_learn_from_redirect_traffic) on the
  # import path. That suppression was added in lock-step — see
  # terraform-provider-xcsh tools/import-default-suppressions.json (HTTPLoadBalancer).
  #
  # SP1 extends this from a bare toggle to full discovery/crawler coverage. When
  # no api_crawler_domains are set we emit NO api_crawler block, so the rendered
  # config is identical to the bare form (server default disable_api_crawler,
  # suppressed on import) — a 0-change no-op.
  # api_discovery_choice oneof: enable_api_discovery vs disable_api_discovery.
  # Default (enable, no inner arms) renders an empty enable_api_discovery {} —
  # identical to the prior bare form, so a normal apply is a 0-change no-op.
  dynamic "enable_api_discovery" {
    for_each = var.api_discovery_choice == "enable" ? [1] : []
    content {
      # Inline API crawler (api_crawler oneof: api_crawler_config vs disable_api_crawler).
      # The password uses the reusable clear/blindfold SecretType convention
      # (locals_api.tf): exactly one of blindfold_secret_info / clear_secret_info.
      dynamic "api_crawler" {
        for_each = length(var.api_crawler_domains) > 0 ? [1] : []
        content {
          api_crawler_config {
            dynamic "domains" {
              for_each = var.api_crawler_domains
              content {
                domain = domains.value.domain
                simple_login {
                  user = domains.value.user
                  password {
                    dynamic "blindfold_secret_info" {
                      for_each = local.api_crawler_password_secret.use_blindfold ? [1] : []
                      content {
                        location            = local.api_crawler_password_secret.location
                        store_provider      = local.api_crawler_password_secret.store_provider
                        decryption_provider = local.api_crawler_password_secret.decryption_provider
                      }
                    }
                    dynamic "clear_secret_info" {
                      for_each = local.api_crawler_password_secret.use_blindfold ? [] : [1]
                      content {
                        url          = local.api_crawler_password_secret.url
                        provider_ref = local.api_crawler_password_secret.provider_ref
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }

      # learn_from_redirect_traffic oneof. omit => emit NEITHER arm (server default
      # disable_learn_from_redirect_traffic is import-suppressed). enable => emit enable arm.
      dynamic "enable_learn_from_redirect_traffic" {
        for_each = var.api_discovery_learn_from_redirect == "enable" ? [1] : []
        content {}
      }

      # discovered_api_settings — omitted entirely unless a purge duration is set.
      dynamic "discovered_api_settings" {
        for_each = var.api_discovery_purge_duration != null ? [1] : []
        content {
          purge_duration_for_inactive_discovered_apis = var.api_discovery_purge_duration
        }
      }

      # api-auth-discovery oneof: omit (suppressed default_api_auth_discovery) or
      # custom_api_auth_discovery referencing the standalone xcsh_api_discovery.
      dynamic "custom_api_auth_discovery" {
        for_each = var.api_discovery_auth_mode == "custom" ? [1] : []
        content {
          api_discovery_ref {
            name      = xcsh_api_discovery.this[0].name
            namespace = var.namespace
          }
        }
      }

      # API discovery from source-code scan (SP2). Select the code_base_integration
      # created in scm.tf and the repositories to scan. Off by default (emit no
      # block). The code_base_integration object-ref keeps its Computed tenant
      # across apply via provider #1091 (>= 3.71.2), same class as api_discovery_ref.
      dynamic "api_discovery_from_code_scan" {
        for_each = var.api_discovery_code_scan != "off" ? [1] : []
        content {
          code_base_integrations {
            code_base_integration {
              name      = xcsh_code_base_integration.this[0].name
              namespace = var.namespace
            }

            # repo-selection oneof: all_repos vs selected_repos.
            dynamic "all_repos" {
              for_each = var.api_discovery_code_scan == "all" ? [1] : []
              content {}
            }
            dynamic "selected_repos" {
              for_each = var.api_discovery_code_scan == "selected" ? [1] : []
              content {
                api_code_repo = var.api_discovery_code_scan_repos
              }
            }
          }
        }
      }
    }
  }

  # disable_api_discovery — the other arm of api_discovery_choice.
  dynamic "disable_api_discovery" {
    for_each = var.api_discovery_choice == "disable" ? [1] : []
    content {}
  }

  # API schema enforcement (api_definition_choice oneof: api_specification vs the
  # server default disable_api_definition). Default omits the block entirely, so the
  # server applies disable_api_definition, which the provider suppresses on import
  # (0-change; do not declare it). "specification" references the xcsh_api_definition
  # created in api_definition.tf; the api_definition object-ref keeps its Computed
  # tenant across apply via provider #1091 (>= 3.71.2), the same class as the SP1
  # api_discovery_ref. validation_target_choice picks how strictly to validate:
  # validation_disabled (define but do not enforce), validation_all_spec_endpoints
  # (enforce every endpoint, fall-through allow), or validation_custom_list (SP3:
  # per-endpoint OpenAPI validation rules with a fall-through-allow default).
  dynamic "api_specification" {
    for_each = var.api_definition_choice == "specification" ? [1] : []
    content {
      api_definition {
        name      = xcsh_api_definition.this[0].name
        namespace = var.namespace
      }

      dynamic "validation_disabled" {
        for_each = var.api_specification_validation == "disabled" ? [1] : []
        content {}
      }

      dynamic "validation_all_spec_endpoints" {
        for_each = var.api_specification_validation == "all_spec_endpoints" ? [1] : []
        content {
          # ONE validation_mode applied to every spec endpoint (Batch A: this used to
          # hardcode skip_validation and enforce nothing). Request + response are
          # independent oneofs; response omitted entirely unless response_mode set.
          validation_mode {
            dynamic "skip_validation" {
              for_each = local.rendered_api_validation.req_skip ? [1] : []
              content {}
            }
            dynamic "validation_mode_active" {
              for_each = local.rendered_api_validation.req_active ? [1] : []
              content {
                request_validation_properties = local.rendered_api_validation.req_props
                dynamic "enforcement_block" {
                  for_each = local.rendered_api_validation.req_block ? [1] : []
                  content {}
                }
                dynamic "enforcement_report" {
                  for_each = local.rendered_api_validation.req_report ? [1] : []
                  content {}
                }
              }
            }
            dynamic "skip_response_validation" {
              for_each = local.rendered_api_validation.resp_emit && local.rendered_api_validation.resp_skip ? [1] : []
              content {}
            }
            dynamic "response_validation_mode_active" {
              for_each = local.rendered_api_validation.resp_emit && local.rendered_api_validation.resp_active ? [1] : []
              content {
                response_validation_properties = local.rendered_api_validation.resp_props
                dynamic "enforcement_block" {
                  for_each = local.rendered_api_validation.resp_block ? [1] : []
                  content {}
                }
                dynamic "enforcement_report" {
                  for_each = local.rendered_api_validation.resp_report ? [1] : []
                  content {}
                }
              }
            }
          }

          fall_through_mode {
            dynamic "fall_through_mode_allow" {
              for_each = local.rendered_api_validation.ft_custom ? [] : [1]
              content {}
            }
            # fall_through_mode_custom rules use action_block/report/skip (NOT the
            # per-rule validation_mode used by validation_custom_list). Reuse the
            # shared validation_custom_rules, mapping action -> action_*.
            dynamic "fall_through_mode_custom" {
              for_each = local.rendered_api_validation.ft_custom ? [1] : []
              content {
                dynamic "open_api_validation_rules" {
                  for_each = var.validation_custom_rules
                  content {
                    metadata {
                      name = "fallthrough-rule-${open_api_validation_rules.key}"
                    }
                    api_endpoint {
                      methods = open_api_validation_rules.value.methods
                      path    = open_api_validation_rules.value.path
                    }
                    dynamic "action_block" {
                      for_each = open_api_validation_rules.value.action == "block" ? [1] : []
                      content {}
                    }
                    dynamic "action_report" {
                      for_each = open_api_validation_rules.value.action == "report" ? [1] : []
                      content {}
                    }
                    dynamic "action_skip" {
                      for_each = open_api_validation_rules.value.action == "skip" ? [1] : []
                      content {}
                    }
                  }
                }
              }
            }
          }

          # OpenAPI settings (oversized body + additional query parameters). Emitted
          # only when a knob is set, so the default stays 0-change / import-clean.
          dynamic "settings" {
            for_each = local.rendered_api_validation.settings_emit ? [1] : []
            content {
              dynamic "oversized_body_fail_validation" {
                for_each = local.rendered_api_validation.oversized_fail ? [1] : []
                content {}
              }
              dynamic "oversized_body_skip_validation" {
                for_each = local.rendered_api_validation.oversized_skip ? [1] : []
                content {}
              }
              dynamic "property_validation_settings_custom" {
                for_each = local.rendered_api_validation.params_custom ? [1] : []
                content {
                  query_parameters {
                    dynamic "allow_additional_parameters" {
                      for_each = local.rendered_api_validation.params_allow ? [1] : []
                      content {}
                    }
                    dynamic "disallow_additional_parameters" {
                      for_each = local.rendered_api_validation.params_disallow ? [1] : []
                      content {}
                    }
                  }
                }
              }
            }
          }
        }
      }

      # validation_custom_list (SP3): per-endpoint rules + fall-through allow for
      # unlisted endpoints. Each rule matches an api_endpoint (method/path) and
      # applies action_block | action_report | action_skip.
      dynamic "validation_custom_list" {
        for_each = var.api_specification_validation == "custom_list" ? [1] : []
        content {
          fall_through_mode {
            fall_through_mode_allow {}
          }
          dynamic "open_api_validation_rules" {
            for_each = var.validation_custom_rules
            content {
              metadata {
                name = "validation-rule-${open_api_validation_rules.key}"
              }
              any_domain {}
              api_endpoint {
                methods = open_api_validation_rules.value.methods
                path    = open_api_validation_rules.value.path
              }
              # action via validation_mode: skip = skip_validation; block/report =
              # validation_mode_active with enforcement_block / enforcement_report.
              validation_mode {
                dynamic "skip_validation" {
                  for_each = open_api_validation_rules.value.action == "skip" ? [1] : []
                  content {}
                }
                dynamic "validation_mode_active" {
                  for_each = contains(["block", "report"], open_api_validation_rules.value.action) ? [1] : []
                  content {
                    # request_validation_properties has SizeAtLeast(1); shared with
                    # all_spec_endpoints via var.api_validation_request_properties
                    # (Batch A: was hardcoded).
                    request_validation_properties = var.api_validation_request_properties
                    dynamic "enforcement_block" {
                      for_each = open_api_validation_rules.value.action == "block" ? [1] : []
                      content {}
                    }
                    dynamic "enforcement_report" {
                      for_each = open_api_validation_rules.value.action == "report" ? [1] : []
                      content {}
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  # Rate limiting (SP3, rate_limit_choice oneof: rate_limit vs the server default
  # disable_rate_limit). Default omits the block — the server applies
  # disable_rate_limit, which the provider suppresses on import (0-change; do not
  # declare it). "rate_limit" emits the self-contained inline request rate limiter:
  # no IP allow-list (no_ip_allowed_list) and no policy refs (no_policies), so the
  # rate_limiter spec alone defines the limit. The per-endpoint api_rate_limit arm
  # and the standalone xcsh_rate_limiter_policy are deferred (see sp3-findings.md).
  dynamic "rate_limit" {
    for_each = var.rate_limit_choice == "rate_limit" ? [1] : []
    content {
      # IP-allow-list oneof: no_ip_allowed_list (default) | ip_allowed_list (inline
      # prefixes) | custom_ip_allowed_list (refs to ip_prefix_set objects).
      dynamic "no_ip_allowed_list" {
        for_each = (length(var.rate_limit_ip_allowed_prefixes) == 0 && length(var.rate_limit_custom_ip_prefix_sets) == 0) ? [1] : []
        content {}
      }
      dynamic "ip_allowed_list" {
        for_each = length(var.rate_limit_ip_allowed_prefixes) > 0 ? [1] : []
        content {
          prefixes = var.rate_limit_ip_allowed_prefixes
        }
      }
      dynamic "custom_ip_allowed_list" {
        for_each = length(var.rate_limit_custom_ip_prefix_sets) > 0 ? [1] : []
        content {
          dynamic "rate_limiter_allowed_prefixes" {
            for_each = var.rate_limit_custom_ip_prefix_sets
            content {
              name      = rate_limiter_allowed_prefixes.value.name
              namespace = coalesce(rate_limiter_allowed_prefixes.value.namespace, var.namespace)
            }
          }
        }
      }

      # policies oneof: no_policies (default) | policies (refs to xcsh_rate_limiter_policy).
      dynamic "no_policies" {
        for_each = length(var.rate_limit_policy_refs) == 0 ? [1] : []
        content {}
      }
      dynamic "policies" {
        for_each = length(var.rate_limit_policy_refs) > 0 ? [1] : []
        content {
          dynamic "policies" {
            for_each = var.rate_limit_policy_refs
            iterator = pol
            content {
              name      = xcsh_rate_limiter_policy.this[pol.value].name
              namespace = var.namespace
            }
          }
        }
      }

      rate_limiter {
        total_number      = var.rate_limit_total_number
        unit              = var.rate_limit_unit
        period_multiplier = var.rate_limit_period_multiplier
        burst_multiplier  = var.rate_limit_burst_multiplier
      }
    }
  }

  # Per-endpoint API rate limiting (Coverage Batch B, api_rate_limit arm). Selected
  # with rate_limit_choice="api_rate_limit". api_endpoint_rules + bypass rules +
  # server_url_rules, each with the shared client_matcher oneof (any_client default,
  # import-suppressed). See variables_api_rate_limit.tf.
  dynamic "api_rate_limit" {
    for_each = var.rate_limit_choice == "api_rate_limit" ? [1] : []
    content {
      dynamic "api_endpoint_rules" {
        for_each = var.api_rate_limit_endpoint_rules
        iterator = ep
        content {
          api_endpoint_path = ep.value.api_endpoint_path
          specific_domain   = ep.value.specific_domain
          dynamic "any_domain" {
            for_each = ep.value.specific_domain == null ? [1] : []
            content {}
          }
          dynamic "api_endpoint_method" {
            for_each = length(ep.value.methods) > 0 ? [1] : []
            content {
              methods        = ep.value.methods
              invert_matcher = ep.value.methods_invert
            }
          }
          dynamic "ref_rate_limiter" {
            for_each = ep.value.ref_rate_limiter != null ? [1] : []
            content {
              name      = xcsh_rate_limiter.this[ep.value.ref_rate_limiter].name
              namespace = var.namespace
            }
          }
          dynamic "inline_rate_limiter" {
            for_each = ep.value.inline_threshold != null ? [1] : []
            content {
              threshold = ep.value.inline_threshold
              unit      = ep.value.inline_unit
              dynamic "use_http_lb_user_id" {
                for_each = ep.value.inline_user_id == "http_lb" ? [1] : []
                content {}
              }
              dynamic "ref_user_id" {
                for_each = ep.value.inline_user_id == "ref" ? [1] : []
                content {
                  name      = ep.value.inline_user_ref
                  namespace = var.namespace
                }
              }
            }
          }
          dynamic "client_matcher" {
            for_each = ep.value.client_matcher != null && ep.value.client_matcher.mode != null ? [ep.value.client_matcher] : []
            iterator = cm
            content {
              dynamic "any_ip" {
                for_each = cm.value.mode == "any_ip" ? [1] : []
                content {}
              }
              dynamic "asn_list" {
                for_each = cm.value.mode == "asn_list" ? [1] : []
                content { as_numbers = cm.value.as_numbers }
              }
              dynamic "asn_matcher" {
                for_each = cm.value.mode == "asn_matcher" ? [1] : []
                content {
                  dynamic "asn_sets" {
                    for_each = cm.value.asn_sets
                    content {
                      name      = asn_sets.value.name
                      namespace = coalesce(asn_sets.value.namespace, var.namespace)
                    }
                  }
                }
              }
              dynamic "client_selector" {
                for_each = cm.value.mode == "client_selector" ? [1] : []
                content { expressions = cm.value.selector_expressions }
              }
              dynamic "ip_matcher" {
                for_each = cm.value.mode == "ip_matcher" ? [1] : []
                content {
                  invert_matcher = cm.value.ip_invert
                  dynamic "prefix_sets" {
                    for_each = cm.value.ip_prefix_sets
                    content {
                      name      = prefix_sets.value.name
                      namespace = coalesce(prefix_sets.value.namespace, var.namespace)
                    }
                  }
                }
              }
              dynamic "ip_prefix_list" {
                for_each = cm.value.mode == "ip_prefix_list" ? [1] : []
                content {
                  ip_prefixes  = cm.value.ip_prefixes
                  invert_match = cm.value.ip_invert
                }
              }
              dynamic "ip_threat_category_list" {
                for_each = cm.value.mode == "ip_threat_category_list" ? [1] : []
                content { ip_threat_categories = cm.value.ip_threat_categories }
              }
              dynamic "tls_fingerprint_matcher" {
                for_each = cm.value.mode == "tls_fingerprint_matcher" ? [1] : []
                content {
                  classes         = length(cm.value.tls_classes) > 0 ? cm.value.tls_classes : null
                  exact_values    = length(cm.value.tls_exact_values) > 0 ? cm.value.tls_exact_values : null
                  excluded_values = length(cm.value.tls_excluded_values) > 0 ? cm.value.tls_excluded_values : null
                }
              }
            }
          }
          dynamic "request_matcher" {
            for_each = ep.value.request_matcher != null ? [ep.value.request_matcher] : []
            iterator = rm
            content {
              dynamic "cookie_matchers" {
                for_each = rm.value.cookies
                iterator = m
                content {
                  name           = m.value.name
                  invert_matcher = m.value.invert
                  dynamic "check_present" {
                    for_each = m.value.presence == "present" ? [1] : []
                    content {}
                  }
                  dynamic "check_not_present" {
                    for_each = m.value.presence == "absent" ? [1] : []
                    content {}
                  }
                  dynamic "item" {
                    for_each = m.value.presence == "match" ? [1] : []
                    content {
                      exact_values = length(m.value.exact_values) > 0 ? m.value.exact_values : null
                      regex_values = length(m.value.regex_values) > 0 ? m.value.regex_values : null
                    }
                  }
                }
              }
              dynamic "headers" {
                for_each = rm.value.headers
                iterator = m
                content {
                  name           = m.value.name
                  invert_matcher = m.value.invert
                  dynamic "check_present" {
                    for_each = m.value.presence == "present" ? [1] : []
                    content {}
                  }
                  dynamic "check_not_present" {
                    for_each = m.value.presence == "absent" ? [1] : []
                    content {}
                  }
                  dynamic "item" {
                    for_each = m.value.presence == "match" ? [1] : []
                    content {
                      exact_values = length(m.value.exact_values) > 0 ? m.value.exact_values : null
                      regex_values = length(m.value.regex_values) > 0 ? m.value.regex_values : null
                    }
                  }
                }
              }
              dynamic "jwt_claims" {
                for_each = rm.value.jwt_claims
                iterator = m
                content {
                  name           = m.value.name
                  invert_matcher = m.value.invert
                  dynamic "check_present" {
                    for_each = m.value.presence == "present" ? [1] : []
                    content {}
                  }
                  dynamic "check_not_present" {
                    for_each = m.value.presence == "absent" ? [1] : []
                    content {}
                  }
                  dynamic "item" {
                    for_each = m.value.presence == "match" ? [1] : []
                    content {
                      exact_values = length(m.value.exact_values) > 0 ? m.value.exact_values : null
                      regex_values = length(m.value.regex_values) > 0 ? m.value.regex_values : null
                    }
                  }
                }
              }
              dynamic "query_params" {
                for_each = rm.value.query_params
                iterator = m
                content {
                  key            = m.value.name
                  invert_matcher = m.value.invert
                  dynamic "check_present" {
                    for_each = m.value.presence == "present" ? [1] : []
                    content {}
                  }
                  dynamic "check_not_present" {
                    for_each = m.value.presence == "absent" ? [1] : []
                    content {}
                  }
                  dynamic "item" {
                    for_each = m.value.presence == "match" ? [1] : []
                    content {
                      exact_values = length(m.value.exact_values) > 0 ? m.value.exact_values : null
                      regex_values = length(m.value.regex_values) > 0 ? m.value.regex_values : null
                    }
                  }
                }
              }
            }
          }
        }
      }

      dynamic "bypass_rate_limiting_rules" {
        for_each = length(var.api_rate_limit_bypass_rules) > 0 ? [1] : []
        content {
          dynamic "bypass_rate_limiting_rules" {
            for_each = var.api_rate_limit_bypass_rules
            iterator = bp
            content {
              base_path       = bp.value.target == "base_path" ? bp.value.base_path : null
              specific_domain = bp.value.specific_domain
              dynamic "any_domain" {
                for_each = bp.value.specific_domain == null ? [1] : []
                content {}
              }
              dynamic "any_url" {
                for_each = bp.value.target == "any_url" ? [1] : []
                content {}
              }
              dynamic "api_endpoint" {
                for_each = bp.value.target == "api_endpoint" ? [1] : []
                content {
                  path    = bp.value.endpoint_path
                  methods = length(bp.value.endpoint_methods) > 0 ? bp.value.endpoint_methods : null
                }
              }
              dynamic "api_groups" {
                for_each = bp.value.target == "api_groups" ? [1] : []
                content { api_groups = bp.value.api_groups }
              }
              dynamic "client_matcher" {
                for_each = bp.value.client_matcher != null && bp.value.client_matcher.mode != null ? [bp.value.client_matcher] : []
                iterator = cm
                content {
                  dynamic "any_ip" {
                    for_each = cm.value.mode == "any_ip" ? [1] : []
                    content {}
                  }
                  dynamic "asn_list" {
                    for_each = cm.value.mode == "asn_list" ? [1] : []
                    content { as_numbers = cm.value.as_numbers }
                  }
                  dynamic "asn_matcher" {
                    for_each = cm.value.mode == "asn_matcher" ? [1] : []
                    content {
                      dynamic "asn_sets" {
                        for_each = cm.value.asn_sets
                        content {
                          name      = asn_sets.value.name
                          namespace = coalesce(asn_sets.value.namespace, var.namespace)
                        }
                      }
                    }
                  }
                  dynamic "client_selector" {
                    for_each = cm.value.mode == "client_selector" ? [1] : []
                    content { expressions = cm.value.selector_expressions }
                  }
                  dynamic "ip_matcher" {
                    for_each = cm.value.mode == "ip_matcher" ? [1] : []
                    content {
                      invert_matcher = cm.value.ip_invert
                      dynamic "prefix_sets" {
                        for_each = cm.value.ip_prefix_sets
                        content {
                          name      = prefix_sets.value.name
                          namespace = coalesce(prefix_sets.value.namespace, var.namespace)
                        }
                      }
                    }
                  }
                  dynamic "ip_prefix_list" {
                    for_each = cm.value.mode == "ip_prefix_list" ? [1] : []
                    content {
                      ip_prefixes  = cm.value.ip_prefixes
                      invert_match = cm.value.ip_invert
                    }
                  }
                  dynamic "ip_threat_category_list" {
                    for_each = cm.value.mode == "ip_threat_category_list" ? [1] : []
                    content { ip_threat_categories = cm.value.ip_threat_categories }
                  }
                  dynamic "tls_fingerprint_matcher" {
                    for_each = cm.value.mode == "tls_fingerprint_matcher" ? [1] : []
                    content {
                      classes         = length(cm.value.tls_classes) > 0 ? cm.value.tls_classes : null
                      exact_values    = length(cm.value.tls_exact_values) > 0 ? cm.value.tls_exact_values : null
                      excluded_values = length(cm.value.tls_excluded_values) > 0 ? cm.value.tls_excluded_values : null
                    }
                  }
                }
              }
            }
          }
        }
      }

      dynamic "server_url_rules" {
        for_each = var.api_rate_limit_server_url_rules
        iterator = su
        content {
          api_group       = su.value.api_group
          base_path       = su.value.base_path
          specific_domain = su.value.specific_domain
          dynamic "any_domain" {
            for_each = su.value.specific_domain == null ? [1] : []
            content {}
          }
          dynamic "ref_rate_limiter" {
            for_each = su.value.ref_rate_limiter != null ? [1] : []
            content {
              name      = xcsh_rate_limiter.this[su.value.ref_rate_limiter].name
              namespace = var.namespace
            }
          }
          dynamic "inline_rate_limiter" {
            for_each = su.value.inline_threshold != null ? [1] : []
            content {
              threshold = su.value.inline_threshold
              unit      = su.value.inline_unit
              dynamic "use_http_lb_user_id" {
                for_each = su.value.inline_user_id == "http_lb" ? [1] : []
                content {}
              }
              dynamic "ref_user_id" {
                for_each = su.value.inline_user_id == "ref" ? [1] : []
                content {
                  name      = su.value.inline_user_ref
                  namespace = var.namespace
                }
              }
            }
          }
          dynamic "client_matcher" {
            for_each = su.value.client_matcher != null && su.value.client_matcher.mode != null ? [su.value.client_matcher] : []
            iterator = cm
            content {
              dynamic "any_ip" {
                for_each = cm.value.mode == "any_ip" ? [1] : []
                content {}
              }
              dynamic "asn_list" {
                for_each = cm.value.mode == "asn_list" ? [1] : []
                content { as_numbers = cm.value.as_numbers }
              }
              dynamic "asn_matcher" {
                for_each = cm.value.mode == "asn_matcher" ? [1] : []
                content {
                  dynamic "asn_sets" {
                    for_each = cm.value.asn_sets
                    content {
                      name      = asn_sets.value.name
                      namespace = coalesce(asn_sets.value.namespace, var.namespace)
                    }
                  }
                }
              }
              dynamic "client_selector" {
                for_each = cm.value.mode == "client_selector" ? [1] : []
                content { expressions = cm.value.selector_expressions }
              }
              dynamic "ip_matcher" {
                for_each = cm.value.mode == "ip_matcher" ? [1] : []
                content {
                  invert_matcher = cm.value.ip_invert
                  dynamic "prefix_sets" {
                    for_each = cm.value.ip_prefix_sets
                    content {
                      name      = prefix_sets.value.name
                      namespace = coalesce(prefix_sets.value.namespace, var.namespace)
                    }
                  }
                }
              }
              dynamic "ip_prefix_list" {
                for_each = cm.value.mode == "ip_prefix_list" ? [1] : []
                content {
                  ip_prefixes  = cm.value.ip_prefixes
                  invert_match = cm.value.ip_invert
                }
              }
              dynamic "ip_threat_category_list" {
                for_each = cm.value.mode == "ip_threat_category_list" ? [1] : []
                content { ip_threat_categories = cm.value.ip_threat_categories }
              }
              dynamic "tls_fingerprint_matcher" {
                for_each = cm.value.mode == "tls_fingerprint_matcher" ? [1] : []
                content {
                  classes         = length(cm.value.tls_classes) > 0 ? cm.value.tls_classes : null
                  exact_values    = length(cm.value.tls_exact_values) > 0 ? cm.value.tls_exact_values : null
                  excluded_values = length(cm.value.tls_excluded_values) > 0 ? cm.value.tls_excluded_values : null
                }
              }
            }
          }
        }
      }
    }
  }

  # Sensitive-data protection (SP3, sensitive_data_policy_choice oneof: custom
  # sensitive_data_policy vs the server default default_sensitive_data_policy).
  # Default omits the block (default_sensitive_data_policy is import-suppressed;
  # 0-change). "custom" references the standalone xcsh_sensitive_data_policy; the
  # object-ref keeps its Computed tenant across apply via provider #1091.
  dynamic "sensitive_data_policy" {
    for_each = var.sensitive_data_policy_choice == "custom" ? [1] : []
    content {
      sensitive_data_policy_ref {
        name      = xcsh_sensitive_data_policy.this[0].name
        namespace = var.namespace
      }
    }
  }

  # Sensitive-data disclosure (Batch C): for a given api_endpoint (path + methods)
  # and response body fields, mask or report disclosed sensitive data. Omitted when
  # the list is empty (0-change).
  dynamic "sensitive_data_disclosure_rules" {
    for_each = length(var.sensitive_data_disclosure_rules) > 0 ? [1] : []
    content {
      dynamic "sensitive_data_types_in_response" {
        for_each = var.sensitive_data_disclosure_rules
        iterator = d
        content {
          api_endpoint {
            methods = length(d.value.methods) > 0 ? d.value.methods : null
            path    = d.value.path
          }
          # body.fields requires >= 1 item; omit the whole body block when no fields
          # are named (rule then applies to the whole response body).
          dynamic "body" {
            for_each = length(d.value.fields) > 0 ? [1] : []
            content {
              fields = d.value.fields
            }
          }
          dynamic "mask" {
            for_each = d.value.action == "mask" ? [1] : []
            content {}
          }
          dynamic "report" {
            for_each = d.value.action == "report" ? [1] : []
            content {}
          }
        }
      }
    }
  }

  # Data Guard — mask sensitive values (credit-card/SSN/...) in responses per
  # domain + path. Omitted when the list is empty (0-change). domain matcher is a
  # oneof (any_domain | exact_value | suffix_value); action is apply_data_guard vs
  # skip_data_guard. The deeper sensitive_data_disclosure_rules (per-endpoint body
  # field masking) are deferred this cycle — see sp3-findings.md.
  dynamic "data_guard_rules" {
    for_each = var.data_guard_rules
    content {
      metadata {
        name = "data-guard-${data_guard_rules.key}"
      }
      dynamic "any_domain" {
        for_each = data_guard_rules.value.domain_mode == "any" ? [1] : []
        content {}
      }
      exact_value  = data_guard_rules.value.domain_mode == "exact" ? data_guard_rules.value.domain : null
      suffix_value = data_guard_rules.value.domain_mode == "suffix" ? data_guard_rules.value.domain : null
      path {
        path = data_guard_rules.value.path
      }
      dynamic "apply_data_guard" {
        for_each = data_guard_rules.value.apply ? [1] : []
        content {}
      }
      dynamic "skip_data_guard" {
        for_each = data_guard_rules.value.apply ? [] : [1]
        content {}
      }
    }
  }

  # Client access control (CAC) — trusted_clients bypass the SKIP_PROCESSING_* security named
  # in actions; blocked_clients are blocked (or have those actions applied). Each rule matches
  # by exactly one of ip_prefix / ipv6_prefix / as_number / user_identifier. Omitted when the
  # list is empty (0-change). actions null-when-empty (server default SKIP_PROCESSING_WAF).
  dynamic "trusted_clients" {
    for_each = var.trusted_clients
    content {
      metadata {
        name = coalesce(trusted_clients.value.name, "cac-trusted-${trusted_clients.key}")
      }
      ip_prefix            = trusted_clients.value.ip_prefix
      ipv6_prefix          = trusted_clients.value.ipv6_prefix
      as_number            = trusted_clients.value.as_number
      user_identifier      = trusted_clients.value.user_identifier
      expiration_timestamp = trusted_clients.value.expiration_timestamp
      actions              = length(trusted_clients.value.actions) > 0 ? trusted_clients.value.actions : null
    }
  }
  dynamic "blocked_clients" {
    for_each = var.blocked_clients
    content {
      metadata {
        name = coalesce(blocked_clients.value.name, "cac-blocked-${blocked_clients.key}")
      }
      ip_prefix            = blocked_clients.value.ip_prefix
      ipv6_prefix          = blocked_clients.value.ipv6_prefix
      as_number            = blocked_clients.value.as_number
      user_identifier      = blocked_clients.value.user_identifier
      expiration_timestamp = blocked_clients.value.expiration_timestamp
      actions              = length(blocked_clients.value.actions) > 0 ? blocked_clients.value.actions : null
    }
  }
  # IP reputation — block clients whose source IP matches the given IpThreatCategory list
  # (empty list = the server default set). Omitted entirely when disabled (0-change).
  dynamic "enable_ip_reputation" {
    for_each = var.ip_reputation_enabled ? [1] : []
    content {
      ip_threat_categories = length(var.ip_reputation_categories) > 0 ? var.ip_reputation_categories : null
    }
  }

  # App-layer response/cookie protection (LPC-1). cors_policy: access-control-* headers.
  # csrf_policy: oneof all_load_balancer_domains | custom_domain_list | disabled.
  # protected_cookies[]: per-cookie httponly/secure/samesite/tampering handling. Each omitted
  # when unset (0-change). Empty lists emitted null-when-empty.
  dynamic "cors_policy" {
    for_each = var.cors_policy != null ? [1] : []
    content {
      allow_origin       = length(var.cors_policy.allow_origin) > 0 ? var.cors_policy.allow_origin : null
      allow_origin_regex = length(var.cors_policy.allow_origin_regex) > 0 ? var.cors_policy.allow_origin_regex : null
      allow_methods      = var.cors_policy.allow_methods
      allow_headers      = var.cors_policy.allow_headers
      expose_headers     = var.cors_policy.expose_headers
      maximum_age        = var.cors_policy.maximum_age
      allow_credentials  = var.cors_policy.allow_credentials
      disabled           = var.cors_policy.disabled
    }
  }
  dynamic "csrf_policy" {
    for_each = var.csrf_policy_mode != "omit" ? [1] : []
    content {
      dynamic "all_load_balancer_domains" {
        for_each = var.csrf_policy_mode == "all_domains" ? [1] : []
        content {}
      }
      dynamic "custom_domain_list" {
        for_each = var.csrf_policy_mode == "custom" ? [1] : []
        content {
          domains = length(var.csrf_custom_domains) > 0 ? var.csrf_custom_domains : null
        }
      }
      dynamic "disabled" {
        for_each = var.csrf_policy_mode == "disabled" ? [1] : []
        content {}
      }
    }
  }
  dynamic "protected_cookies" {
    for_each = var.protected_cookies
    content {
      name          = protected_cookies.value.name
      max_age_value = protected_cookies.value.max_age_value
      dynamic "add_httponly" {
        for_each = protected_cookies.value.httponly == "add" ? [1] : []
        content {}
      }
      dynamic "ignore_httponly" {
        for_each = protected_cookies.value.httponly == "ignore" ? [1] : []
        content {}
      }
      dynamic "add_secure" {
        for_each = protected_cookies.value.secure == "add" ? [1] : []
        content {}
      }
      dynamic "ignore_secure" {
        for_each = protected_cookies.value.secure == "ignore" ? [1] : []
        content {}
      }
      dynamic "samesite_lax" {
        for_each = protected_cookies.value.samesite == "lax" ? [1] : []
        content {}
      }
      dynamic "samesite_none" {
        for_each = protected_cookies.value.samesite == "none" ? [1] : []
        content {}
      }
      dynamic "samesite_strict" {
        for_each = protected_cookies.value.samesite == "strict" ? [1] : []
        content {}
      }
      dynamic "ignore_samesite" {
        for_each = protected_cookies.value.samesite == "ignore" ? [1] : []
        content {}
      }
      dynamic "enable_tampering_protection" {
        for_each = protected_cookies.value.tampering == "enable" ? [1] : []
        content {}
      }
      dynamic "disable_tampering_protection" {
        for_each = protected_cookies.value.tampering == "disable" ? [1] : []
        content {}
      }
      dynamic "ignore_max_age" {
        for_each = protected_cookies.value.ignore_max_age ? [1] : []
        content {}
      }
    }
  }

  # Header/cookie manipulation (LPC-2) via more_option. Emitted only when a header/cookie
  # list is set (0-change otherwise); *_to_remove lists null-when-empty.
  dynamic "more_option" {
    for_each = (length(var.request_headers_to_add) + length(var.request_headers_to_remove) + length(var.response_headers_to_add) + length(var.response_headers_to_remove) + length(var.request_cookies_to_remove) + length(var.response_cookies_to_remove)) > 0 || var.disable_default_error_pages ? [1] : []
    content {
      dynamic "request_headers_to_add" {
        for_each = var.request_headers_to_add
        content {
          name   = request_headers_to_add.value.name
          value  = request_headers_to_add.value.value
          append = request_headers_to_add.value.append
        }
      }
      request_headers_to_remove = length(var.request_headers_to_remove) > 0 ? var.request_headers_to_remove : null
      dynamic "response_headers_to_add" {
        for_each = var.response_headers_to_add
        content {
          name   = response_headers_to_add.value.name
          value  = response_headers_to_add.value.value
          append = response_headers_to_add.value.append
        }
      }
      response_headers_to_remove  = length(var.response_headers_to_remove) > 0 ? var.response_headers_to_remove : null
      request_cookies_to_remove   = length(var.request_cookies_to_remove) > 0 ? var.request_cookies_to_remove : null
      response_cookies_to_remove  = length(var.response_cookies_to_remove) > 0 ? var.response_cookies_to_remove : null
      disable_default_error_pages = var.disable_default_error_pages
    }
  }

  # API protection rules (Coverage Batch D) — allow/deny access to API endpoints
  # (api_endpoint_rules) or API groups / base paths (api_groups_rules), each scoped by
  # a PER-RULE client_matcher (full oneof) + request_matcher. Omitted when both lists
  # are empty (0-change). Omit a client_matcher for "match any" (server default
  # any_client, import-suppressed). invert_matcher is now per-rule (methods_invert).
  dynamic "api_protection_rules" {
    for_each = (length(var.api_protection_rules) + length(var.api_protection_group_rules)) > 0 ? [1] : []
    content {
      dynamic "api_endpoint_rules" {
        for_each = var.api_protection_rules
        iterator = ep
        content {
          metadata {
            name = "api-protection-${ep.key}"
          }
          api_endpoint_path = ep.value.path
          dynamic "any_domain" {
            for_each = ep.value.domain_mode == "any" ? [1] : []
            content {}
          }
          specific_domain = ep.value.domain_mode == "specific" ? ep.value.domain : null
          api_endpoint_method {
            invert_matcher = ep.value.methods_invert
            methods        = ep.value.methods
          }
          action {
            dynamic "allow" {
              for_each = ep.value.action == "allow" ? [1] : []
              content {}
            }
            dynamic "deny" {
              for_each = ep.value.action == "deny" ? [1] : []
              content {}
            }
          }
          dynamic "client_matcher" {
            for_each = ep.value.client_matcher != null && ep.value.client_matcher.mode != null ? [ep.value.client_matcher] : []
            iterator = cm
            content {
              dynamic "any_ip" {
                for_each = cm.value.mode == "any_ip" ? [1] : []
                content {}
              }
              dynamic "asn_list" {
                for_each = cm.value.mode == "asn_list" ? [1] : []
                content { as_numbers = cm.value.as_numbers }
              }
              dynamic "asn_matcher" {
                for_each = cm.value.mode == "asn_matcher" ? [1] : []
                content {
                  dynamic "asn_sets" {
                    for_each = cm.value.asn_sets
                    content {
                      name      = asn_sets.value.name
                      namespace = coalesce(asn_sets.value.namespace, var.namespace)
                    }
                  }
                }
              }
              dynamic "client_selector" {
                for_each = cm.value.mode == "client_selector" ? [1] : []
                content { expressions = cm.value.selector_expressions }
              }
              dynamic "ip_matcher" {
                for_each = cm.value.mode == "ip_matcher" ? [1] : []
                content {
                  invert_matcher = cm.value.ip_invert
                  dynamic "prefix_sets" {
                    for_each = cm.value.ip_prefix_sets
                    content {
                      name      = prefix_sets.value.name
                      namespace = coalesce(prefix_sets.value.namespace, var.namespace)
                    }
                  }
                }
              }
              dynamic "ip_prefix_list" {
                for_each = cm.value.mode == "ip_prefix_list" ? [1] : []
                content {
                  ip_prefixes  = cm.value.ip_prefixes
                  invert_match = cm.value.ip_invert
                }
              }
              dynamic "ip_threat_category_list" {
                for_each = cm.value.mode == "ip_threat_category_list" ? [1] : []
                content { ip_threat_categories = cm.value.ip_threat_categories }
              }
              dynamic "tls_fingerprint_matcher" {
                for_each = cm.value.mode == "tls_fingerprint_matcher" ? [1] : []
                content {
                  classes         = length(cm.value.tls_classes) > 0 ? cm.value.tls_classes : null
                  exact_values    = length(cm.value.tls_exact_values) > 0 ? cm.value.tls_exact_values : null
                  excluded_values = length(cm.value.tls_excluded_values) > 0 ? cm.value.tls_excluded_values : null
                }
              }
            }
          }
          dynamic "request_matcher" {
            for_each = ep.value.request_matcher != null ? [ep.value.request_matcher] : []
            iterator = rm
            content {
              dynamic "cookie_matchers" {
                for_each = rm.value.cookies
                iterator = m
                content {
                  name           = m.value.name
                  invert_matcher = m.value.invert
                  dynamic "check_present" {
                    for_each = m.value.presence == "present" ? [1] : []
                    content {}
                  }
                  dynamic "check_not_present" {
                    for_each = m.value.presence == "absent" ? [1] : []
                    content {}
                  }
                  dynamic "item" {
                    for_each = m.value.presence == "match" ? [1] : []
                    content {
                      exact_values = length(m.value.exact_values) > 0 ? m.value.exact_values : null
                      regex_values = length(m.value.regex_values) > 0 ? m.value.regex_values : null
                    }
                  }
                }
              }
              dynamic "headers" {
                for_each = rm.value.headers
                iterator = m
                content {
                  name           = m.value.name
                  invert_matcher = m.value.invert
                  dynamic "check_present" {
                    for_each = m.value.presence == "present" ? [1] : []
                    content {}
                  }
                  dynamic "check_not_present" {
                    for_each = m.value.presence == "absent" ? [1] : []
                    content {}
                  }
                  dynamic "item" {
                    for_each = m.value.presence == "match" ? [1] : []
                    content {
                      exact_values = length(m.value.exact_values) > 0 ? m.value.exact_values : null
                      regex_values = length(m.value.regex_values) > 0 ? m.value.regex_values : null
                    }
                  }
                }
              }
              dynamic "jwt_claims" {
                for_each = rm.value.jwt_claims
                iterator = m
                content {
                  name           = m.value.name
                  invert_matcher = m.value.invert
                  dynamic "check_present" {
                    for_each = m.value.presence == "present" ? [1] : []
                    content {}
                  }
                  dynamic "check_not_present" {
                    for_each = m.value.presence == "absent" ? [1] : []
                    content {}
                  }
                  dynamic "item" {
                    for_each = m.value.presence == "match" ? [1] : []
                    content {
                      exact_values = length(m.value.exact_values) > 0 ? m.value.exact_values : null
                      regex_values = length(m.value.regex_values) > 0 ? m.value.regex_values : null
                    }
                  }
                }
              }
              dynamic "query_params" {
                for_each = rm.value.query_params
                iterator = m
                content {
                  key            = m.value.name
                  invert_matcher = m.value.invert
                  dynamic "check_present" {
                    for_each = m.value.presence == "present" ? [1] : []
                    content {}
                  }
                  dynamic "check_not_present" {
                    for_each = m.value.presence == "absent" ? [1] : []
                    content {}
                  }
                  dynamic "item" {
                    for_each = m.value.presence == "match" ? [1] : []
                    content {
                      exact_values = length(m.value.exact_values) > 0 ? m.value.exact_values : null
                      regex_values = length(m.value.regex_values) > 0 ? m.value.regex_values : null
                    }
                  }
                }
              }
            }
          }
        }
      }

      dynamic "api_groups_rules" {
        for_each = var.api_protection_group_rules
        iterator = gp
        content {
          metadata {
            name = "api-protection-group-${gp.key}"
          }
          api_group = gp.value.api_group
          base_path = gp.value.base_path
          dynamic "any_domain" {
            for_each = gp.value.domain_mode == "any" ? [1] : []
            content {}
          }
          specific_domain = gp.value.domain_mode == "specific" ? gp.value.domain : null
          action {
            dynamic "allow" {
              for_each = gp.value.action == "allow" ? [1] : []
              content {}
            }
            dynamic "deny" {
              for_each = gp.value.action == "deny" ? [1] : []
              content {}
            }
          }
          dynamic "client_matcher" {
            for_each = gp.value.client_matcher != null && gp.value.client_matcher.mode != null ? [gp.value.client_matcher] : []
            iterator = cm
            content {
              dynamic "any_ip" {
                for_each = cm.value.mode == "any_ip" ? [1] : []
                content {}
              }
              dynamic "asn_list" {
                for_each = cm.value.mode == "asn_list" ? [1] : []
                content { as_numbers = cm.value.as_numbers }
              }
              dynamic "asn_matcher" {
                for_each = cm.value.mode == "asn_matcher" ? [1] : []
                content {
                  dynamic "asn_sets" {
                    for_each = cm.value.asn_sets
                    content {
                      name      = asn_sets.value.name
                      namespace = coalesce(asn_sets.value.namespace, var.namespace)
                    }
                  }
                }
              }
              dynamic "client_selector" {
                for_each = cm.value.mode == "client_selector" ? [1] : []
                content { expressions = cm.value.selector_expressions }
              }
              dynamic "ip_matcher" {
                for_each = cm.value.mode == "ip_matcher" ? [1] : []
                content {
                  invert_matcher = cm.value.ip_invert
                  dynamic "prefix_sets" {
                    for_each = cm.value.ip_prefix_sets
                    content {
                      name      = prefix_sets.value.name
                      namespace = coalesce(prefix_sets.value.namespace, var.namespace)
                    }
                  }
                }
              }
              dynamic "ip_prefix_list" {
                for_each = cm.value.mode == "ip_prefix_list" ? [1] : []
                content {
                  ip_prefixes  = cm.value.ip_prefixes
                  invert_match = cm.value.ip_invert
                }
              }
              dynamic "ip_threat_category_list" {
                for_each = cm.value.mode == "ip_threat_category_list" ? [1] : []
                content { ip_threat_categories = cm.value.ip_threat_categories }
              }
              dynamic "tls_fingerprint_matcher" {
                for_each = cm.value.mode == "tls_fingerprint_matcher" ? [1] : []
                content {
                  classes         = length(cm.value.tls_classes) > 0 ? cm.value.tls_classes : null
                  exact_values    = length(cm.value.tls_exact_values) > 0 ? cm.value.tls_exact_values : null
                  excluded_values = length(cm.value.tls_excluded_values) > 0 ? cm.value.tls_excluded_values : null
                }
              }
            }
          }
          dynamic "request_matcher" {
            for_each = gp.value.request_matcher != null ? [gp.value.request_matcher] : []
            iterator = rm
            content {
              dynamic "headers" {
                for_each = rm.value.headers
                iterator = m
                content {
                  name           = m.value.name
                  invert_matcher = m.value.invert
                  dynamic "check_present" {
                    for_each = m.value.presence == "present" ? [1] : []
                    content {}
                  }
                  dynamic "check_not_present" {
                    for_each = m.value.presence == "absent" ? [1] : []
                    content {}
                  }
                  dynamic "item" {
                    for_each = m.value.presence == "match" ? [1] : []
                    content {
                      exact_values = length(m.value.exact_values) > 0 ? m.value.exact_values : null
                      regex_values = length(m.value.regex_values) > 0 ? m.value.regex_values : null
                    }
                  }
                }
              }
              dynamic "cookie_matchers" {
                for_each = rm.value.cookies
                iterator = m
                content {
                  name           = m.value.name
                  invert_matcher = m.value.invert
                  dynamic "check_present" {
                    for_each = m.value.presence == "present" ? [1] : []
                    content {}
                  }
                  dynamic "check_not_present" {
                    for_each = m.value.presence == "absent" ? [1] : []
                    content {}
                  }
                  dynamic "item" {
                    for_each = m.value.presence == "match" ? [1] : []
                    content {
                      exact_values = length(m.value.exact_values) > 0 ? m.value.exact_values : null
                      regex_values = length(m.value.regex_values) > 0 ? m.value.regex_values : null
                    }
                  }
                }
              }
              dynamic "jwt_claims" {
                for_each = rm.value.jwt_claims
                iterator = m
                content {
                  name           = m.value.name
                  invert_matcher = m.value.invert
                  dynamic "check_present" {
                    for_each = m.value.presence == "present" ? [1] : []
                    content {}
                  }
                  dynamic "check_not_present" {
                    for_each = m.value.presence == "absent" ? [1] : []
                    content {}
                  }
                  dynamic "item" {
                    for_each = m.value.presence == "match" ? [1] : []
                    content {
                      exact_values = length(m.value.exact_values) > 0 ? m.value.exact_values : null
                      regex_values = length(m.value.regex_values) > 0 ? m.value.regex_values : null
                    }
                  }
                }
              }
              dynamic "query_params" {
                for_each = rm.value.query_params
                iterator = m
                content {
                  key            = m.value.name
                  invert_matcher = m.value.invert
                  dynamic "check_present" {
                    for_each = m.value.presence == "present" ? [1] : []
                    content {}
                  }
                  dynamic "check_not_present" {
                    for_each = m.value.presence == "absent" ? [1] : []
                    content {}
                  }
                  dynamic "item" {
                    for_each = m.value.presence == "match" ? [1] : []
                    content {
                      exact_values = length(m.value.exact_values) > 0 ? m.value.exact_values : null
                      regex_values = length(m.value.regex_values) > 0 ? m.value.regex_values : null
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  # API Testing (SP4) — LB api_testing_choice oneof: the inline api_testing block
  # (scheduled/triggered API tests against domains with credentials) vs the server
  # default disable_api_testing (import-suppressed => omit => 0-change). Shares the
  # rendered domains/credentials with the standalone xcsh_api_testing resource (DRY);
  # the LB surface carries no schedule. Emit only when api_testing_choice = "enabled".
  dynamic "api_testing" {
    for_each = var.api_testing_choice == "enabled" ? [1] : []
    content {
      custom_header_value = var.api_testing_custom_header_value

      dynamic "domains" {
        for_each = local.rendered_api_testing
        content {
          domain                    = domains.value.domain
          allow_destructive_methods = domains.value.allow_destructive_methods

          dynamic "credentials" {
            for_each = domains.value.credentials
            content {
              credential_name = credentials.value.credential_name

              dynamic "api_key" {
                for_each = credentials.value.use_api_key ? [1] : []
                content {
                  key = credentials.value.api_key_name
                  value {
                    dynamic "blindfold_secret_info" {
                      for_each = credentials.value.secret_use_blindfold ? [1] : []
                      content { location = credentials.value.secret_location }
                    }
                    dynamic "clear_secret_info" {
                      for_each = credentials.value.secret_use_blindfold ? [] : [1]
                      content { url = credentials.value.secret_url }
                    }
                  }
                }
              }
              dynamic "basic_auth" {
                for_each = credentials.value.use_basic_auth ? [1] : []
                content {
                  user = credentials.value.user
                  password {
                    dynamic "blindfold_secret_info" {
                      for_each = credentials.value.secret_use_blindfold ? [1] : []
                      content { location = credentials.value.secret_location }
                    }
                    dynamic "clear_secret_info" {
                      for_each = credentials.value.secret_use_blindfold ? [] : [1]
                      content { url = credentials.value.secret_url }
                    }
                  }
                }
              }
              dynamic "bearer_token" {
                for_each = credentials.value.use_bearer ? [1] : []
                content {
                  token {
                    dynamic "blindfold_secret_info" {
                      for_each = credentials.value.secret_use_blindfold ? [1] : []
                      content { location = credentials.value.secret_location }
                    }
                    dynamic "clear_secret_info" {
                      for_each = credentials.value.secret_use_blindfold ? [] : [1]
                      content { url = credentials.value.secret_url }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  # Client-Side Defense — inject the F5 XC telemetry JavaScript into served pages
  # to detect Magecart/formjacking/skimming (client_side_defense oneof vs the
  # server default disable_client_side_defense). Requires the CSD tenant addon
  # (verified via the data-source guard in the root module). When csd_enabled is
  # false we emit NO block — the server applies disable_client_side_defense, which
  # the provider suppresses on import (so no drift; do not declare it).
  dynamic "client_side_defense" {
    for_each = var.csd_enabled ? [1] : []
    content {
      policy {
        js_insert_all_pages {}
      }
    }
  }

  # Malicious User Detection — score per-user behavior into threat levels
  # (malicious_user_detection oneof vs the server default disable_malicious_user_detection).
  # (malicious_user_detection oneof vs the server default disable_malicious_user_detection).
  # When mud_enabled is false we emit NO block — the server applies the disable marker,
  # which the provider suppresses on import (no drift; do not declare it).
  dynamic "enable_malicious_user_detection" {
    for_each = var.mud_enabled ? [1] : []
    content {}
  }

  # User identification: reference a user_identification policy when mud_user_id is
  # user_identification; otherwise emit nothing and the server applies the default
  # user_id_client_ip (import-suppressed). (user_id oneof: user_id_client_ip vs
  # user_identification.)
  dynamic "user_identification" {
    for_each = var.mud_enabled && var.mud_user_id == "user_identification" ? [1] : []
    content {
      name      = xcsh_user_identification.mud[0].name
      namespace = xcsh_user_identification.mud[0].namespace
    }
  }

  # Auto-mitigation for detected malicious users, via the challenge oneof. mud_challenge_mode
  # selects enable_challenge (risk-based) or policy_based_challenge (policy-rule-based); both
  # carry the malicious_user_mitigation reference. "none" emits neither → server default
  # no_challenge (import-suppressed). Both arms are gated on mud_enabled.
  dynamic "enable_challenge" {
    for_each = var.mud_enabled && var.mud_challenge_mode == "enable_challenge" ? [1] : []
    content {
      malicious_user_mitigation {
        name      = xcsh_malicious_user_mitigation.mud[0].name
        namespace = xcsh_malicious_user_mitigation.mud[0].namespace
      }
    }
  }

  dynamic "policy_based_challenge" {
    for_each = var.mud_enabled && var.mud_challenge_mode == "policy_based_challenge" ? [1] : []
    content {
      malicious_user_mitigation {
        name      = xcsh_malicious_user_mitigation.mud[0].name
        namespace = xcsh_malicious_user_mitigation.mud[0].namespace
      }
    }
  }

  # Fail fast at plan if a crawler domain is configured without a usable password
  # value — a cross-variable check the api_crawler_password variable validation cannot
  # express (clear needs plaintext; blindfold needs location).
  lifecycle {
    precondition {
      condition     = length(var.api_crawler_domains) == 0 || local.api_crawler_password_secret.url != null || local.api_crawler_password_secret.location != null
      error_message = "api_crawler_domains is set but api_crawler_password has no value: set plaintext (clear) or location (blindfold)."
    }

    # Code-scan discovery lives inside enable_api_discovery and references the
    # code_base_integration, so it requires discovery enabled AND the integration
    # created — cross-variable checks the per-variable validation cannot express.
    precondition {
      condition     = var.api_discovery_code_scan == "off" || var.api_discovery_choice == "enable"
      error_message = "api_discovery_code_scan requires api_discovery_choice=\"enable\" (code scan is part of enable_api_discovery)."
    }
    precondition {
      condition     = var.api_discovery_code_scan == "off" || var.code_base_integration_enabled
      error_message = "api_discovery_code_scan requires code_base_integration_enabled=true (it references the code_base_integration)."
    }
    precondition {
      condition     = var.api_discovery_code_scan != "selected" || length(var.api_discovery_code_scan_repos) > 0
      error_message = "api_discovery_code_scan=\"selected\" requires api_discovery_code_scan_repos to be non-empty."
    }

    # API testing (both surfaces) needs real domains — F5 XC rejects a domain with no
    # credentials (500) and an api_testing block with no domains is meaningless. The
    # standalone resource guards this in its own precondition; mirror it for the LB
    # inline block so api_testing_choice="enabled" fails fast at plan (cross-variable,
    # symmetric with the standalone path).
    precondition {
      condition     = var.api_testing_choice != "enabled" || length(var.api_testing_domains) > 0
      error_message = "api_testing_choice=\"enabled\" requires at least one api_testing_domains entry."
    }

    # Custom OpenAPI fall-through / custom_list needs rules to emit — an empty
    # fall_through_mode_custom {} (or custom_list with no rules) fails at apply.
    precondition {
      condition     = var.api_validation_fall_through != "custom" || length(var.validation_custom_rules) > 0
      error_message = "api_validation_fall_through=\"custom\" requires at least one validation_custom_rules entry."
    }

    # rate_limit.policies references standalone rate_limiter_policies by name; each ref
    # must resolve to a created policy, and policies only apply on the rate_limit arm.
    precondition {
      condition     = length(var.rate_limit_ip_allowed_prefixes) == 0 || length(var.rate_limit_custom_ip_prefix_sets) == 0
      error_message = "set only one of rate_limit_ip_allowed_prefixes (inline) or rate_limit_custom_ip_prefix_sets (refs), not both."
    }
    precondition {
      condition     = length(var.rate_limit_policy_refs) == 0 || var.rate_limit_choice == "rate_limit"
      error_message = "rate_limit_policy_refs requires rate_limit_choice=\"rate_limit\"."
    }
    precondition {
      condition     = (length(var.rate_limit_ip_allowed_prefixes) == 0 && length(var.rate_limit_custom_ip_prefix_sets) == 0) || var.rate_limit_choice == "rate_limit"
      error_message = "rate_limit_ip_allowed_prefixes / rate_limit_custom_ip_prefix_sets require rate_limit_choice=\"rate_limit\"."
    }
    precondition {
      condition     = var.rate_limit_choice != "api_rate_limit" || (length(var.api_rate_limit_endpoint_rules) + length(var.api_rate_limit_bypass_rules) + length(var.api_rate_limit_server_url_rules)) > 0
      error_message = "rate_limit_choice=\"api_rate_limit\" requires at least one api_rate_limit_endpoint_rules / bypass_rules / server_url_rules entry."
    }
    precondition {
      condition     = alltrue([for r in var.rate_limit_policy_refs : contains([for p in var.rate_limiter_policies : p.name], r)])
      error_message = "every rate_limit_policy_refs entry must name a rate_limiter_policies entry."
    }

    # active_service_policies references standalone service_policies by name, in order;
    # every ref must resolve to a created policy, and names only apply on the active arm.
    precondition {
      condition     = alltrue([for r in var.service_policy_active : contains([for p in var.service_policies : p.name], r)])
      error_message = "every service_policy_active entry must name a service_policies entry."
    }
    precondition {
      condition     = length(var.service_policy_active) == 0 || var.service_policies_choice == "active"
      error_message = "service_policy_active requires service_policies_choice=\"active\"."
    }
    precondition {
      condition     = var.service_policies_choice != "active" || length(var.service_policy_active) > 0
      error_message = "service_policies_choice=\"active\" requires at least one service_policy_active entry."
    }

    # The api_rate_limit rule lists only apply on the api_rate_limit arm, and every
    # ref_rate_limiter must resolve to a created xcsh_rate_limiter.
    precondition {
      condition     = var.rate_limit_choice == "api_rate_limit" || (length(var.api_rate_limit_endpoint_rules) == 0 && length(var.api_rate_limit_bypass_rules) == 0 && length(var.api_rate_limit_server_url_rules) == 0)
      error_message = "api_rate_limit_* rules require rate_limit_choice=\"api_rate_limit\"."
    }
    precondition {
      condition = alltrue(concat(
        [for r in var.api_rate_limit_endpoint_rules : contains(keys(xcsh_rate_limiter.this), r.ref_rate_limiter) if r.ref_rate_limiter != null],
        [for r in var.api_rate_limit_server_url_rules : contains(keys(xcsh_rate_limiter.this), r.ref_rate_limiter) if r.ref_rate_limiter != null],
      ))
      error_message = "every api_rate_limit ref_rate_limiter must name a rate_limiters entry."
    }

    # custom_data_types attach to the standalone sensitive_data_policy, so they need
    # that policy selected. The ref-exists check lives on xcsh_sensitive_data_policy
    # (the resource that indexes xcsh_data_type), so it is not duplicated here.
    precondition {
      condition     = length(var.sensitive_data_custom_type_refs) == 0 || var.sensitive_data_policy_choice == "custom"
      error_message = "sensitive_data_custom_type_refs requires sensitive_data_policy_choice=\"custom\"."
    }
  }
}
