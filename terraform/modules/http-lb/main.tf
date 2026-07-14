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
  name      = "webapp-api-protection"
  namespace = var.namespace
  labels    = var.labels

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
    # F5 XC always normalizes an empty endpoint_subsets object into the API
    # response for each default_route_pools entry (verified via live API), so we
    # declare it to keep apply/plan/import consistent. This is correct config,
    # not a workaround. (Provider-side handling of server-default empty oneof
    # members on import is tracked in terraform-provider-xcsh#1003.)
    endpoint_subsets {}
  }

  advertise_on_public_default_vip {}

  # Attach the WAF (oneof: app_firewall vs disable_waf; server default disable_waf).
  app_firewall {
    name      = xcsh_app_firewall.this.name
    namespace = xcsh_app_firewall.this.namespace
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
                        location = local.api_crawler_password_secret.location
                      }
                    }
                    dynamic "clear_secret_info" {
                      for_each = local.api_crawler_password_secret.use_blindfold ? [] : [1]
                      content {
                        url = local.api_crawler_password_secret.url
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
    }
  }

  # disable_api_discovery — the other arm of api_discovery_choice.
  dynamic "disable_api_discovery" {
    for_each = var.api_discovery_choice == "disable" ? [1] : []
    content {}
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
}
