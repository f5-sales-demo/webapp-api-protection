# xcsh_api_testing (SP4) — standalone scheduled API-testing config. Created iff
# api_testing_standalone_enabled (single knob). Consumes local.rendered_api_testing
# (shared with the LB inline api_testing block, DRY). Schedule is a flat top-level
# oneof; every_week is the suppressed server default (emit neither marker for it).
# Credentials carry the clear/blindfold SecretType (seal-once-pin — see locals_api.tf).
resource "xcsh_api_testing" "this" {
  count     = var.api_testing_standalone_enabled ? 1 : 0
  name      = "${var.namespace}-api-testing"
  namespace = var.namespace

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

          dynamic "admin" {
            for_each = credentials.value.use_admin ? [1] : []
            content {}
          }
          dynamic "standard" {
            for_each = credentials.value.use_standard ? [1] : []
            content {}
          }
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

  # Schedule oneof (every_week = suppressed default => emit neither marker).
  dynamic "every_day" {
    for_each = local.api_testing_use_every_day ? [1] : []
    content {}
  }
  dynamic "every_month" {
    for_each = local.api_testing_use_every_month ? [1] : []
    content {}
  }

  lifecycle {
    precondition {
      condition     = length(var.api_testing_domains) > 0
      error_message = "api_testing_standalone_enabled requires at least one api_testing_domains entry."
    }
  }
}
