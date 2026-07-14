# xcsh_code_base_integration (github) — holds the SCM credentials F5 XC uses to pull
# API specs from source control. Repo selection happens at the LB via
# enable_api_discovery.api_discovery_from_code_scan (that LB wiring lands once provider
# #1091 — object-ref tenant — is released, same class as the SP1 api_discovery_ref).
# access_token uses the reusable clear/blindfold convention (local.rendered_secret),
# the identical SecretType shape as the crawler password.
resource "xcsh_code_base_integration" "github" {
  count     = var.code_base_integration_enabled ? 1 : 0
  name      = "${var.namespace}-api-catalog"
  namespace = var.namespace

  code_base_integration {
    github {
      username = var.code_base_integration_username
      access_token {
        dynamic "blindfold_secret_info" {
          for_each = local.rendered_secret["code_base_integration_token"].use_blindfold ? [1] : []
          content {
            location = local.rendered_secret["code_base_integration_token"].location
          }
        }
        dynamic "clear_secret_info" {
          for_each = local.rendered_secret["code_base_integration_token"].use_blindfold ? [] : [1]
          content {
            url = local.rendered_secret["code_base_integration_token"].url
          }
        }
      }
    }
  }

  # Fail fast at plan if enabled without a usable token value.
  lifecycle {
    precondition {
      condition     = local.rendered_secret["code_base_integration_token"].url != null || local.rendered_secret["code_base_integration_token"].location != null
      error_message = "code_base_integration_enabled requires code_base_integration_access_token: set plaintext (clear) or location (blindfold)."
    }
  }
}

output "code_base_integration_enabled" {
  description = "Whether an xcsh_code_base_integration (github) is created."
  value       = var.code_base_integration_enabled
}

output "code_base_integration_token_method" {
  description = "Effective code_base_integration access_token secret method (clear or blindfold)."
  value       = nonsensitive(var.code_base_integration_access_token.method)
}
