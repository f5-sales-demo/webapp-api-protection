# xcsh_code_base_integration (Coverage Batch E) — SCM credentials F5 XC uses to pull
# API specs from source control. code_base_integration_provider selects the arm; the
# token (code_base_integration_access_token) is rendered as access_token (github/
# github_enterprise/gitlab/gitlab_enterprise/azure_repos) or passwd (bitbucket/
# bitbucket_server) via the reusable clear/blindfold convention (local.rendered_secret,
# identical SecretType shape as the crawler password). Repo selection is at the LB via
# enable_api_discovery.api_discovery_from_code_scan.
resource "xcsh_code_base_integration" "this" {
  count     = var.code_base_integration_enabled ? 1 : 0
  name      = "${var.namespace}-api-catalog"
  namespace = var.namespace

  code_base_integration {
    dynamic "github" {
      for_each = var.code_base_integration_provider == "github" ? [1] : []
      content {
        username   = var.code_base_integration_username
        verify_ssl = var.code_base_integration_verify_ssl
        access_token {
          dynamic "blindfold_secret_info" {
            for_each = local.scm_token_blindfold
            content {
              location = blindfold_secret_info.value
            }
          }
          dynamic "clear_secret_info" {
            for_each = local.scm_token_clear
            content {
              url = clear_secret_info.value
            }
          }
        }
      }
    }
    dynamic "github_enterprise" {
      for_each = var.code_base_integration_provider == "github_enterprise" ? [1] : []
      content {
        hostname = var.code_base_integration_hostname
        username = var.code_base_integration_username
        access_token {
          dynamic "blindfold_secret_info" {
            for_each = local.scm_token_blindfold
            content {
              location = blindfold_secret_info.value
            }
          }
          dynamic "clear_secret_info" {
            for_each = local.scm_token_clear
            content {
              url = clear_secret_info.value
            }
          }
        }
      }
    }
    dynamic "gitlab" {
      for_each = var.code_base_integration_provider == "gitlab" ? [1] : []
      content {
        access_token {
          dynamic "blindfold_secret_info" {
            for_each = local.scm_token_blindfold
            content {
              location = blindfold_secret_info.value
            }
          }
          dynamic "clear_secret_info" {
            for_each = local.scm_token_clear
            content {
              url = clear_secret_info.value
            }
          }
        }
      }
    }
    dynamic "gitlab_enterprise" {
      for_each = var.code_base_integration_provider == "gitlab_enterprise" ? [1] : []
      content {
        url = var.code_base_integration_url
        access_token {
          dynamic "blindfold_secret_info" {
            for_each = local.scm_token_blindfold
            content {
              location = blindfold_secret_info.value
            }
          }
          dynamic "clear_secret_info" {
            for_each = local.scm_token_clear
            content {
              url = clear_secret_info.value
            }
          }
        }
      }
    }
    dynamic "azure_repos" {
      for_each = var.code_base_integration_provider == "azure_repos" ? [1] : []
      content {
        access_token {
          dynamic "blindfold_secret_info" {
            for_each = local.scm_token_blindfold
            content {
              location = blindfold_secret_info.value
            }
          }
          dynamic "clear_secret_info" {
            for_each = local.scm_token_clear
            content {
              url = clear_secret_info.value
            }
          }
        }
      }
    }
    dynamic "bitbucket" {
      for_each = var.code_base_integration_provider == "bitbucket" ? [1] : []
      content {
        username = var.code_base_integration_username
        passwd {
          dynamic "blindfold_secret_info" {
            for_each = local.scm_token_blindfold
            content {
              location = blindfold_secret_info.value
            }
          }
          dynamic "clear_secret_info" {
            for_each = local.scm_token_clear
            content {
              url = clear_secret_info.value
            }
          }
        }
      }
    }
    dynamic "bitbucket_server" {
      for_each = var.code_base_integration_provider == "bitbucket_server" ? [1] : []
      content {
        url        = var.code_base_integration_url
        username   = var.code_base_integration_username
        verify_ssl = var.code_base_integration_verify_ssl
        passwd {
          dynamic "blindfold_secret_info" {
            for_each = local.scm_token_blindfold
            content {
              location = blindfold_secret_info.value
            }
          }
          dynamic "clear_secret_info" {
            for_each = local.scm_token_clear
            content {
              url = clear_secret_info.value
            }
          }
        }
      }
    }
  }

  lifecycle {
    precondition {
      condition     = local.scm_token.url != null || local.scm_token.location != null
      error_message = "code_base_integration_enabled requires code_base_integration_access_token: set plaintext (clear) or location (blindfold)."
    }
    precondition {
      condition     = var.code_base_integration_provider != "github_enterprise" || var.code_base_integration_hostname != ""
      error_message = "code_base_integration_provider=github_enterprise requires code_base_integration_hostname."
    }
    precondition {
      condition     = !contains(["gitlab_enterprise", "bitbucket_server"], var.code_base_integration_provider) || var.code_base_integration_url != ""
      error_message = "code_base_integration_provider gitlab_enterprise/bitbucket_server requires code_base_integration_url."
    }
    precondition {
      condition     = !contains(["github", "github_enterprise", "bitbucket", "bitbucket_server"], var.code_base_integration_provider) || var.code_base_integration_username != ""
      error_message = "code_base_integration_provider github/github_enterprise/bitbucket/bitbucket_server requires code_base_integration_username."
    }
  }
}

output "code_base_integration_enabled" {
  description = "Whether an xcsh_code_base_integration is created."
  value       = var.code_base_integration_enabled
}

output "code_base_integration_provider" {
  description = "Effective SCM provider arm."
  value       = var.code_base_integration_provider
}

output "code_base_integration_token_method" {
  description = "Effective code_base_integration token secret method (clear or blindfold)."
  value       = nonsensitive(var.code_base_integration_access_token.method)
}
