# Rendered API Testing domains/credentials (SP4, DRY). Both surfaces (standalone
# xcsh_api_testing + LB inline api_testing block) consume local.rendered_api_testing —
# one transform that pre-computes each credential's auth-arm selectors and the
# clear/blindfold SecretType shape (same seal-once-pin rule as locals_api.tf: the
# blindfold `location` is a PRE-SEALED string:///... pinned offline, never computed
# inline, so apply stays idempotent + import-clean).
locals {
  rendered_api_testing = [
    for d in var.api_testing_domains : {
      domain                    = d.domain
      allow_destructive_methods = d.allow_destructive_methods
      credentials = [
        for c in d.credentials : {
          credential_name = c.credential_name
          use_admin       = c.auth_type == "admin"
          use_standard    = c.auth_type == "standard"
          use_api_key     = c.auth_type == "api_key"
          use_basic_auth  = c.auth_type == "basic_auth"
          use_bearer      = c.auth_type == "bearer_token"
          api_key_name    = c.api_key_name
          user            = c.user
          # SecretType (api_key value / basic_auth password / bearer_token token):
          # exactly one of url (clear) / location (blindfold) is non-null when present.
          secret_use_blindfold = c.secret != null && try(c.secret.method, "clear") == "blindfold"
          secret_url = (c.secret != null && try(c.secret.method, "clear") == "clear" && try(c.secret.plaintext, null) != null
            ? "string:///${base64encode(c.secret.plaintext)}"
          : null)
          secret_location = c.secret != null && try(c.secret.method, "clear") == "blindfold" ? c.secret.location : null
        }
      ]
    }
  ]

  # Schedule arm selectors (standalone only). every_week is the suppressed server
  # default => emit NEITHER marker so a bare resource is import-clean.
  api_testing_use_every_day   = var.api_testing_schedule == "every_day"
  api_testing_use_every_month = var.api_testing_schedule == "every_month"
}
