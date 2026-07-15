# Reusable clear/blindfold SecretType renderer (DRY). Every secret-bearing option
# registers its input (same object shape: {method, plaintext, location}) in
# _secret_inputs and reads local.rendered_secret[<key>] -> {use_blindfold, url,
# location}. ONE transform serves all secrets (crawler password, SCM access_token,
# future TLS/origin secrets) instead of a per-field copy.
#
# use_blindfold selects the SecretType arm; `location` is the PRE-SEALED offline blob
# (blindfold arm), `url` is the base64 clear value (clear arm). Exactly one is non-null.
# The blindfold location is pinned (sealed once via scripts/blindfold-seal.sh), NOT
# computed here: provider::xcsh::blindfold uses a random data key, so an inline call
# would produce a new ciphertext every plan and drift. Pinning is the F5-documented
# offline-blindfold pattern and keeps apply idempotent + import-clean.
locals {
  _secret_inputs = {
    api_crawler_password        = var.api_crawler_password
    code_base_integration_token = var.code_base_integration_access_token
  }

  rendered_secret = {
    for k, s in local._secret_inputs : k => {
      use_blindfold = s.method == "blindfold"
      url = (s.method == "clear" && s.plaintext != null
        ? "string:///${base64encode(s.plaintext)}"
      : null)
      location = s.method == "blindfold" ? s.location : null
    }
  }

  # LB name — shared by the LB resource and app_api_group (which references the LB by
  # this static name to avoid a resource-dependency cycle; see app_api_group.tf).
  lb_name = "webapp-api-protection"

  # Named aliases for consumers (keep references stable/short).
  api_crawler_password_secret = local.rendered_secret["api_crawler_password"]
  scm_token                   = local.rendered_secret["code_base_integration_token"]

  # Precomputed single-element (or empty) selectors for the SCM token secret arm, so
  # each of the 7 provider arms renders the same compact blindfold/clear dynamic pair
  # (one selection expression, not a repeated ternary per arm).
  scm_token_blindfold = local.scm_token.use_blindfold ? [local.scm_token.location] : []
  scm_token_clear     = local.scm_token.use_blindfold ? [] : [local.scm_token.url]
}
