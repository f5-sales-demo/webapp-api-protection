# Renderer for the reusable clear/blindfold SecretType convention. use_blindfold
# selects the SecretType arm; `location` is the offline-sealed blob (blindfold
# arm), `url` is the base64 clear value (clear arm). Exactly one is non-null when
# plaintext is set. The provider::xcsh::blindfold call sits in the untaken branch
# of the conditional for the clear arm, so a clear-method plan never contacts the
# tenant; the blindfold arm calls the provider function (needs XCSH creds).
locals {
  api_crawler_password_secret = {
    use_blindfold = var.api_crawler_password.method == "blindfold"
    url = (var.api_crawler_password.method == "clear" && var.api_crawler_password.plaintext != null
      ? "string:///${base64encode(var.api_crawler_password.plaintext)}"
    : null)
    location = (var.api_crawler_password.method == "blindfold" && var.api_crawler_password.plaintext != null
      ? provider::xcsh::blindfold(base64encode(var.api_crawler_password.plaintext), var.api_crawler_password.blindfold_policy_name, var.api_crawler_password.blindfold_policy_namespace)
    : null)
  }
}
