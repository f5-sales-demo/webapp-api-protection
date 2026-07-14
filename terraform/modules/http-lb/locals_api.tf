# Renderer for the reusable clear/blindfold SecretType convention. use_blindfold
# selects the SecretType arm; `location` is the pre-sealed offline blob (blindfold
# arm), `url` is the base64 clear value (clear arm). Exactly one is non-null.
#
# The blindfold location is pinned (sealed once via scripts/blindfold-seal.sh), NOT
# computed here: provider::xcsh::blindfold uses a random data key, so an inline call
# would produce a new ciphertext every plan and drift. Pinning the sealed value is
# the F5-documented offline-blindfold pattern and keeps apply idempotent + import-clean.
locals {
  api_crawler_password_secret = {
    use_blindfold = var.api_crawler_password.method == "blindfold"
    url = (var.api_crawler_password.method == "clear" && var.api_crawler_password.plaintext != null
      ? "string:///${base64encode(var.api_crawler_password.plaintext)}"
    : null)
    location = var.api_crawler_password.method == "blindfold" ? var.api_crawler_password.location : null
  }
}
