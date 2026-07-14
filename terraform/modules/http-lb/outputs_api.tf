# API Discovery & Crawler (SP1) outputs — effective arm echoes for plan-level
# tests and downstream visibility, matching the waf_*_mode output convention.

# method/use_blindfold are the arm selector and a bool — not secret. The
# api_crawler_password variable is sensitive to protect `plaintext`, which taints
# these derived values; nonsensitive() strips the taint from the non-secret parts
# only (plaintext, url, location are never exposed).
output "api_crawler_password_method" {
  description = "Effective api_crawler_password secret method (clear or blindfold)."
  value       = nonsensitive(var.api_crawler_password.method)
}

output "api_crawler_password_use_blindfold" {
  description = "Whether the crawler password renders the blindfold_secret_info arm (true) or clear_secret_info (false)."
  value       = nonsensitive(local.api_crawler_password_secret.use_blindfold)
}

output "api_crawler_domain_count" {
  description = "Number of authenticated domains configured for the inline API crawler."
  value       = length(var.api_crawler_domains)
}

output "api_discovery_choice" {
  description = "Effective api_discovery_choice arm (enable or disable)."
  value       = var.api_discovery_choice
}

output "api_discovery_learn_from_redirect" {
  description = "Effective learn-from-redirect arm (omit or enable)."
  value       = var.api_discovery_learn_from_redirect
}

output "api_discovery_purge_duration" {
  description = "Effective discovered_api_settings purge duration (null when omitted)."
  value       = var.api_discovery_purge_duration
}
