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
