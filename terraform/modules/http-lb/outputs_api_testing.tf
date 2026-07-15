# API Testing (SP4) outputs.
output "api_testing_choice" {
  description = "Effective LB api_testing_choice (disable | enabled)."
  value       = var.api_testing_choice
}

output "api_testing_standalone_created" {
  description = "Whether a standalone xcsh_api_testing resource is created."
  value       = var.api_testing_standalone_enabled
}

output "api_testing_schedule" {
  description = "Standalone api_testing schedule arm (every_week suppressed default | every_day | every_month)."
  value       = var.api_testing_schedule
}

output "api_testing_domain_count" {
  description = "Number of configured API-testing domains."
  value       = nonsensitive(length(var.api_testing_domains))
}

output "api_testing_credential_count" {
  description = "Total configured API-testing credentials across all domains."
  value       = nonsensitive(length(var.api_testing_domains) == 0 ? 0 : sum([for d in var.api_testing_domains : length(d.credentials)]))
}
