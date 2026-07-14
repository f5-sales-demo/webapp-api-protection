# API Protection (SP3) outputs — effective arm echoes for plan-level tests and
# downstream visibility (same convention as outputs_api.tf / outputs_api_definition.tf).

output "client_matcher_mode" {
  description = "Effective shared client-matcher mode (any, ip_prefix, or ip_threat)."
  value       = var.client_matcher.mode
}

output "rate_limit_choice" {
  description = "Effective rate_limit_choice arm (disable or rate_limit)."
  value       = var.rate_limit_choice
}

output "sensitive_data_policy_created" {
  description = "Whether a standalone xcsh_sensitive_data_policy is created."
  value       = var.sensitive_data_policy_enabled
}

output "sensitive_data_policy_choice" {
  description = "Effective sensitive_data_policy_choice arm (default or custom)."
  value       = var.sensitive_data_policy_choice
}

output "data_guard_rule_count" {
  description = "Number of data_guard_rules configured."
  value       = length(var.data_guard_rules)
}
