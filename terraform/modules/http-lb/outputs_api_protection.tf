# API Protection (SP3) outputs — effective arm echoes for plan-level tests and
# downstream visibility (same convention as outputs_api.tf / outputs_api_definition.tf).

output "rate_limit_choice" {
  description = "Effective rate_limit_choice arm (disable or rate_limit)."
  value       = var.rate_limit_choice
}

output "sensitive_data_policy_created" {
  description = "Whether a standalone xcsh_sensitive_data_policy is created."
  value       = var.sensitive_data_policy_choice == "custom"
}

output "sensitive_data_policy_choice" {
  description = "Effective sensitive_data_policy_choice arm (default or custom)."
  value       = var.sensitive_data_policy_choice
}

output "data_guard_rule_count" {
  description = "Number of data_guard_rules configured."
  value       = length(var.data_guard_rules)
}

output "api_protection_rule_count" {
  description = "Number of api_protection_rules (api_endpoint_rules) configured."
  value       = length(var.api_protection_rules)
}

output "api_protection_group_rule_count" {
  description = "Number of api_protection_rules (api_groups_rules) configured."
  value       = length(var.api_protection_group_rules)
}
