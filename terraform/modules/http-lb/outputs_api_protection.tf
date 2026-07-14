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
