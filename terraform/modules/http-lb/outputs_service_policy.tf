# Created service policy names, for reference/verification (SPol effort).
output "service_policy_names" {
  description = "Names of the created xcsh_service_policy objects, keyed by name."
  value       = { for k, p in xcsh_service_policy.this : k => p.name }
}
