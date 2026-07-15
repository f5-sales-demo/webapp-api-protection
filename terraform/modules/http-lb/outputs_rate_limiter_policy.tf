# Standalone rate-limiter policy outputs (Coverage Batch B).
output "rate_limiter_policy_names" {
  description = "Names of the standalone xcsh_rate_limiter_policy resources created."
  value       = sort([for p in xcsh_rate_limiter_policy.this : p.name])
}

output "rate_limiter_policy_count" {
  description = "Number of standalone xcsh_rate_limiter_policy resources created."
  value       = length(xcsh_rate_limiter_policy.this)
}
