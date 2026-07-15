# Standalone rate-limiter outputs (Coverage Batch B) — names for wiring/assertions.
output "rate_limiter_names" {
  description = "Names of the standalone xcsh_rate_limiter resources created."
  value       = sort([for rl in xcsh_rate_limiter.this : rl.name])
}

output "rate_limiter_count" {
  description = "Number of standalone xcsh_rate_limiter resources created."
  value       = length(xcsh_rate_limiter.this)
}
