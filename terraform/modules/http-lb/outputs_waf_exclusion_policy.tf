# Names of the standalone WAF exclusion policies created (LPC-4b), for reference/visibility.
output "waf_exclusion_policy_names" {
  description = "Names of created standalone xcsh_waf_exclusion_policy resources."
  value       = [for p in xcsh_waf_exclusion_policy.this : p.name]
}
