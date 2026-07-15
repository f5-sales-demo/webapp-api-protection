# Standalone custom data-type outputs (Coverage Batch C).
output "data_type_names" {
  description = "Names of the standalone xcsh_data_type resources created."
  value       = sort([for d in xcsh_data_type.this : d.name])
}

output "data_type_count" {
  description = "Number of standalone xcsh_data_type resources created."
  value       = length(xcsh_data_type.this)
}
