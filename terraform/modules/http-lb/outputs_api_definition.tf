# API Definition & spec enforcement (SP2) outputs — effective arm echoes for
# plan-level tests and downstream visibility (same convention as outputs_api.tf).

output "api_definition_choice" {
  description = "Effective api_definition_choice arm (disable or specification)."
  value       = var.api_definition_choice
}

output "api_definition_created" {
  description = "Whether an xcsh_api_definition is created (true when api_definition_choice=specification)."
  value       = var.api_definition_choice == "specification"
}

output "api_definition_swagger_spec_count" {
  description = "Number of pinned OpenAPI object-store paths on the api_definition."
  value       = length(var.api_definition_swagger_specs)
}

output "api_definition_schema_origin" {
  description = "Effective api_definition schema origin (strict or mixed)."
  value       = var.api_definition_schema_origin
}

output "api_specification_validation" {
  description = "Effective api_specification validation_target_choice arm (disabled or all_spec_endpoints)."
  value       = var.api_specification_validation
}

output "api_discovery_code_scan" {
  description = "Effective api_discovery_from_code_scan arm (off, selected, or all)."
  value       = var.api_discovery_code_scan
}

output "api_discovery_code_scan_repo_count" {
  description = "Number of repositories selected for code-scan discovery (0 unless code scan is 'selected')."
  value       = var.api_discovery_code_scan == "selected" ? length(var.api_discovery_code_scan_repos) : 0
}
