# OpenAPI validation enforcement (Batch A) outputs — echo the effective config so
# plan-tests can assert arm selection (the deeply-nested dynamic blocks are otherwise
# not observable at plan time; a clean plan with a given mode proves the block renders).
output "api_validation_request_mode" {
  description = "Effective all_spec_endpoints request validation mode."
  value       = var.api_validation_request_mode
}

output "api_validation_response_mode" {
  description = "Effective all_spec_endpoints response validation mode."
  value       = var.api_validation_response_mode
}

output "api_validation_fall_through" {
  description = "Effective validation fall-through (allow | custom)."
  value       = var.api_validation_fall_through
}

output "api_validation_enforces" {
  description = "Whether all_spec_endpoints validation actually enforces (request or response active), i.e. not skip/omit only. False unless api_specification_validation=all_spec_endpoints is the active arm."
  value       = var.api_specification_validation == "all_spec_endpoints" && (local.rendered_api_validation.req_active || (local.rendered_api_validation.resp_emit && local.rendered_api_validation.resp_active))
}
