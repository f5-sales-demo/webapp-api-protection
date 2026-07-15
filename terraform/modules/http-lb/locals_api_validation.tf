# Rendered OpenAPI-validation arm selectors (Batch A, DRY). Both api_specification
# validation arms consume local.rendered_api_validation for validation_mode / settings
# / fall_through so the two stay consistent and neither hardcodes skip.
locals {
  rendered_api_validation = {
    # request-side oneof
    req_skip   = var.api_validation_request_mode == "skip"
    req_active = contains(["block", "report"], var.api_validation_request_mode)
    req_block  = var.api_validation_request_mode == "block"
    req_report = var.api_validation_request_mode == "report"
    req_props  = var.api_validation_request_properties

    # response-side oneof (omit => emit neither arm)
    resp_emit   = var.api_validation_response_mode != "omit"
    resp_skip   = var.api_validation_response_mode == "skip"
    resp_active = contains(["block", "report"], var.api_validation_response_mode)
    resp_block  = var.api_validation_response_mode == "block"
    resp_report = var.api_validation_response_mode == "report"
    resp_props  = var.api_validation_response_properties

    # fall-through
    ft_custom = var.api_validation_fall_through == "custom"

    # settings (emit the settings block only if any knob is set)
    settings_emit   = var.api_validation_oversized_body != "omit" || var.api_validation_additional_params != "omit"
    oversized_fail  = var.api_validation_oversized_body == "fail"
    oversized_skip  = var.api_validation_oversized_body == "skip"
    params_custom   = var.api_validation_additional_params != "omit"
    params_allow    = var.api_validation_additional_params == "allow"
    params_disallow = var.api_validation_additional_params == "disallow"
  }
}
