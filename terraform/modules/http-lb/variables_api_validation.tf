# ---------------------------------------------------------------------------
# OpenAPI validation enforcement (Coverage Batch A). Drives validation_all_spec_endpoints
# (one validation_mode for every spec endpoint, plus fall_through + settings). Fixes the
# correctness gap where all_spec_endpoints hardcoded skip_validation (built inventory but
# enforced nothing). Only api_validation_request_properties is ALSO shared with
# validation_custom_list (whose fall_through/per-rule action stay in its own arm).
# The 8 OpenAPI properties the LB can validate (request or response side):
# PROPERTY_QUERY_PARAMETERS, PROPERTY_PATH_PARAMETERS, PROPERTY_CONTENT_TYPE,
# PROPERTY_COOKIE_PARAMETERS, PROPERTY_HTTP_HEADERS, PROPERTY_HTTP_BODY,
# PROPERTY_SECURITY_SCHEMA, PROPERTY_RESPONSE_CODE.
# ---------------------------------------------------------------------------

# Request-side enforcement for validation_all_spec_endpoints:
#   skip   -> validation_mode { skip_validation {} }               (no enforcement)
#   block  -> validation_mode_active + enforcement_block           (reject mismatches)
#   report -> validation_mode_active + enforcement_report          (log only)
variable "api_validation_request_mode" {
  description = "all_spec_endpoints request validation: skip | block | report."
  type        = string
  default     = "skip"

  validation {
    condition     = contains(["skip", "block", "report"], var.api_validation_request_mode)
    error_message = "api_validation_request_mode must be skip, block, or report."
  }
}

variable "api_validation_request_properties" {
  description = "Request properties to validate (validation_mode_active.request_validation_properties) when request_mode=block|report."
  type        = list(string)
  default     = ["PROPERTY_QUERY_PARAMETERS", "PROPERTY_PATH_PARAMETERS", "PROPERTY_HTTP_HEADERS", "PROPERTY_HTTP_BODY"]

  validation {
    condition = alltrue([
      for p in var.api_validation_request_properties :
      contains(["PROPERTY_QUERY_PARAMETERS", "PROPERTY_PATH_PARAMETERS", "PROPERTY_CONTENT_TYPE", "PROPERTY_COOKIE_PARAMETERS", "PROPERTY_HTTP_HEADERS", "PROPERTY_HTTP_BODY", "PROPERTY_SECURITY_SCHEMA", "PROPERTY_RESPONSE_CODE"], p)
    ])
    error_message = "each api_validation_request_properties value must be a valid PROPERTY_* enum."
  }

  validation {
    condition     = length(var.api_validation_request_properties) > 0
    error_message = "api_validation_request_properties must be non-empty (SizeAtLeast 1) when request validation is active."
  }
}

# Response-side enforcement (independent oneof): omit emits neither response arm.
variable "api_validation_response_mode" {
  description = "all_spec_endpoints response validation: omit | skip | block | report."
  type        = string
  default     = "omit"

  validation {
    condition     = contains(["omit", "skip", "block", "report"], var.api_validation_response_mode)
    error_message = "api_validation_response_mode must be omit, skip, block, or report."
  }
}

variable "api_validation_response_properties" {
  description = "Response properties to validate (response_validation_mode_active.response_validation_properties) when response_mode=block|report."
  type        = list(string)
  default     = ["PROPERTY_HTTP_BODY", "PROPERTY_RESPONSE_CODE"]

  validation {
    condition = alltrue([
      for p in var.api_validation_response_properties :
      contains(["PROPERTY_QUERY_PARAMETERS", "PROPERTY_PATH_PARAMETERS", "PROPERTY_CONTENT_TYPE", "PROPERTY_COOKIE_PARAMETERS", "PROPERTY_HTTP_HEADERS", "PROPERTY_HTTP_BODY", "PROPERTY_SECURITY_SCHEMA", "PROPERTY_RESPONSE_CODE"], p)
    ])
    error_message = "each api_validation_response_properties value must be a valid PROPERTY_* enum."
  }

  validation {
    condition     = length(var.api_validation_response_properties) > 0
    error_message = "api_validation_response_properties must be non-empty (SizeAtLeast 1) when response validation is active."
  }
}

# Fall-through for endpoints NOT in the spec (both arms). allow = pass through;
# custom = apply the validation_custom_rules as the fall-through rule set.
variable "api_validation_fall_through" {
  description = "Fall-through for unlisted endpoints: allow | custom."
  type        = string
  default     = "allow"

  validation {
    condition     = contains(["allow", "custom"], var.api_validation_fall_through)
    error_message = "api_validation_fall_through must be allow or custom."
  }
}

# OpenAPI settings.oversized_body handling: omit (server default) | fail | skip.
variable "api_validation_oversized_body" {
  description = "settings.oversized_body: omit | fail (oversized_body_fail_validation) | skip (oversized_body_skip_validation)."
  type        = string
  default     = "omit"

  validation {
    condition     = contains(["omit", "fail", "skip"], var.api_validation_oversized_body)
    error_message = "api_validation_oversized_body must be omit, fail, or skip."
  }
}

# settings.property_validation_settings_custom.query_parameters additional-params:
# omit (server default) | allow | disallow (extra query params not in the spec).
variable "api_validation_additional_params" {
  description = "settings query-parameter additional-params: omit | allow | disallow."
  type        = string
  default     = "omit"

  validation {
    condition     = contains(["omit", "allow", "disallow"], var.api_validation_additional_params)
    error_message = "api_validation_additional_params must be omit, allow, or disallow."
  }
}
