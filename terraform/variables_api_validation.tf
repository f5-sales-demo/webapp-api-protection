# OpenAPI validation enforcement (Batch A) root passthrough. Validations live in the
# module (modules/http-lb/variables_api_validation.tf). Defaults keep validation as
# skip/omit so an all_spec_endpoints or custom_list config that does not opt into
# enforcement stays 0-change.
variable "api_validation_request_mode" {
  description = "all_spec_endpoints request validation: skip | block | report."
  type        = string
  default     = "skip"
}

variable "api_validation_request_properties" {
  description = "Request properties to validate when request_mode=block|report."
  type        = list(string)
  default     = ["PROPERTY_QUERY_PARAMETERS", "PROPERTY_PATH_PARAMETERS", "PROPERTY_HTTP_HEADERS", "PROPERTY_HTTP_BODY"]
}

variable "api_validation_response_mode" {
  description = "all_spec_endpoints response validation: omit | skip | block | report."
  type        = string
  default     = "omit"
}

variable "api_validation_response_properties" {
  description = "Response properties to validate when response_mode=block|report."
  type        = list(string)
  default     = ["PROPERTY_HTTP_BODY", "PROPERTY_RESPONSE_CODE"]
}

variable "api_validation_fall_through" {
  description = "Fall-through for unlisted endpoints: allow | custom."
  type        = string
  default     = "allow"
}

variable "api_validation_oversized_body" {
  description = "settings.oversized_body: omit | fail | skip."
  type        = string
  default     = "omit"
}

variable "api_validation_additional_params" {
  description = "settings query-parameter additional-params: omit | allow | disallow."
  type        = string
  default     = "omit"
}
