# Root-level API Definition & spec-enforcement (SP2) inputs, passed through to
# modules/http-lb. Defaults keep api_definition_choice at the server default
# disable_api_definition (0-change). The api-definition matrix supplies these via
# -var-file per variant. Validation lives in the module.

variable "api_definition_choice" {
  description = "api_definition_choice: disable or specification."
  type        = string
  default     = "disable"
}

variable "api_definition_swagger_specs" {
  description = "Pinned object-store paths of uploaded OpenAPI files (scripts/swagger-upload.sh)."
  type        = list(string)
  default     = []
}

variable "api_definition_inventory_inclusion" {
  description = "api_inventory_inclusion_list entries ({method, path})."
  type = list(object({
    method = optional(string, "ANY")
    path   = string
  }))
  default = []
}

variable "api_definition_inventory_exclusion" {
  description = "api_inventory_exclusion_list entries ({method, path})."
  type = list(object({
    method = optional(string, "ANY")
    path   = string
  }))
  default = []
}

variable "api_definition_non_api_endpoints" {
  description = "non_api_endpoints entries ({method, path})."
  type = list(object({
    method = optional(string, "ANY")
    path   = string
  }))
  default = []
}

variable "api_definition_schema_origin" {
  description = "api_definition schema origin: strict or mixed."
  type        = string
  default     = "strict"
}

variable "api_specification_validation" {
  description = "api_specification validation_target_choice: disabled or all_spec_endpoints."
  type        = string
  default     = "disabled"
}
