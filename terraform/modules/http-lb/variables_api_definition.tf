# ---------------------------------------------------------------------------
# API Definition & spec enforcement (SP2) — inputs.
#
# Two spec-management surfaces:
#   1. xcsh_api_definition  — the API spec object (uploaded OpenAPI files +
#      inventory lists + schema origin).
#   2. LB api_definition_choice.api_specification — reference that definition and
#      choose how strictly to validate live traffic against it.
#
# Defaults keep the LB's api_definition_choice at the server default
# disable_api_definition (import-suppressed) => 0-change. The api-definition matrix
# cycles the non-default arms. See docs/superpowers/plans/sp2-findings.md.
# ---------------------------------------------------------------------------

# api_definition_choice oneof: api_specification vs disable_api_definition.
# "disable" (default) omits the block entirely => server default
# disable_api_definition (suppressed on import) => no drift. "specification"
# creates xcsh_api_definition and references it from the LB's api_specification.
variable "api_definition_choice" {
  description = "api_definition_choice: disable (no schema enforcement) or specification (enforce against an xcsh_api_definition)."
  type        = string
  default     = "disable"

  validation {
    condition     = contains(["disable", "specification"], var.api_definition_choice)
    error_message = "api_definition_choice must be \"disable\" or \"specification\"."
  }
}

# swagger_specs on xcsh_api_definition are OBJECT-STORE PATHS of uploaded OpenAPI
# files, NOT inline bodies (server validation rule requires
# /api/object_store/namespaces/{ns}/stored_objects/swagger/{name}/{version}).
# Upload once with scripts/swagger-upload.sh (content-addressed, idempotent) and
# pin the returned path here — the same seal-once-pin discipline as blindfold.
variable "api_definition_swagger_specs" {
  description = "Pinned object-store paths of uploaded OpenAPI files (from scripts/swagger-upload.sh). Empty = define the API from discovered inventory only."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for s in var.api_definition_swagger_specs :
      can(regex("^/api/object_store/namespaces/[a-z]([-a-z0-9]*[a-z0-9])?/stored_objects/swagger/", s))
    ])
    error_message = "each swagger_specs entry must be an object-store path: /api/object_store/namespaces/<ns>/stored_objects/swagger/<name>/<version> (upload via scripts/swagger-upload.sh)."
  }
}

# Inventory inclusion/exclusion + non-API endpoints. Each is a list of
# {method, path}; method is the F5 XC HTTP-method enum (default ANY).
variable "api_definition_inventory_inclusion" {
  description = "api_inventory_inclusion_list: endpoints to force INTO the API inventory ({method, path})."
  type = list(object({
    method = optional(string, "ANY")
    path   = string
  }))
  default = []

  validation {
    condition = alltrue([
      for e in var.api_definition_inventory_inclusion :
      contains(["ANY", "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH", "COPY"], e.method)
    ])
    error_message = "each inventory inclusion method must be a valid HTTP method (ANY|GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH|COPY)."
  }
}

variable "api_definition_inventory_exclusion" {
  description = "api_inventory_exclusion_list: endpoints to force OUT of the API inventory ({method, path})."
  type = list(object({
    method = optional(string, "ANY")
    path   = string
  }))
  default = []

  validation {
    condition = alltrue([
      for e in var.api_definition_inventory_exclusion :
      contains(["ANY", "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH", "COPY"], e.method)
    ])
    error_message = "each inventory exclusion method must be a valid HTTP method (ANY|GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH|COPY)."
  }
}

variable "api_definition_non_api_endpoints" {
  description = "non_api_endpoints: endpoints to mark as NON-API ({method, path})."
  type = list(object({
    method = optional(string, "ANY")
    path   = string
  }))
  default = []

  validation {
    condition = alltrue([
      for e in var.api_definition_non_api_endpoints :
      contains(["ANY", "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH", "COPY"], e.method)
    ])
    error_message = "each non_api_endpoints method must be a valid HTTP method (ANY|GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH|COPY)."
  }
}

# schema-origin oneof: strict (server default, import-suppressed => omit) vs mixed.
variable "api_definition_schema_origin" {
  description = "api_definition schema origin: strict (server default, suppressed) or mixed."
  type        = string
  default     = "strict"

  validation {
    condition     = contains(["strict", "mixed"], var.api_definition_schema_origin)
    error_message = "api_definition_schema_origin must be \"strict\" or \"mixed\"."
  }
}

# validation_target_choice arm for LB api_specification. "disabled" (default)
# defines the spec without enforcing it; "all_spec_endpoints" validates all
# endpoints (fall-through allow); "custom_list" (SP3) applies per-endpoint OpenAPI
# validation rules (validation_custom_rules) with a fall-through-allow default.
variable "api_specification_validation" {
  description = "api_specification validation_target_choice: disabled, all_spec_endpoints, or custom_list."
  type        = string
  default     = "disabled"

  validation {
    condition     = contains(["disabled", "all_spec_endpoints", "custom_list"], var.api_specification_validation)
    error_message = "api_specification_validation must be \"disabled\", \"all_spec_endpoints\", or \"custom_list\"."
  }
}

# Per-endpoint OpenAPI validation rules for the custom_list arm (SP3). Each rule
# targets an api_endpoint (method + path) with an action: block (enforce), report
# (monitor), or skip (exempt). fall-through for unlisted endpoints is allow.
variable "validation_custom_rules" {
  description = "validation_custom_list.open_api_validation_rules: list of {path, methods, action block|report|skip}."
  type = list(object({
    path    = string
    methods = optional(list(string), ["ANY"])
    action  = optional(string, "report")
  }))
  default = []

  validation {
    condition = alltrue([
      for r in var.validation_custom_rules : contains(["block", "report", "skip"], r.action)
    ])
    error_message = "each validation_custom_rules action must be block, report, or skip."
  }

  validation {
    condition = alltrue([
      for r in var.validation_custom_rules : alltrue([
        for m in r.methods :
        contains(["ANY", "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH", "COPY"], m)
      ])
    ])
    error_message = "each validation_custom_rules method must be a valid HTTP method."
  }
}
