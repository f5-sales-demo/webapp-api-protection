# Root passthrough for App API Groups (Coverage Batch F). Thin passthrough: the full
# object type + validation live in the module (modules/http-lb/variables_app_api_group.tf).
variable "app_api_groups" {
  description = "xcsh_app_api_group definitions passthrough (typed+validated in the module)."
  type        = any
  default     = []
}
