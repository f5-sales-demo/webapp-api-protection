# CSD policy: the client_side_defense.policy JavaScript-insertion oneof (gated by csd_enabled).
# js_insert = all_pages (default; the current behavior) | disabled (disable_js_insert) | all_except
# (js_insert_all_pages_except + exclude_list). Each exclude_list entry (all_except only) needs a
# name (metadata, required by the API), a domain matcher (any/exact/regex/suffix), and a path
# matcher (exact/prefix/regex, required).
variable "csd" {
  description = "Client-Side Defense policy. js_insert = all_pages|disabled|all_except; exclude_list applies only to all_except."
  type = object({
    js_insert = optional(string, "all_pages")
    exclude_list = optional(list(object({
      name         = string
      domain_mode  = optional(string, "any") # any | exact | regex | suffix
      domain_value = optional(string)
      path_mode    = optional(string, "prefix") # exact | prefix | regex
      path_value   = string
    })), [])
  })
  default = {}

  validation {
    condition     = contains(["all_pages", "disabled", "all_except"], var.csd.js_insert)
    error_message = "csd.js_insert must be all_pages, disabled, or all_except."
  }
  validation {
    condition     = var.csd.js_insert == "all_except" || length(var.csd.exclude_list) == 0
    error_message = "csd.exclude_list is only valid when csd.js_insert = all_except."
  }
  validation {
    condition     = alltrue([for e in var.csd.exclude_list : contains(["any", "exact", "regex", "suffix"], e.domain_mode)])
    error_message = "csd.exclude_list[].domain_mode must be any, exact, regex, or suffix."
  }
  validation {
    condition     = alltrue([for e in var.csd.exclude_list : contains(["exact", "prefix", "regex"], e.path_mode)])
    error_message = "csd.exclude_list[].path_mode must be exact, prefix, or regex."
  }
  validation {
    condition     = alltrue([for e in var.csd.exclude_list : e.domain_mode == "any" || e.domain_value != null])
    error_message = "csd.exclude_list[].domain_value is required unless domain_mode = any."
  }
}
