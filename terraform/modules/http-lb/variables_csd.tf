# CSD policy: the client_side_defense.policy JavaScript-insertion oneof (gated by csd_enabled).
# js_insert selects the single oneof arm (all four are mutually exclusive — API-enforced):
#   all_pages (default) | disabled (disable_js_insert) | all_except (js_insert_all_pages_except +
#   exclude_list) | insertion_rules (js_insertion_rules + rules[>=1] + optional exclude_list).
# Every matcher entry (exclude_list / insertion_rules.rules) has: name (metadata, API-required),
# optional description (metadata.description_spec), a domain matcher (any/exact/regex/suffix), and a
# path matcher (exact/prefix/regex, required).
variable "csd" {
  description = "Client-Side Defense policy. js_insert = all_pages|disabled|all_except|insertion_rules. exclude_list -> all_except; insertion_rules -> js_insertion_rules (rules required, exclude_list optional)."
  type = object({
    js_insert = optional(string, "all_pages")
    exclude_list = optional(list(object({
      name         = string
      description  = optional(string)
      domain_mode  = optional(string, "any") # any | exact | regex | suffix
      domain_value = optional(string)
      path_mode    = optional(string, "prefix") # exact | prefix | regex
      path_value   = string
    })), [])
    insertion_rules = optional(object({
      rules = optional(list(object({
        name         = string
        description  = optional(string)
        domain_mode  = optional(string, "any")
        domain_value = optional(string)
        path_mode    = optional(string, "prefix")
        path_value   = string
      })), [])
      exclude_list = optional(list(object({
        name         = string
        description  = optional(string)
        domain_mode  = optional(string, "any")
        domain_value = optional(string)
        path_mode    = optional(string, "prefix")
        path_value   = string
      })), [])
    }))
  })
  default = {}

  validation {
    condition     = contains(["all_pages", "disabled", "all_except", "insertion_rules"], var.csd.js_insert)
    error_message = "csd.js_insert must be all_pages, disabled, all_except, or insertion_rules."
  }
  validation {
    condition     = var.csd.js_insert == "all_except" || length(var.csd.exclude_list) == 0
    error_message = "csd.exclude_list is only valid when csd.js_insert = all_except."
  }
  validation {
    condition     = var.csd.js_insert == "insertion_rules" || var.csd.insertion_rules == null
    error_message = "csd.insertion_rules is only valid when csd.js_insert = insertion_rules."
  }
  validation {
    condition     = var.csd.js_insert != "insertion_rules" || (var.csd.insertion_rules != null && length(var.csd.insertion_rules.rules) > 0)
    error_message = "csd.insertion_rules.rules must have at least one rule when js_insert = insertion_rules (API min 1)."
  }
  # Matcher validations apply to every list (exclude_list + insertion_rules.rules/exclude_list).
  validation {
    condition = alltrue([
      for e in concat(
        var.csd.exclude_list,
        try(var.csd.insertion_rules.rules, []),
        try(var.csd.insertion_rules.exclude_list, []),
      ) : contains(["any", "exact", "regex", "suffix"], e.domain_mode)
    ])
    error_message = "csd matcher domain_mode must be any, exact, regex, or suffix."
  }
  validation {
    condition = alltrue([
      for e in concat(
        var.csd.exclude_list,
        try(var.csd.insertion_rules.rules, []),
        try(var.csd.insertion_rules.exclude_list, []),
      ) : contains(["exact", "prefix", "regex"], e.path_mode)
    ])
    error_message = "csd matcher path_mode must be exact, prefix, or regex."
  }
  validation {
    condition = alltrue([
      for e in concat(
        var.csd.exclude_list,
        try(var.csd.insertion_rules.rules, []),
        try(var.csd.insertion_rules.exclude_list, []),
      ) : e.domain_mode == "any" || e.domain_value != null
    ])
    error_message = "csd matcher domain_value is required unless domain_mode = any."
  }
}
