# LPC-4a: LB inline WAF exclusion rules (waf_exclusion.waf_exclusion_inline_rules.rules[]).
# Each rule matches a domain + path + methods and then either skips WAF entirely
# (waf_skip_processing) or excludes specific signatures / violations / attack types / bot names
# from triggering (app_firewall_detection_control). Empty list omits the whole block (0-change).

variable "waf_exclusion_rules" {
  description = "Inline WAF exclusion rules on the LB. Empty omits the waf_exclusion block."
  type = list(object({
    name                 = string                     # metadata.name
    description          = optional(string)           # metadata.description_spec
    domain               = optional(string, "any")    # any|exact|suffix (any_domain / exact_value / suffix_value)
    domain_value         = optional(string)           # value for domain=exact|suffix
    path                 = optional(string, "any")    # any|prefix|regex (any_path / path_prefix / path_regex)
    path_value           = optional(string)           # value for path=prefix|regex
    methods              = optional(list(string), []) # ANY|GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH|COPY
    expiration_timestamp = optional(string)           # RFC 3339; rule inactive after this instant
    action               = optional(string, "skip")   # skip (waf_skip_processing) | detection_control
    # detection_control exclusions (action=detection_control). context defaults CONTEXT_ANY;
    # context_name only for HEADER/COOKIE/PARAMETER contexts.
    exclude_signatures = optional(list(object({
      signature_id = number # 0 (all) or 200000001-299999999
      context      = optional(string, "CONTEXT_ANY")
      context_name = optional(string)
    })), [])
    exclude_violations = optional(list(object({
      violation    = string # VIOL_*
      context      = optional(string, "CONTEXT_ANY")
      context_name = optional(string)
    })), [])
    exclude_attack_types = optional(list(object({
      attack_type  = string # ATTACK_TYPE_*
      context      = optional(string, "CONTEXT_ANY")
      context_name = optional(string)
    })), [])
    exclude_bot_names = optional(list(string), [])
  }))
  default = []

  validation {
    condition     = alltrue([for r in var.waf_exclusion_rules : contains(["any", "exact", "suffix"], r.domain)])
    error_message = "each waf_exclusion_rules[].domain must be any, exact, or suffix."
  }
  validation {
    condition     = alltrue([for r in var.waf_exclusion_rules : contains(["any", "prefix", "regex"], r.path)])
    error_message = "each waf_exclusion_rules[].path must be any, prefix, or regex."
  }
  validation {
    condition     = alltrue([for r in var.waf_exclusion_rules : r.domain == "any" || (r.domain_value != null && r.domain_value != "")])
    error_message = "waf_exclusion_rules[].domain_value is required when domain is exact or suffix."
  }
  validation {
    condition     = alltrue([for r in var.waf_exclusion_rules : r.path == "any" || (r.path_value != null && r.path_value != "")])
    error_message = "waf_exclusion_rules[].path_value is required when path is prefix or regex."
  }
  validation {
    condition     = alltrue([for r in var.waf_exclusion_rules : contains(["skip", "detection_control"], r.action)])
    error_message = "each waf_exclusion_rules[].action must be skip or detection_control."
  }
  validation {
    condition = alltrue([for r in var.waf_exclusion_rules : alltrue([
      for m in r.methods : contains(["ANY", "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH", "COPY"], m)
    ])])
    error_message = "waf_exclusion_rules[].methods entries must be valid HTTP methods (ANY/GET/HEAD/POST/PUT/DELETE/CONNECT/OPTIONS/TRACE/PATCH/COPY)."
  }
  validation {
    condition = alltrue([for r in var.waf_exclusion_rules : alltrue(concat(
      [for e in r.exclude_signatures : contains(["CONTEXT_ANY", "CONTEXT_BODY", "CONTEXT_REQUEST", "CONTEXT_RESPONSE", "CONTEXT_PARAMETER", "CONTEXT_HEADER", "CONTEXT_COOKIE", "CONTEXT_URL", "CONTEXT_URI"], e.context)],
      [for e in r.exclude_violations : contains(["CONTEXT_ANY", "CONTEXT_BODY", "CONTEXT_REQUEST", "CONTEXT_RESPONSE", "CONTEXT_PARAMETER", "CONTEXT_HEADER", "CONTEXT_COOKIE", "CONTEXT_URL", "CONTEXT_URI"], e.context)],
      [for e in r.exclude_attack_types : contains(["CONTEXT_ANY", "CONTEXT_BODY", "CONTEXT_REQUEST", "CONTEXT_RESPONSE", "CONTEXT_PARAMETER", "CONTEXT_HEADER", "CONTEXT_COOKIE", "CONTEXT_URL", "CONTEXT_URI"], e.context)]
    ))])
    error_message = "waf_exclusion_rules[] exclusion context values must be a valid CONTEXT_* enum."
  }
  validation {
    condition = alltrue([for r in var.waf_exclusion_rules :
      r.action != "detection_control" ||
      (length(r.exclude_signatures) + length(r.exclude_violations) + length(r.exclude_attack_types) + length(r.exclude_bot_names)) > 0
    ])
    error_message = "waf_exclusion_rules[] with action=detection_control must define at least one exclusion."
  }
}
