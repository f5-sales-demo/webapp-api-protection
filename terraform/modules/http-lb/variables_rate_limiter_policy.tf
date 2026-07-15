# ---------------------------------------------------------------------------
# Standalone rate-limiter policies (Coverage Batch B). Creates xcsh_rate_limiter_policy
# objects referenced by the LB rate_limit.policies arm. A policy scopes to a set of
# servers (any_server | server_name_matcher | server_selector) and carries ordered
# rules[]; each rule combines match conditions with an action:
#   action = "apply"  -> apply_rate_limiter {}   (apply the server-default limiter)
#            "bypass" -> bypass_rate_limiter {}  (skip rate limiting)
#            "custom" -> custom_rate_limiter ref -> a var.rate_limiters entry (by name)
# Rule match conditions (all optional; omit => match all):
#   asn:     "any" | "list" (asn_numbers) | "matcher" (asn_sets refs)
#   ip:      "any" | "prefix_list" (ip_prefixes) | "matcher" (ip_prefix_sets refs)
#   country: "any" | "list" (country_codes)
#   http_methods, path_* , domain_* , headers[]
# Default [] creates no policies (0-change).
# ---------------------------------------------------------------------------
variable "rate_limiter_policies" {
  description = "Standalone xcsh_rate_limiter_policy definitions (referenced by LB rate_limit.policies), keyed by name."
  type = list(object({
    name              = string
    server_scope      = optional(string, "any_server") # any_server | name_matcher | selector
    server_name_exact = optional(list(string), [])
    server_name_regex = optional(list(string), [])
    server_selector   = optional(list(string), []) # label expressions for server_selector
    rules = optional(list(object({
      name                = string
      action              = optional(string, "apply") # apply | bypass | custom
      custom_rate_limiter = optional(string)          # name of a var.rate_limiters entry (action=custom)
      # client matchers. Omit to match any: the server-default any_asn/any_ip/any_country
      # markers are import-suppressed, so an omitted matcher round-trips 0-change.
      asn            = optional(string) # list | matcher | null(omit=any)
      asn_numbers    = optional(list(number), [])
      asn_sets       = optional(list(object({ name = string, namespace = optional(string) })), [])
      ip             = optional(string) # prefix_list | matcher | null(omit=any)
      ip_prefixes    = optional(list(string), [])
      ip_invert      = optional(bool, false)
      ip_sets        = optional(list(object({ name = string, namespace = optional(string) })), [])
      country        = optional(string) # list | null(omit=any)
      countries      = optional(list(string), [])
      country_invert = optional(bool, false)
      # request matchers
      http_methods        = optional(list(string), [])
      http_methods_invert = optional(bool, false)
      path_exact          = optional(list(string), [])
      path_prefixes       = optional(list(string), [])
      path_regex          = optional(list(string), [])
      path_suffix         = optional(list(string), [])
      path_invert         = optional(bool, false)
      domain_exact        = optional(list(string), [])
      domain_regex        = optional(list(string), [])
      headers = optional(list(object({
        name         = string
        invert       = optional(bool, false)
        presence     = optional(string, "match") # present | absent | match
        exact_values = optional(list(string), [])
        regex_values = optional(list(string), [])
      })), [])
    })), [])
  }))
  default = []

  validation {
    condition     = length(var.rate_limiter_policies) == length(distinct([for p in var.rate_limiter_policies : p.name]))
    error_message = "rate_limiter_policies names must be unique."
  }

  validation {
    condition = alltrue([
      for p in var.rate_limiter_policies : contains(["any_server", "name_matcher", "selector"], p.server_scope)
    ])
    error_message = "rate_limiter_policies server_scope must be any_server, name_matcher, or selector."
  }

  validation {
    condition = alltrue([
      for p in var.rate_limiter_policies : alltrue([
        for r in p.rules : contains(["apply", "bypass", "custom"], r.action)
      ])
    ])
    error_message = "rate_limiter_policies rules.action must be apply, bypass, or custom."
  }

  validation {
    condition = alltrue([
      for p in var.rate_limiter_policies : alltrue([
        for r in p.rules : r.action != "custom" || (r.custom_rate_limiter != null && r.custom_rate_limiter != "")
      ])
    ])
    error_message = "rate_limiter_policies rules with action=custom must set custom_rate_limiter (a rate_limiters name)."
  }

  validation {
    condition = alltrue([
      for p in var.rate_limiter_policies : alltrue([
        for r in p.rules : r.asn == null || contains(["list", "matcher"], r.asn)
      ])
    ])
    error_message = "rate_limiter_policies rules.asn must be list, matcher, or null (omit=match any)."
  }

  validation {
    condition = alltrue([
      for p in var.rate_limiter_policies : alltrue([
        for r in p.rules : r.ip == null || contains(["prefix_list", "matcher"], r.ip)
      ])
    ])
    error_message = "rate_limiter_policies rules.ip must be prefix_list, matcher, or null (omit=match any)."
  }

  validation {
    condition = alltrue([
      for p in var.rate_limiter_policies : alltrue([
        for r in p.rules : r.country == null || contains(["list"], r.country)
      ])
    ])
    error_message = "rate_limiter_policies rules.country must be list or null (omit=match any)."
  }

  # F5 XC CountryCode is an enum; codes take the COUNTRY_<ISO> form (e.g. COUNTRY_US),
  # not the bare ISO code. Guard the prefix to catch the common "US"/"CA" mistake early.
  validation {
    condition = alltrue([
      for p in var.rate_limiter_policies : alltrue([
        for r in p.rules : alltrue([
          for c in r.countries : startswith(c, "COUNTRY_")
        ])
      ])
    ])
    error_message = "rate_limiter_policies rules.countries must be F5 XC CountryCode enums (COUNTRY_<ISO>, e.g. COUNTRY_US)."
  }

  validation {
    condition = alltrue([
      for p in var.rate_limiter_policies : alltrue([
        for r in p.rules : alltrue([
          for h in r.headers : contains(["present", "absent", "match"], h.presence)
        ])
      ])
    ])
    error_message = "rate_limiter_policies rules.headers.presence must be present, absent, or match."
  }

  validation {
    condition = alltrue([
      for p in var.rate_limiter_policies : alltrue([
        for r in p.rules : length(p.rules) == length(distinct([for x in p.rules : x.name]))
      ])
    ])
    error_message = "rate_limiter_policies rule names must be unique within a policy."
  }

  # A selected list-bearing matcher arm must carry a non-empty payload — an empty
  # asn_list/ip_prefix_list/country_list (or a *_matcher with no set refs) is an
  # API-invalid object. Mirrors the action=block/custom payload guards above.
  validation {
    condition = alltrue([
      for p in var.rate_limiter_policies : alltrue([
        for r in p.rules : (
          (r.asn != "list" || length(r.asn_numbers) > 0) &&
          (r.asn != "matcher" || length(r.asn_sets) > 0) &&
          (r.ip != "prefix_list" || length(r.ip_prefixes) > 0) &&
          (r.ip != "matcher" || length(r.ip_sets) > 0) &&
          (r.country != "list" || length(r.countries) > 0)
        )
      ])
    ])
    error_message = "rate_limiter_policies: a selected matcher arm needs its payload (asn=list⇒asn_numbers, asn=matcher⇒asn_sets, ip=prefix_list⇒ip_prefixes, ip=matcher⇒ip_sets, country=list⇒countries)."
  }
}
