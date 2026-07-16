# Service policies (SPol effort). Standalone xcsh_service_policy objects created by
# service_policy.tf (for_each by name), attached to the LB via the service_policies_choice
# oneof in main.tf. SPol-1 (foundation) covers the two outer oneofs — rule-handling and
# server scope — plus a minimal rule_list; per-rule matchers/actions/constraints land in
# SPol-2..4. Defaults create nothing and emit no LB block (0-change; server default
# service_policies_from_namespace, import-suppressed).

variable "service_policies" {
  description = "Standalone xcsh_service_policy objects to create. Each selects a rule-handling arm and a server-scope arm; rule_list supplies inline rules."
  type = list(object({
    name              = string
    rule_handling     = optional(string, "allow_all")  # allow_all|deny_all|allow_list|deny_list|rule_list
    server_scope      = optional(string, "any_server") # any_server|name|name_matcher|selector
    server_name       = optional(string)
    server_name_exact = optional(list(string), [])
    server_name_regex = optional(list(string), [])
    server_selector   = optional(list(string), [])
    rules = optional(list(object({
      name   = string
      action = optional(string, "DENY") # DENY|ALLOW|NEXT_POLICY (provider-validated)
    })), [])
  }))
  default = []

  validation {
    condition     = alltrue([for p in var.service_policies : contains(["allow_all", "deny_all", "allow_list", "deny_list", "rule_list"], p.rule_handling)])
    error_message = "each service_policies[].rule_handling must be allow_all, deny_all, allow_list, deny_list, or rule_list."
  }

  validation {
    condition     = alltrue([for p in var.service_policies : contains(["any_server", "name", "name_matcher", "selector"], p.server_scope)])
    error_message = "each service_policies[].server_scope must be any_server, name, name_matcher, or selector."
  }

  # rule_list is the only arm that carries rules; a stray rules list on another arm is a
  # config error (the rule would be silently dropped).
  validation {
    condition     = alltrue([for p in var.service_policies : length(coalesce(p.rules, [])) == 0 || p.rule_handling == "rule_list"])
    error_message = "service_policies[].rules is only valid when rule_handling=\"rule_list\"."
  }
}

variable "service_policies_choice" {
  description = "LB service_policies_choice arm: omit (server default service_policies_from_namespace, import-clean), none (no_service_policies), or active (active_service_policies referencing service_policy_active)."
  type        = string
  default     = "omit"

  validation {
    condition     = contains(["omit", "none", "active"], var.service_policies_choice)
    error_message = "service_policies_choice must be omit, none, or active."
  }
}

variable "service_policy_active" {
  description = "Ordered service policy names (from service_policies) to attach when service_policies_choice=active. Order is load-bearing: policies are evaluated top-to-bottom."
  type        = list(string)
  default     = []
}
