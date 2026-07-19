# DDoS-1: L7 DDoS protection (l7_ddos_protection). Emitted only when ddos.l7_enabled = true
# (the whole block is a server-default otherwise, import-suppressed). The module emits ONLY the
# non-default arms; the server materializes the default markers (default_rps_threshold,
# clientside_action_none, mitigation_block, ddos_policy_none — all import-suppressed via provider
# >= v3.72.15 / #1155), so a minimal config round-trips 0-change:
#   rps               -> rps_threshold (custom int), else omit (server default_rps_threshold)
#   clientside_action -> js -> clientside_action_js_challenge, captcha -> _captcha_challenge,
#                        none (default) -> omit (server clientside_action_none)
# A live probe showed mitigation_block {} and ddos_policy_none {} are ALWAYS materialized together
# regardless of input — they are not a user oneof, so no ddos_policy selector is exposed.
# (ddos_policy_custom, a ref to an external xcsh_ddos_policy, is a later slice — no such object here.)
variable "ddos" {
  description = "L7 DDoS protection config. l7_enabled emits l7_ddos_protection; rps_threshold null uses the server default; clientside_action = none|js|captcha."
  type = object({
    l7_enabled         = optional(bool, false)
    rps_threshold      = optional(number)
    clientside_action  = optional(string, "none")
    cs_cookie_expiry   = optional(number)
    cs_custom_page     = optional(string)
    cs_js_script_delay = optional(number)
    # DDoS-3: manual L7 DDoS block rules. Each rule blocks a client source (the ddos_client_source
    # oneof selected by `source`): country | asn | ip | tls | ja4.
    mitigation_rules = optional(list(object({
      name                 = string
      source               = optional(string, "country") # country | asn | ip | tls | ja4
      countries            = optional(list(string), [])
      as_numbers           = optional(list(number), [])
      ip_prefixes          = optional(list(string), [])
      ip_invert            = optional(bool, false)
      tls_classes          = optional(list(string), [])
      tls_exact            = optional(list(string), [])
      ja4_exact            = optional(list(string), [])
      expiration_timestamp = optional(string)
    })), [])
  })
  default = {}

  validation {
    condition     = contains(["none", "js", "captcha"], var.ddos.clientside_action)
    error_message = "ddos.clientside_action must be none, js, or captcha."
  }
  validation {
    condition     = var.ddos.rps_threshold == null || var.ddos.rps_threshold >= 1
    error_message = "ddos.rps_threshold must be >= 1 when set."
  }
  validation {
    condition     = alltrue([for r in var.ddos.mitigation_rules : contains(["country", "asn", "ip", "tls", "ja4"], r.source)])
    error_message = "ddos.mitigation_rules[].source must be country, asn, ip, tls, or ja4."
  }
}
