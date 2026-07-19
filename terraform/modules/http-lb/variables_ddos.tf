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
}
