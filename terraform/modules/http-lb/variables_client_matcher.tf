# Shared client-matcher (SP3) — reused by api_protection_rules and api_rate_limit
# rules (DRY). One input + one renderer (locals_client_matcher.tf) + a dynamic block
# each consumer emits. Covers the common arms:
#   any (any_client, default) | ip_prefix (ip_prefix_list) | ip_threat (ip_threat_category_list)
# The deep/rare arms (asn_matcher/asn_list, tls_fingerprint_matcher, client_selector
# label-expressions) are deferred — see docs/superpowers/plans/sp3-findings.md.
variable "client_matcher" {
  description = "Shared client matcher. mode=any (any client), ip_prefix (IP prefix list), or ip_threat (IP threat category list)."
  type = object({
    mode                 = optional(string, "any")
    ip_prefixes          = optional(list(string), [])
    invert               = optional(bool, false)
    ip_threat_categories = optional(list(string), [])
  })
  default = { mode = "any" }

  validation {
    condition     = contains(["any", "ip_prefix", "ip_threat"], var.client_matcher.mode)
    error_message = "client_matcher.mode must be \"any\", \"ip_prefix\", or \"ip_threat\"."
  }

  validation {
    condition = alltrue([
      for c in var.client_matcher.ip_threat_categories :
      contains(["SPAM_SOURCES", "WINDOWS_EXPLOITS", "WEB_ATTACKS", "BOTNETS", "SCANNERS", "REPUTATION", "PHISHING", "PROXY", "MOBILE_THREATS", "TOR_PROXY", "DENIAL_OF_SERVICE", "NETWORK"], c)
    ])
    error_message = "each ip_threat_categories value must be a valid F5 XC IP threat category."
  }

  validation {
    condition     = var.client_matcher.mode != "ip_prefix" || length(var.client_matcher.ip_prefixes) > 0
    error_message = "client_matcher.mode=ip_prefix requires ip_prefixes."
  }

  validation {
    condition     = var.client_matcher.mode != "ip_threat" || length(var.client_matcher.ip_threat_categories) > 0
    error_message = "client_matcher.mode=ip_threat requires ip_threat_categories."
  }
}
