# CSD-2: standalone CSD domain registrations beyond the required protected_domain (which stays at
# the root, as the eTLD+1 prerequisite that must exist before the LB enables CSD). These are optional
# CSD tuning, created in the LB namespace and gated by csd_enabled:
#   mitigated_domains — block a detected third-party domain (drives CSD blocked_scripts/mitigated_domains)
#   allowed_domains   — allowlist a domain so CSD does not flag it
# Both take a specific host (not an eTLD+1); the CSD domain API is list/create/delete only (GET-by-name
# 501; domain values tenant-globally-unique -> 409 on re-create), so there is no whole-object import.
variable "csd_mitigated_domains" {
  description = "CSD mitigated (blocked) domains. Each: name (DNS-1123) + domain (specific host, e.g. cdn.jsdelivr.net)."
  type = list(object({
    name        = string
    domain      = string
    description = optional(string)
    disable     = optional(bool, false)
    labels      = optional(map(string), {})
    annotations = optional(map(string), {})
  }))
  default = []

  validation {
    condition     = alltrue([for d in var.csd_mitigated_domains : length(d.domain) > 0 && length(d.domain) <= 256])
    error_message = "csd_mitigated_domains[].domain must be a non-empty host (<= 256 chars)."
  }
}

variable "csd_allowed_domains" {
  description = "CSD allowed (allowlisted) domains. Each: name (DNS-1123) + domain (specific host)."
  type = list(object({
    name        = string
    domain      = string
    description = optional(string)
    disable     = optional(bool, false)
    labels      = optional(map(string), {})
    annotations = optional(map(string), {})
  }))
  default = []

  validation {
    condition     = alltrue([for d in var.csd_allowed_domains : length(d.domain) > 0 && length(d.domain) <= 256])
    error_message = "csd_allowed_domains[].domain must be a non-empty host (<= 256 chars)."
  }
}
