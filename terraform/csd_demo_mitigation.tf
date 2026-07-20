# CSD demo — Phase 3 (Mitigate) reproduced in Terraform.
#
# The CSD docs demo (csd/docs/en/demo/phase-3-mitigate.mdx) applies mitigations by POSTing the
# attack's third-party domains to the CSD mitigated_domains API. This reproduces that step
# declaratively: when csd_demo_mitigation_enabled = true, the six domains the /csd-demo/ page
# loads/exfils to (4 CDN supply-chain domains + 2 external exfil endpoints) are registered as
# xcsh_mitigated_domain resources (via the http-lb module's csd_mitigated_domains input).
#
# This is the mitigate/teardown toggle: set true to apply the mitigations (Phase 3 Step 3), leave
# false (default) to remove them (Phase 4 teardown of mitigations). CSD mitigation blocks SCRIPT
# LOADING from mitigated domains (clears the <script> src) — so it meaningfully blocks the 4 CDN
# supply-chain scripts. The 2 exfil domains are included for demo fidelity (they appear in the
# mitigated list) though CSD does not intercept fetch() (per the docs).
#
# csd_demo_mitigated_domains uses the SAME type as csd_mitigated_domains so the selection in
# main.tf (enabled ? demo : user) unifies cleanly. httpbin.org note: the CSD API rejects a bare
# eTLD+1 as mitigated_domain ("cannot derive eTLD+1"), so the identifier is httpbin.org while the
# mitigated_domain value is www.httpbin.org — matching the docs' Phase 3 Step 3 exception.

variable "csd_demo_mitigation_enabled" {
  description = "Apply the CSD demo Phase 3 mitigations (register the /csd-demo/ third-party domains as CSD mitigated_domains). false = teardown/no mitigations."
  type        = bool
  default     = false
}

variable "csd_demo_mitigated_domains" {
  description = "The /csd-demo/ third-party domains registered when csd_demo_mitigation_enabled = true (4 CDN supply-chain + 2 external exfil). Same shape as csd_mitigated_domains."
  type = list(object({
    name        = string
    domain      = string
    description = optional(string)
    disable     = optional(bool, false)
    labels      = optional(map(string), {})
    annotations = optional(map(string), {})
  }))
  # Names are DNS-1123 labels (no dots — provider requirement); domain carries the real host.
  default = [
    { name = "block-jsdelivr", domain = "cdn.jsdelivr.net", description = "CSD demo: CDN supply-chain script domain" },
    { name = "block-esm-sh", domain = "esm.sh", description = "CSD demo: CDN supply-chain script domain" },
    { name = "block-unpkg", domain = "unpkg.com", description = "CSD demo: CDN supply-chain script domain" },
    { name = "block-jspm", domain = "ga.jspm.io", description = "CSD demo: CDN supply-chain script domain" },
    { name = "block-httpbin", domain = "www.httpbin.org", description = "CSD demo: external exfil endpoint (eTLD+1 -> www host)" },
    { name = "block-jsonplaceholder", domain = "jsonplaceholder.typicode.com", description = "CSD demo: external exfil endpoint" },
  ]
}
