# CSD demo — Phase 3 (Mitigate) reproduced in Terraform.
#
# The CSD docs demo (csd/docs/en/demo/phase-3-mitigate.mdx) applies mitigations by registering the
# attacking third-party script's host as a CSD mitigated_domain. This reproduces that step
# declaratively: when csd_demo_mitigation_enabled = true, the cdn-simulator edge host — which serves
# the behaving skimmer (/csd-demo/checkout.js, a genuine third-party <script src>) — is registered as
# an xcsh_mitigated_domain (via the http-lb module's csd_mitigated_domains input).
#
# The mitigated host is DERIVED from var.csd_cdn_simulator_host, the same single source of truth that
# the origin's checkout page loads the skimmer from. There is exactly one behaving third-party script
# in the demo (checkout.js reads payment fields), so exactly one host to detect and mitigate; the
# other libraries the page loads are benign (never read fields) and CSD does not flag them.
#
# This is the mitigate/teardown toggle: set true to apply the mitigation (Phase 3 Step 3), leave
# false (default) to remove it (Phase 4 teardown, and the "before" detection baseline). CSD
# mitigation blocks SCRIPT LOADING from the mitigated host (clears the <script> src), so it blocks
# the third-party skimmer — the detect -> mitigate -> block cycle.

variable "csd_demo_mitigation_enabled" {
  description = "Apply the CSD demo Phase 3 mitigation (register the cdn-simulator skimmer host as a CSD mitigated_domain). false = teardown/no mitigation (also the 'before' detection baseline)."
  type        = bool
  default     = false
}

locals {
  # Single source of truth: the host we load the behaving skimmer from (var.csd_cdn_simulator_host)
  # is exactly the host CSD detects and we mitigate. name is a stable DNS-1123 label (no dots);
  # domain carries the real FQDN (validated as an FQDN on the variable). Built to the same object
  # shape as var.csd_mitigated_domains so main.tf's enabled ? demo : user selection type-checks.
  csd_demo_mitigated_domains = [
    {
      name        = "block-cdn-simulator"
      domain      = var.csd_cdn_simulator_host
      description = "CSD demo: third-party CDN host serving the behaving skimmer (checkout.js from cdn-simulator)"
      disable     = false
      labels      = tomap({})
      annotations = tomap({})
    }
  ]
}
