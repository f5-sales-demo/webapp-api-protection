# CSD-2: mitigated / allowed domain registrations (gated by csd_enabled), keyed by name. Created in
# the LB namespace, mirroring the root xcsh_protected_domain. No import round-trip (CSD domain API is
# list/create/delete only — provider Read tolerates the 501 GET-by-name, terraform-provider-xcsh#1044).
resource "xcsh_mitigated_domain" "this" {
  for_each = var.csd_enabled ? { for d in var.csd_mitigated_domains : d.name => d } : {}

  name             = each.value.name
  namespace        = var.namespace
  mitigated_domain = each.value.domain
  description      = each.value.description
  disable          = each.value.disable
  labels           = each.value.labels
  annotations      = each.value.annotations
}

resource "xcsh_allowed_domain" "this" {
  for_each = var.csd_enabled ? { for d in var.csd_allowed_domains : d.name => d } : {}

  name           = each.value.name
  namespace      = var.namespace
  allowed_domain = each.value.domain
  description    = each.value.description
  disable        = each.value.disable
  labels         = each.value.labels
  annotations    = each.value.annotations
}
