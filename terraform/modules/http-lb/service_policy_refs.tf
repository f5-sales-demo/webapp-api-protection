# Ref objects for the SPol-2b service_policy ref matcher arms (asn_matcher -> bgp_asn_set,
# ip_matcher -> ip_prefix_set). Created here so a rule can reference a set by name via
# asn = "matcher" / ip = "matcher". Kept as first-class module resources (for_each by name)
# so the service_policy's ref fields resolve to real objects and round-trip import-clean
# (the server-filled kind/tenant/uid are provider-computed — live-verified, no drift).
resource "xcsh_bgp_asn_set" "this" {
  for_each = { for s in var.service_policy_bgp_asn_sets : s.name => s }

  name       = each.value.name
  namespace  = var.namespace
  as_numbers = each.value.as_numbers
}

resource "xcsh_ip_prefix_set" "this" {
  for_each = { for s in var.service_policy_ip_prefix_sets : s.name => s }

  name      = each.value.name
  namespace = var.namespace

  dynamic "ipv4_prefixes" {
    for_each = each.value.ipv4_prefixes
    content {
      ipv4_prefix = ipv4_prefixes.value
    }
  }
}
