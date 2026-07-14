# Shared client-matcher renderer (SP3, DRY). Consumers (api_protection_rules,
# api_rate_limit rules) read local.rendered_client_matcher and emit the matching
# dynamic arm. mode selects exactly one of any_client / ip_prefix_list /
# ip_threat_category_list; the non-selected arms render nothing.
locals {
  rendered_client_matcher = {
    use_any       = var.client_matcher.mode == "any"
    use_ip_prefix = var.client_matcher.mode == "ip_prefix"
    use_ip_threat = var.client_matcher.mode == "ip_threat"

    ip_prefixes          = var.client_matcher.ip_prefixes
    invert               = var.client_matcher.invert
    ip_threat_categories = var.client_matcher.ip_threat_categories
  }
}
