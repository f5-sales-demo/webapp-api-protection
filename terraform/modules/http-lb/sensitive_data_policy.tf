# xcsh_sensitive_data_policy (SP3) — the standalone policy the LB's
# sensitive_data_policy_choice=custom references. Created iff that same choice is
# "custom" (single knob, mirroring api_definition.tf), so the resource and the LB
# reference can never desync. compliances / disabled_predefined_data_types are set
# only when non-empty so the empty-list default matches the server default
# (import-clean). custom_data_types (object-refs to xcsh_custom_data_type) are
# deferred this cycle — see docs/superpowers/plans/sp3-findings.md.
resource "xcsh_sensitive_data_policy" "this" {
  count     = var.sensitive_data_policy_choice == "custom" ? 1 : 0
  name      = "${var.namespace}-sensitive-data"
  namespace = var.namespace

  compliances                    = length(var.sensitive_data_compliances) > 0 ? var.sensitive_data_compliances : null
  disabled_predefined_data_types = length(var.sensitive_data_disabled_predefined) > 0 ? var.sensitive_data_disabled_predefined : null
}
