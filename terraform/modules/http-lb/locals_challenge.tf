# CH-1: derive the effective LB challenge_type from the unified `challenge` variable and MUD.
# An explicit challenge.mode wins; otherwise MUD's presence selects the risk-based enable arm
# with the mitigation ref attached (preserving the pre-unify MUD default of enable_challenge);
# otherwise no challenge.
locals {
  challenge_explicit = var.challenge.mode != null

  challenge_mode = (
    local.challenge_explicit ? var.challenge.mode :
    var.mud_enabled ? "enable" : "none"
  )

  # Attach the malicious_user_mitigation ref: when derived from MUD, always; when explicit,
  # only if the user asked for it (validated to enable/policy_based arms in variables_challenge.tf).
  challenge_attach_mud = (
    local.challenge_explicit ? var.challenge.attach_malicious_user_mitigation : var.mud_enabled
  )
}
