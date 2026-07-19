# CH-1: unified challenge configuration. Owns the LB challenge_type oneof
# (no_challenge | enable_challenge | js_challenge | captcha_challenge | policy_based_challenge).
# MUD's auto-mitigation is one configuration of this oneof (enable/policy_based with the
# malicious_user_mitigation ref attached), not a separate variable — see locals_challenge.tf
# for how the effective mode is derived when this is left unset.
variable "challenge" {
  description = <<-EOT
    LB challenge configuration. mode selects the challenge_type oneof arm:
      none          -> no challenge (server default no_challenge; omitted)
      enable        -> enable_challenge (risk-based; carries the MUD mitigation ref)
      js            -> js_challenge (JavaScript challenge for ALL traffic)
      captcha       -> captcha_challenge (CAPTCHA for ALL traffic)
      policy_based  -> policy_based_challenge (rich body added in CH-2/CH-3)
    cookie_expiry/custom_page apply to js + captcha; js_script_delay to js only.
    attach_malicious_user_mitigation attaches the mitigation ref (enable/policy_based only,
    requires mud_enabled). When mode is null the effective mode is derived from mud_enabled.
  EOT
  type = object({
    mode                             = optional(string)
    cookie_expiry                    = optional(number)
    custom_page                      = optional(string)
    js_script_delay                  = optional(number)
    attach_malicious_user_mitigation = optional(bool, false)
  })
  default = {}

  validation {
    condition     = var.challenge.mode == null || contains(["none", "enable", "js", "captcha", "policy_based"], var.challenge.mode)
    error_message = "challenge.mode must be one of none, enable, js, captcha, policy_based."
  }
  validation {
    condition     = !var.challenge.attach_malicious_user_mitigation || contains(["enable", "policy_based"], coalesce(var.challenge.mode, "none"))
    error_message = "challenge.attach_malicious_user_mitigation is valid only for mode enable or policy_based."
  }
}
