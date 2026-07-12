# Plan-level test: the LB challenge integration is selected by mud_challenge_mode —
# enable_challenge, policy_based_challenge, or none (neither block). Each mode must
# produce a valid plan. Targets ./modules/http-lb with a dummy origin — no tenant.
variables {
  namespace         = "webapp-api-protection"
  lb_domains        = ["www.f5-sales-demo.com"]
  origin_ip         = "203.0.113.10"
  origin_port       = 80
  health_check_path = "/health"
  labels            = {}
  waf_mode          = "blocking"
  csd_enabled       = false
  mud_enabled       = true
}

run "challenge_enable_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { mud_challenge_mode = "enable_challenge" }
  assert {
    condition     = output.mud_challenge_mode == "enable_challenge"
    error_message = "challenge mode must be enable_challenge"
  }
}

run "challenge_policy_based_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { mud_challenge_mode = "policy_based_challenge" }
  assert {
    condition     = output.mud_challenge_mode == "policy_based_challenge"
    error_message = "challenge mode must be policy_based_challenge"
  }
}

run "challenge_none_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { mud_challenge_mode = "none" }
  assert {
    condition     = output.mud_challenge_mode == "none"
    error_message = "challenge mode none must render (neither challenge block emitted)"
  }
}
