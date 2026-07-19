# Plan-level test: MUD auto-mitigation drives the LB challenge_type oneof through the unified
# `challenge` variable (CH-1) — enable / policy_based with the mitigation ref attached, or none.
# Targets ./modules/http-lb with a dummy origin — no tenant.
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
  variables { challenge = { mode = "enable", attach_malicious_user_mitigation = true } }
  assert {
    condition     = output.challenge_mode == "enable"
    error_message = "challenge mode must be enable"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.enable_challenge.malicious_user_mitigation.name == "webapp-api-protection-mud"
    error_message = "enable arm must carry the mitigation ref"
  }
}

run "challenge_policy_based_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { challenge = { mode = "policy_based", attach_malicious_user_mitigation = true } }
  assert {
    condition     = output.challenge_mode == "policy_based"
    error_message = "challenge mode must be policy_based"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.policy_based_challenge.malicious_user_mitigation.name == "webapp-api-protection-mud"
    error_message = "policy_based arm must carry the mitigation ref"
  }
}

run "challenge_none_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { challenge = { mode = "none" } }
  assert {
    condition     = output.challenge_mode == "none"
    error_message = "challenge mode none must render (no challenge arm emitted)"
  }
}
