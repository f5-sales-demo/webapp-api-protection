# Plan-level test: the MUD option variables expose sensible defaults and render.
# Targets ./modules/http-lb directly with a dummy origin — no tenant contact.
run "mud_defaults_render" {
  command = plan

  module {
    source = "./modules/http-lb"
  }

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

  assert {
    condition     = output.mud_user_id == "client_ip"
    error_message = "default MUD user-id method must be client_ip"
  }

  assert {
    condition     = output.mud_challenge_mode == "enable_challenge"
    error_message = "default MUD challenge mode must be enable_challenge"
  }

  assert {
    condition     = output.mud_mitigation.high == "block_temporarily"
    error_message = "default high-threat action must be block_temporarily"
  }
}
