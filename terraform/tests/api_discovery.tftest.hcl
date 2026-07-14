# Plan-level tests: every api_discovery_choice arm + nested discovery sub-option
# renders a valid provider value. Targets ./modules/http-lb with a dummy origin
# (no tenant contact). Defaults reproduce the bare enable_api_discovery {} block.
variables {
  namespace         = "webapp-api-protection"
  lb_domains        = ["www.f5-sales-demo.com"]
  origin_ip         = "203.0.113.10"
  origin_port       = 80
  health_check_path = "/health"
  labels            = {}
  csd_enabled       = false
  mud_enabled       = false
}

run "discovery_default_is_enable" {
  command = plan
  module { source = "./modules/http-lb" }
  assert {
    condition     = output.api_discovery_choice == "enable"
    error_message = "default api_discovery_choice must be enable (0-change)"
  }
}

run "discovery_disable_arm" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { api_discovery_choice = "disable" }
  assert {
    condition     = output.api_discovery_choice == "disable"
    error_message = "disable_api_discovery arm must render"
  }
}

run "discovery_learn_from_redirect_enable" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { api_discovery_learn_from_redirect = "enable" }
  assert {
    condition     = output.api_discovery_learn_from_redirect == "enable"
    error_message = "enable_learn_from_redirect_traffic arm must render"
  }
}

run "discovery_purge_duration" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { api_discovery_purge_duration = 7 }
  assert {
    condition     = output.api_discovery_purge_duration == 7
    error_message = "discovered_api_settings purge duration must render"
  }
}

# Server rule is 1..7 days; an out-of-range value must fail validation (fail fast at
# plan) rather than reach the API as a 400 BAD_REQUEST.
run "discovery_purge_duration_out_of_range" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { api_discovery_purge_duration = 48 }
  expect_failures = [var.api_discovery_purge_duration]
}

run "discovery_auth_mode_default" {
  command = plan
  module { source = "./modules/http-lb" }
  assert {
    condition     = output.api_discovery_auth_mode == "default"
    error_message = "default api_discovery_auth_mode must be the suppressed default arm"
  }
}

run "discovery_auth_mode_custom" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_discovery_auth_mode         = "custom"
    api_discovery_custom_auth_types = [{ parameter_name = "X-API-Key", parameter_type = "HEADER" }]
  }
  assert {
    condition     = output.api_discovery_custom_auth_type_count == 1
    error_message = "custom_api_auth_discovery with a custom auth type must render"
  }
}

