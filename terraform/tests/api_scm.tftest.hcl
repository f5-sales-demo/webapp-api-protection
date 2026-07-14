# Plan-level tests for the SCM code_base_integration (github) — access_token via the
# reusable clear/blindfold SecretType convention. Targets ./modules/http-lb, dummy origin.
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

run "scm_disabled_default" {
  command = plan
  module { source = "./modules/http-lb" }
  assert {
    condition     = output.code_base_integration_enabled == false
    error_message = "code_base_integration must be disabled by default (0-change)"
  }
}

run "scm_github_clear_token" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    code_base_integration_enabled      = true
    code_base_integration_username     = "f5-sales-demo-bot"
    code_base_integration_access_token = { method = "clear", plaintext = "ghp_example_token" }
  }
  assert {
    condition     = output.code_base_integration_token_method == "clear"
    error_message = "clear access_token arm must render"
  }
}

run "scm_github_blindfold_token" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    code_base_integration_enabled      = true
    code_base_integration_username     = "f5-sales-demo-bot"
    code_base_integration_access_token = { method = "blindfold", location = "string:///eyJrZXlfdmVyc2lvbiI6MX0=" }
  }
  assert {
    condition     = output.code_base_integration_token_method == "blindfold"
    error_message = "blindfold access_token arm must render"
  }
}

run "scm_enabled_without_token_fails" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    code_base_integration_enabled      = true
    code_base_integration_username     = "f5-sales-demo-bot"
    code_base_integration_access_token = { method = "clear", plaintext = null }
  }
  expect_failures = [xcsh_code_base_integration.github]
}
