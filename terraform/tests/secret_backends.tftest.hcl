# Plan-level tests for the clear/blindfold external secret-backend fields (Coverage
# Batch G): store_provider/decryption_provider (blindfold) + provider_ref (clear),
# threaded through the shared rendered_secret convention (crawler + SCM). Asserted on
# the SCM consumer (accessible path); the crawler uses the identical local. Targets
# ./modules/http-lb.
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

run "scm_blindfold_backend_fields_render" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    code_base_integration_enabled  = true
    code_base_integration_username = "f5-sales-demo-bot"
    code_base_integration_access_token = {
      method              = "blindfold"
      location            = "string:///eyJrZXlfdmVyc2lvbiI6MX0="
      store_provider      = "corp-secret-store"
      decryption_provider = "corp-kms"
    }
  }
  assert {
    condition     = xcsh_code_base_integration.this[0].code_base_integration.github.access_token.blindfold_secret_info.store_provider == "corp-secret-store" && xcsh_code_base_integration.this[0].code_base_integration.github.access_token.blindfold_secret_info.decryption_provider == "corp-kms"
    error_message = "blindfold store_provider + decryption_provider must render"
  }
}

run "scm_clear_provider_ref_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    code_base_integration_enabled  = true
    code_base_integration_username = "f5-sales-demo-bot"
    code_base_integration_access_token = {
      method       = "clear"
      plaintext    = "ghp_example"
      provider_ref = "corp-secret-provider"
    }
  }
  assert {
    condition     = xcsh_code_base_integration.this[0].code_base_integration.github.access_token.clear_secret_info.provider_ref == "corp-secret-provider"
    error_message = "clear provider_ref must render"
  }
}

# Regression: base clear/blindfold (no backend fields) still render with null backends.
run "scm_base_secret_no_backends" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    code_base_integration_enabled      = true
    code_base_integration_username     = "f5-sales-demo-bot"
    code_base_integration_access_token = { method = "clear", plaintext = "ghp_example" }
  }
  assert {
    condition     = xcsh_code_base_integration.this[0].code_base_integration.github.access_token.clear_secret_info.provider_ref == null
    error_message = "base clear secret must render with null provider_ref (0-change for existing configs)"
  }
}

# --- validation failures: backend fields only with the matching method ---

run "scm_rejects_store_provider_on_clear" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    code_base_integration_enabled      = true
    code_base_integration_username     = "f5-sales-demo-bot"
    code_base_integration_access_token = { method = "clear", plaintext = "x", store_provider = "s" }
  }
  expect_failures = [var.code_base_integration_access_token]
}

run "scm_rejects_provider_ref_on_blindfold" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    code_base_integration_enabled      = true
    code_base_integration_username     = "f5-sales-demo-bot"
    code_base_integration_access_token = { method = "blindfold", location = "string:///x", provider_ref = "p" }
  }
  expect_failures = [var.code_base_integration_access_token]
}

run "crawler_rejects_decryption_provider_on_clear" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_crawler_domains  = [{ domain = "api.f5-sales-demo.com", user = "probe" }]
    api_crawler_password = { method = "clear", plaintext = "x", decryption_provider = "kms" }
  }
  expect_failures = [var.api_crawler_password]
}
