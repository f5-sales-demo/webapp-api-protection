# Plan-level tests for API Testing (SP4): LB api_testing_choice inline block, the
# standalone xcsh_api_testing resource + schedule oneof, and the credential auth oneof
# (api_key/basic_auth/bearer_token — the only valid F5 XC credentials_choice members;
# admin/standard 400 and are excluded) with clear/blindfold SecretType. Every domain
# requires >=1 credential and every credential a secret (verified live). Targets
# ./modules/http-lb with a dummy origin.
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

# --- Defaults: off + 0-change shape ---
run "api_testing_default_disabled" {
  command = plan
  module { source = "./modules/http-lb" }
  assert {
    condition     = output.api_testing_choice == "disable" && output.api_testing_standalone_created == false
    error_message = "API testing must default to disabled with no standalone resource"
  }
  assert {
    condition     = output.api_testing_schedule == "every_week" && output.api_testing_domain_count == 0
    error_message = "schedule must default to the suppressed every_week and no domains"
  }
}

# --- LB inline api_testing block ---
run "api_testing_lb_enabled_api_key" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_testing_choice              = "enabled"
    api_testing_custom_header_value = "sp4-tests"
    api_testing_domains = [{
      domain = "api.f5-sales-demo.com"
      credentials = [{
        credential_name = "c-key"
        auth_type       = "api_key"
        api_key_name    = "X-API-Key"
        secret          = { method = "clear", plaintext = "s3cr3t" }
      }]
    }]
  }
  assert {
    condition     = output.api_testing_choice == "enabled" && output.api_testing_credential_count == 1
    error_message = "LB api_testing block must render with one api_key credential"
  }
}

# --- Standalone resource + schedule arms ---
run "api_testing_standalone_every_day_basic_auth" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_testing_standalone_enabled = true
    api_testing_schedule           = "every_day"
    api_testing_domains = [{
      domain = "api.f5-sales-demo.com"
      credentials = [{
        credential_name = "c-basic"
        auth_type       = "basic_auth"
        user            = "tester"
        secret          = { method = "clear", plaintext = "pw" }
      }]
    }]
  }
  assert {
    condition     = output.api_testing_standalone_created == true && output.api_testing_schedule == "every_day"
    error_message = "standalone xcsh_api_testing with every_day schedule must render"
  }
}

run "api_testing_standalone_every_month_bearer_blindfold" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_testing_standalone_enabled = true
    api_testing_schedule           = "every_month"
    api_testing_domains = [{
      domain = "api.f5-sales-demo.com"
      credentials = [{
        credential_name = "c-bearer"
        auth_type       = "bearer_token"
        secret          = { method = "blindfold", location = "string:///UFJFU0VBTEVE" }
      }]
    }]
  }
  assert {
    condition     = output.api_testing_schedule == "every_month" && output.api_testing_credential_count == 1
    error_message = "every_month + bearer_token blindfold credential must render"
  }
}

# --- both surfaces at once ---
run "api_testing_both_surfaces" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_testing_choice             = "enabled"
    api_testing_standalone_enabled = true
    api_testing_domains = [{
      domain = "api.f5-sales-demo.com"
      credentials = [{
        credential_name = "c-key"
        auth_type       = "api_key"
        api_key_name    = "X-API-Key"
        secret          = { method = "clear", plaintext = "s3cr3t" }
      }]
    }]
  }
  assert {
    condition     = output.api_testing_choice == "enabled" && output.api_testing_standalone_created == true
    error_message = "both surfaces must render from one shared domains/credentials input"
  }
}

# --- Validation failures ---
run "api_testing_rejects_bad_choice" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { api_testing_choice = "on" }
  expect_failures = [var.api_testing_choice]
}

run "api_testing_rejects_bad_schedule" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { api_testing_schedule = "hourly" }
  expect_failures = [var.api_testing_schedule]
}

run "api_testing_rejects_bad_auth_type" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_testing_domains = [{
      domain      = "api.f5-sales-demo.com"
      credentials = [{ credential_name = "c", auth_type = "admin", secret = { method = "clear", plaintext = "x" } }]
    }]
  }
  expect_failures = [var.api_testing_domains]
}

run "api_testing_rejects_lb_enabled_without_domains" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { api_testing_choice = "enabled" } # api_testing_domains defaults to []
  expect_failures = [xcsh_http_loadbalancer.this]
}

run "api_testing_rejects_domain_without_credentials" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_testing_domains = [{ domain = "api.f5-sales-demo.com", credentials = [] }]
  }
  expect_failures = [var.api_testing_domains]
}

run "api_testing_rejects_basic_auth_without_user" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_testing_domains = [{
      domain      = "api.f5-sales-demo.com"
      credentials = [{ credential_name = "c", auth_type = "basic_auth", secret = { method = "clear", plaintext = "pw" } }]
    }]
  }
  expect_failures = [var.api_testing_domains]
}

run "api_testing_rejects_api_key_without_name" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_testing_domains = [{
      domain      = "api.f5-sales-demo.com"
      credentials = [{ credential_name = "c", auth_type = "api_key", secret = { method = "clear", plaintext = "x" } }]
    }]
  }
  expect_failures = [var.api_testing_domains]
}

run "api_testing_rejects_clear_without_plaintext" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_testing_domains = [{
      domain      = "api.f5-sales-demo.com"
      credentials = [{ credential_name = "c", auth_type = "bearer_token", secret = { method = "clear" } }]
    }]
  }
  expect_failures = [var.api_testing_domains]
}

run "api_testing_rejects_blindfold_without_location" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_testing_domains = [{
      domain      = "api.f5-sales-demo.com"
      credentials = [{ credential_name = "c", auth_type = "bearer_token", secret = { method = "blindfold" } }]
    }]
  }
  expect_failures = [var.api_testing_domains]
}
