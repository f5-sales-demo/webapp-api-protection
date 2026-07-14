# Plan-level tests for API Definition & spec enforcement (SP2): the
# api_definition_choice / api_specification oneof, xcsh_api_definition, and the
# api_discovery_from_code_scan wiring. Targets ./modules/http-lb, dummy origin.
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

run "api_definition_disabled_default" {
  command = plan
  module { source = "./modules/http-lb" }
  assert {
    condition     = output.api_definition_choice == "disable" && output.api_definition_created == false
    error_message = "api_definition must default to disable with no definition created (0-change)"
  }
  assert {
    condition     = output.api_discovery_code_scan == "off"
    error_message = "code scan must default to off"
  }
}

run "api_specification_validation_disabled" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_definition_choice              = "specification"
    api_specification_validation       = "disabled"
    api_definition_inventory_inclusion = [{ method = "GET", path = "/health" }]
  }
  assert {
    condition     = output.api_definition_created == true && output.api_specification_validation == "disabled"
    error_message = "specification + validation_disabled must render an api_definition"
  }
}

run "api_specification_validation_all_spec_endpoints" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_definition_choice        = "specification"
    api_specification_validation = "all_spec_endpoints"
  }
  assert {
    condition     = output.api_specification_validation == "all_spec_endpoints"
    error_message = "all_spec_endpoints validation arm must render"
  }
}

run "api_definition_schema_origin_mixed" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_definition_choice        = "specification"
    api_definition_schema_origin = "mixed"
  }
  assert {
    condition     = output.api_definition_schema_origin == "mixed"
    error_message = "mixed schema origin must render"
  }
}

run "api_definition_swagger_specs_pinned_path" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_definition_choice = "specification"
    api_definition_swagger_specs = [
      "/api/object_store/namespaces/webapp-api-protection/stored_objects/swagger/vampi/v1-26-07-14"
    ]
  }
  assert {
    condition     = output.api_definition_swagger_spec_count == 1
    error_message = "a pinned object-store swagger path must be accepted"
  }
}

run "api_definition_swagger_specs_rejects_inline_body" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_definition_choice        = "specification"
    api_definition_swagger_specs = ["{\"openapi\":\"3.0.0\"}"]
  }
  expect_failures = [var.api_definition_swagger_specs]
}

run "api_definition_inventory_rejects_bad_method" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_definition_choice              = "specification"
    api_definition_inventory_inclusion = [{ method = "FETCH", path = "/x" }]
  }
  expect_failures = [var.api_definition_inventory_inclusion]
}

run "code_scan_selected_to_api_catalog" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    code_base_integration_enabled      = true
    code_base_integration_username     = "f5-sales-demo-bot"
    code_base_integration_access_token = { method = "clear", plaintext = "ghp_example_token" }
    api_discovery_code_scan            = "selected"
    api_discovery_code_scan_repos      = ["api-catalog"]
  }
  assert {
    condition     = output.api_discovery_code_scan == "selected" && output.api_discovery_code_scan_repo_count == 1
    error_message = "selected code scan over api-catalog must render"
  }
}

run "code_scan_all_repos" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    code_base_integration_enabled      = true
    code_base_integration_username     = "f5-sales-demo-bot"
    code_base_integration_access_token = { method = "clear", plaintext = "ghp_example_token" }
    api_discovery_code_scan            = "all"
  }
  assert {
    condition     = output.api_discovery_code_scan == "all" && output.api_discovery_code_scan_repo_count == 0
    error_message = "all_repos code scan must render (repo_count 0 since no explicit repo list)"
  }
}

run "code_scan_requires_integration" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_discovery_code_scan       = "selected"
    api_discovery_code_scan_repos = ["api-catalog"]
  }
  expect_failures = [xcsh_http_loadbalancer.this]
}

run "code_scan_selected_requires_repos" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    code_base_integration_enabled      = true
    code_base_integration_username     = "f5-sales-demo-bot"
    code_base_integration_access_token = { method = "clear", plaintext = "ghp_example_token" }
    api_discovery_code_scan            = "selected"
    api_discovery_code_scan_repos      = []
  }
  expect_failures = [xcsh_http_loadbalancer.this]
}

run "code_scan_requires_discovery_enabled" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    code_base_integration_enabled      = true
    code_base_integration_username     = "f5-sales-demo-bot"
    code_base_integration_access_token = { method = "clear", plaintext = "ghp_example_token" }
    api_discovery_choice               = "disable"
    api_discovery_code_scan            = "all"
  }
  expect_failures = [xcsh_http_loadbalancer.this]
}
