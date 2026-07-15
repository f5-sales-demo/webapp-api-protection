# Plan-level tests for OpenAPI validation enforcement (Batch A): validation_mode
# (request/response skip|block|report), fall_through (allow|custom), and settings
# (oversized-body, additional-params) on api_specification. Targets ./modules/http-lb.
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

# Default: all_spec_endpoints with no enforcement opt-in = skip (the pre-fix behavior,
# now explicit + advertised via the output, not silently hardcoded).
run "validation_default_skip_no_enforce" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_definition_choice        = "specification"
    api_specification_validation = "all_spec_endpoints"
  }
  assert {
    condition     = output.api_validation_enforces == false && output.api_validation_request_mode == "skip"
    error_message = "default all_spec_endpoints must render skip (no enforcement) explicitly"
  }
}

# The correctness fix: request block/report actually enforces.
run "validation_request_block_enforces" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_definition_choice        = "specification"
    api_specification_validation = "all_spec_endpoints"
    api_validation_request_mode  = "block"
  }
  assert {
    condition     = output.api_validation_enforces == true
    error_message = "request_mode=block must enforce (validation_mode_active + enforcement_block)"
  }
}

run "validation_request_report_enforces" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_definition_choice             = "specification"
    api_specification_validation      = "all_spec_endpoints"
    api_validation_request_mode       = "report"
    api_validation_request_properties = ["PROPERTY_HTTP_BODY", "PROPERTY_HTTP_HEADERS", "PROPERTY_CONTENT_TYPE"]
  }
  assert {
    condition     = output.api_validation_enforces == true
    error_message = "request_mode=report must render validation_mode_active + enforcement_report"
  }
}

run "validation_response_block_enforces" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_definition_choice        = "specification"
    api_specification_validation = "all_spec_endpoints"
    api_validation_response_mode = "block"
  }
  assert {
    condition     = output.api_validation_enforces == true && output.api_validation_response_mode == "block"
    error_message = "response_mode=block must enforce (response_validation_mode_active)"
  }
}

# Fall-through custom + settings render a valid plan.
run "validation_fall_through_custom" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_definition_choice        = "specification"
    api_specification_validation = "all_spec_endpoints"
    api_validation_request_mode  = "block"
    api_validation_fall_through  = "custom"
    validation_custom_rules      = [{ path = "/api/legacy", methods = ["GET"], action = "report" }]
  }
  assert {
    condition     = output.api_validation_fall_through == "custom"
    error_message = "fall_through=custom must render fall_through_mode_custom with rules"
  }
}

run "validation_settings_render" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_definition_choice            = "specification"
    api_specification_validation     = "all_spec_endpoints"
    api_validation_request_mode      = "block"
    api_validation_oversized_body    = "fail"
    api_validation_additional_params = "disallow"
  }
  assert {
    condition     = output.api_validation_enforces == true
    error_message = "settings (oversized_body + additional_params) must render a valid plan"
  }
}

# --- validation failures ---
run "validation_rejects_bad_request_mode" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { api_validation_request_mode = "enforce" }
  expect_failures = [var.api_validation_request_mode]
}

run "validation_rejects_bad_response_mode" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { api_validation_response_mode = "maybe" }
  expect_failures = [var.api_validation_response_mode]
}

run "validation_rejects_bad_fall_through" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { api_validation_fall_through = "deny" }
  expect_failures = [var.api_validation_fall_through]
}

run "validation_rejects_bad_oversized_body" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { api_validation_oversized_body = "truncate" }
  expect_failures = [var.api_validation_oversized_body]
}

run "validation_rejects_bad_additional_params" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { api_validation_additional_params = "strip" }
  expect_failures = [var.api_validation_additional_params]
}

run "validation_rejects_bad_property_enum" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { api_validation_request_properties = ["PROPERTY_NOT_REAL"] }
  expect_failures = [var.api_validation_request_properties]
}

run "validation_rejects_empty_request_properties" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { api_validation_request_properties = [] }
  expect_failures = [var.api_validation_request_properties]
}

run "validation_rejects_empty_response_properties" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { api_validation_response_properties = [] }
  expect_failures = [var.api_validation_response_properties]
}

run "validation_rejects_custom_fall_through_without_rules" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_definition_choice        = "specification"
    api_specification_validation = "all_spec_endpoints"
    api_validation_fall_through  = "custom"
    # validation_custom_rules defaults to [] -> precondition must fail
  }
  expect_failures = [xcsh_http_loadbalancer.this]
}
