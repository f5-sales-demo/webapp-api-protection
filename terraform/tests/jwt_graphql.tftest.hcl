# Plan-level tests for LPC-3: jwt_validation (inline JWKS) + graphql_rules[]. Targets
# ./modules/http-lb. command = plan (no creds). The JWKS is a readable JSON document; the
# module base64-encodes it for the API (F5 XC "cleartext" field is validated as base64).
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

run "graphql_rule_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    graphql_rules = [{
      name          = "gql"
      exact_path    = "/graphql"
      domain        = "any"
      method        = "post"
      max_depth     = 10
      introspection = "disable"
    }]
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.graphql_rules[0].metadata.name == "gql"
    error_message = "graphql_rules metadata.name must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.graphql_rules[0].exact_path == "/graphql"
    error_message = "graphql_rules exact_path must render"
  }
}

run "graphql_exact_domain_requires_value" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    graphql_rules = [{ name = "g", domain = "exact", method = "post" }]
  }
  expect_failures = [var.graphql_rules]
}

run "graphql_bad_method_rejected" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    graphql_rules = [{ name = "g", method = "delete" }]
  }
  expect_failures = [var.graphql_rules]
}

run "graphql_bad_introspection_rejected" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    graphql_rules = [{ name = "g", introspection = "maybe" }]
  }
  expect_failures = [var.graphql_rules]
}

run "graphql_empty_by_default" {
  command = plan
  module { source = "./modules/http-lb" }
  assert {
    condition     = length(xcsh_http_loadbalancer.this.graphql_rules) == 0
    error_message = "graphql_rules must be empty by default"
  }
}

run "jwt_block_renders_base64_jwks" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    jwt_validation = {
      jwks_cleartext = "{\"keys\":[]}"
      action         = "block"
      target         = "all_endpoint"
      issuer         = "https://issuer.example.com"
      audiences      = ["api://webapp"]
    }
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.jwt_validation.jwks_config.cleartext == base64encode("{\"keys\":[]}")
    error_message = "jwks_config.cleartext must be the base64-encoded JWKS"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.jwt_validation.reserved_claims.issuer == "https://issuer.example.com"
    error_message = "reserved_claims.issuer must render"
  }
}

run "jwt_report_derives_disable_arms" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    jwt_validation = {
      jwks_cleartext  = "{\"keys\":[]}"
      action          = "report"
      target          = "base_paths"
      base_paths      = ["/api"]
      validate_period = false
    }
  }
  # issuer omitted -> issuer_disable arm; audiences empty -> audience_disable arm. Both required
  # oneofs must carry an arm (the API rejects a nil oneof), so the derived disable blocks render.
  assert {
    condition     = xcsh_http_loadbalancer.this.jwt_validation.reserved_claims.issuer == null
    error_message = "issuer must be null when omitted"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.jwt_validation.reserved_claims.issuer_disable != null
    error_message = "issuer_disable arm must render when issuer omitted"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.jwt_validation.reserved_claims.audience_disable != null
    error_message = "audience_disable arm must render when audiences empty"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.jwt_validation.reserved_claims.validate_period_disable != null
    error_message = "validate_period_disable arm must render when validate_period=false"
  }
}

run "jwt_target_api_groups_requires_groups" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    jwt_validation = {
      jwks_cleartext = "{\"keys\":[]}"
      target         = "api_groups"
      api_groups     = []
    }
  }
  expect_failures = [var.jwt_validation]
}

run "jwt_bad_jwks_rejected" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    jwt_validation = { jwks_cleartext = "not-json{{" }
  }
  expect_failures = [var.jwt_validation]
}

run "jwt_bad_action_rejected" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    jwt_validation = { jwks_cleartext = "{}", action = "warn" }
  }
  expect_failures = [var.jwt_validation]
}

run "jwt_omitted_by_default" {
  command = plan
  module { source = "./modules/http-lb" }
  assert {
    condition     = xcsh_http_loadbalancer.this.jwt_validation == null
    error_message = "jwt_validation must be omitted (null) by default"
  }
}
