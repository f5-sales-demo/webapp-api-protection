# Plan-level tests for the SCM code_base_integration (Coverage Batch E): all 7 provider
# arms (github/github_enterprise/gitlab/gitlab_enterprise/azure_repos/bitbucket/
# bitbucket_server), token via the reusable clear/blindfold SecretType convention.
# Targets ./modules/http-lb, dummy origin.
variables {
  namespace         = "webapp-api-protection"
  lb_domains        = ["www.f5-sales-demo.com"]
  origin_ip         = "203.0.113.10"
  origin_port       = 80
  health_check_path = "/health"
  labels            = {}
  csd_enabled       = false
  mud_enabled       = false
  # a usable token for the enabled-arm render tests
  code_base_integration_enabled      = true
  code_base_integration_username     = "f5-sales-demo-bot"
  code_base_integration_access_token = { method = "clear", plaintext = "ghp_example_token" }
}

run "scm_disabled_default" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { code_base_integration_enabled = false }
  assert {
    condition     = output.code_base_integration_enabled == false && length(xcsh_code_base_integration.this) == 0
    error_message = "code_base_integration must be disabled by default (0-change)"
  }
}

run "scm_github_clear_token" {
  command = plan
  module { source = "./modules/http-lb" }
  assert {
    condition     = output.code_base_integration_token_method == "clear" && xcsh_code_base_integration.this[0].code_base_integration.github != null
    error_message = "github clear access_token arm must render"
  }
}

run "scm_github_blindfold_token" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    code_base_integration_access_token = { method = "blindfold", location = "string:///eyJrZXlfdmVyc2lvbiI6MX0=" }
  }
  assert {
    condition     = output.code_base_integration_token_method == "blindfold"
    error_message = "github blindfold access_token arm must render"
  }
}

run "scm_github_enterprise" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    code_base_integration_provider = "github_enterprise"
    code_base_integration_hostname = "ghe.f5-sales-demo.com"
  }
  assert {
    condition     = xcsh_code_base_integration.this[0].code_base_integration.github_enterprise.hostname == "ghe.f5-sales-demo.com"
    error_message = "github_enterprise arm must render with hostname"
  }
}

run "scm_gitlab" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { code_base_integration_provider = "gitlab" }
  assert {
    condition     = xcsh_code_base_integration.this[0].code_base_integration.gitlab != null && xcsh_code_base_integration.this[0].code_base_integration.github == null
    error_message = "gitlab arm must render (and github omitted)"
  }
}

run "scm_gitlab_enterprise" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    code_base_integration_provider = "gitlab_enterprise"
    code_base_integration_url      = "https://gitlab.f5-sales-demo.com"
  }
  assert {
    condition     = xcsh_code_base_integration.this[0].code_base_integration.gitlab_enterprise.url == "https://gitlab.f5-sales-demo.com"
    error_message = "gitlab_enterprise arm must render with url"
  }
}

run "scm_azure_repos" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { code_base_integration_provider = "azure_repos" }
  assert {
    condition     = xcsh_code_base_integration.this[0].code_base_integration.azure_repos != null
    error_message = "azure_repos arm must render"
  }
}

run "scm_bitbucket" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { code_base_integration_provider = "bitbucket" }
  assert {
    condition     = xcsh_code_base_integration.this[0].code_base_integration.bitbucket != null
    error_message = "bitbucket arm (passwd) must render"
  }
}

run "scm_bitbucket_server" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    code_base_integration_provider = "bitbucket_server"
    code_base_integration_url      = "https://bb.f5-sales-demo.com"
  }
  assert {
    condition     = xcsh_code_base_integration.this[0].code_base_integration.bitbucket_server.url == "https://bb.f5-sales-demo.com" && xcsh_code_base_integration.this[0].code_base_integration.bitbucket_server.verify_ssl == true
    error_message = "bitbucket_server arm must render with url + verify_ssl"
  }
}

# --- validation / precondition failures ---

run "scm_rejects_bad_provider" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { code_base_integration_provider = "svn" }
  expect_failures = [var.code_base_integration_provider]
}

run "scm_enterprise_without_hostname_fails" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { code_base_integration_provider = "github_enterprise" }
  expect_failures = [xcsh_code_base_integration.this]
}

run "scm_gitlab_enterprise_without_url_fails" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { code_base_integration_provider = "gitlab_enterprise" }
  expect_failures = [xcsh_code_base_integration.this]
}

run "scm_github_without_username_fails" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { code_base_integration_username = "" }
  expect_failures = [xcsh_code_base_integration.this]
}

run "scm_enabled_without_token_fails" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    code_base_integration_access_token = { method = "clear", plaintext = null }
  }
  expect_failures = [xcsh_code_base_integration.this]
}
