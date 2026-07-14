# Plan-level tests for the reusable clear/blindfold SecretType convention, first
# consumed by the inline API crawler credential (enable_api_discovery.api_crawler.
# api_crawler_config.domains[].simple_login.password). Targets ./modules/http-lb
# with a dummy origin. A successful plan proves the dynamic secret block builds a
# valid provider value; asserts pin the effective arm via module outputs.
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

run "clear_secret_selects_clear_arm" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    api_crawler_domains  = [{ domain = "https://api.f5-sales-demo.com", user = "tester" }]
    api_crawler_password = { method = "clear", plaintext = "s3cret" }
  }
  assert {
    condition     = output.api_crawler_password_use_blindfold == false
    error_message = "clear method must not select the blindfold arm"
  }
  assert {
    condition     = output.api_crawler_domain_count == 1
    error_message = "crawler domain must render"
  }
}
