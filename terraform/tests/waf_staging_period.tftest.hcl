# Boundary coverage for the provider schema's 1-20 day WAF staging period.
variables {
  namespace          = "example"
  lb_domains         = ["www.example.com"]
  origin_ip          = "203.0.113.10"
  origin_port        = 80
  health_check_path  = "/health"
  labels             = {}
  csd_enabled        = false
  mud_enabled        = false
  waf_detection_mode = "custom"
}

run "staging_period_rejects_zero" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    waf_staging_mode   = "new"
    waf_staging_period = 0
  }
  expect_failures = [var.waf_staging_period]
}

run "staging_period_rejects_above_twenty" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    waf_staging_mode   = "new_and_updated"
    waf_staging_period = 21
  }
  expect_failures = [var.waf_staging_period]
}
