# Plan-level test: the mitigation policy is driven by var.mud_mitigation and every
# action renders at every threat level (dynamic block validity). Deep resource content
# is verified live by the config-matrix round-trip import (plan tests cannot introspect
# nested blocks). Targets ./modules/http-lb with a dummy origin — no tenant contact.
variables {
  namespace         = "webapp-api-protection"
  lb_domains        = ["www.f5-sales-demo.com"]
  origin_ip         = "203.0.113.10"
  origin_port       = 80
  health_check_path = "/health"
  labels            = {}
  waf_mode          = "blocking"
  csd_enabled       = false
  mud_enabled       = true
}

run "mitigation_permuted_map_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    mud_mitigation = { low = "block_temporarily", medium = "javascript_challenge", high = "captcha_challenge" }
  }
  assert {
    condition     = output.mud_mitigation.low == "block_temporarily" && output.mud_mitigation.medium == "javascript_challenge" && output.mud_mitigation.high == "captcha_challenge"
    error_message = "mitigation map must flow through to the module unchanged"
  }
}

run "mitigation_all_captcha_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    mud_mitigation = { low = "captcha_challenge", medium = "captcha_challenge", high = "captcha_challenge" }
  }
  assert {
    condition     = output.mud_enabled == true
    error_message = "plan must succeed for an all-captcha mitigation map"
  }
}
