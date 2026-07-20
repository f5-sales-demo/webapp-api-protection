# Plan-level tests for CSD-2: xcsh_mitigated_domain + xcsh_allowed_domain (in the http-lb module,
# gated by csd_enabled). command = plan, targets ./modules/http-lb. No import round-trip is tested
# (CSD domain API is list/create/delete only — 501 GET-by-name; verified live via steady-state).
variables {
  namespace         = "webapp-api-protection"
  lb_domains        = ["www.f5-sales-demo.com"]
  origin_ip         = "203.0.113.10"
  origin_port       = 80
  health_check_path = "/health"
  labels            = {}
  csd_enabled       = true
  mud_enabled       = false
}

run "mitigated_and_allowed_render" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    csd_mitigated_domains = [
      { name = "block-jsdelivr", domain = "cdn.jsdelivr.net", description = "block skimmer CDN" },
    ]
    csd_allowed_domains = [
      { name = "allow-fonts", domain = "fonts.googleapis.com", labels = { team = "web" } },
    ]
  }
  assert {
    condition     = xcsh_mitigated_domain.this["block-jsdelivr"].mitigated_domain == "cdn.jsdelivr.net"
    error_message = "mitigated_domain must render the host"
  }
  assert {
    condition     = xcsh_mitigated_domain.this["block-jsdelivr"].namespace == "webapp-api-protection"
    error_message = "mitigated_domain must be in the LB namespace"
  }
  assert {
    condition     = xcsh_allowed_domain.this["allow-fonts"].allowed_domain == "fonts.googleapis.com"
    error_message = "allowed_domain must render the host"
  }
  assert {
    condition     = xcsh_allowed_domain.this["allow-fonts"].labels["team"] == "web"
    error_message = "allowed_domain labels must render"
  }
}

run "disable_toggle_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    csd_mitigated_domains = [{ name = "block-x", domain = "evil.example.com", disable = true }]
  }
  assert {
    condition     = xcsh_mitigated_domain.this["block-x"].disable == true
    error_message = "disable toggle must render"
  }
}

run "omitted_by_default" {
  command = plan
  module { source = "./modules/http-lb" }
  assert {
    condition     = length(xcsh_mitigated_domain.this) == 0 && length(xcsh_allowed_domain.this) == 0
    error_message = "no CSD domain resources by default"
  }
}

run "not_created_when_csd_disabled" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    csd_enabled           = false
    csd_mitigated_domains = [{ name = "block-x", domain = "evil.example.com" }]
  }
  assert {
    condition     = length(xcsh_mitigated_domain.this) == 0
    error_message = "mitigated_domain must not be created when csd_enabled=false"
  }
}

run "bad_mitigated_domain_rejected" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { csd_mitigated_domains = [{ name = "block-empty", domain = "" }] }
  expect_failures = [var.csd_mitigated_domains]
}
