# Plan-level tests for client access control (CAC): trusted_clients / blocked_clients
# (match by ip_prefix/ipv6_prefix/as_number/user_identifier + SKIP_PROCESSING_* actions)
# and enable_ip_reputation. Targets ./modules/http-lb. command = plan (no creds).
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

run "blocked_client_ip_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    blocked_clients = [{ ip_prefix = "192.0.2.10/32" }]
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.blocked_clients[0].ip_prefix == "192.0.2.10/32"
    error_message = "blocked_clients ip_prefix must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.blocked_clients[0].metadata.name == "cac-blocked-0"
    error_message = "blocked_clients metadata name must auto-generate"
  }
}

run "trusted_client_asn_with_actions_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    trusted_clients = [{ as_number = 64512, actions = ["SKIP_PROCESSING_WAF", "SKIP_PROCESSING_BOT"] }]
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.trusted_clients[0].as_number == 64512
    error_message = "trusted_clients as_number must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.trusted_clients[0].actions[0] == "SKIP_PROCESSING_WAF"
    error_message = "trusted_clients actions must render"
  }
}

run "ip_reputation_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    ip_reputation_enabled    = true
    ip_reputation_categories = ["BOTNETS", "TOR_PROXY"]
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.enable_ip_reputation.ip_threat_categories[0] == "BOTNETS"
    error_message = "enable_ip_reputation categories must render"
  }
}

run "cac_omitted_by_default" {
  command = plan
  module { source = "./modules/http-lb" }
  assert {
    condition     = try(length(xcsh_http_loadbalancer.this.blocked_clients), 0) == 0 && try(length(xcsh_http_loadbalancer.this.trusted_clients), 0) == 0
    error_message = "CAC client lists must be empty by default"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.enable_ip_reputation == null
    error_message = "enable_ip_reputation must be omitted (null) by default"
  }
}

run "rejects_no_match_key" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    blocked_clients = [{ actions = ["SKIP_PROCESSING_WAF"] }]
  }
  expect_failures = [var.blocked_clients]
}

run "rejects_multi_match_key" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    blocked_clients = [{ ip_prefix = "192.0.2.0/24", as_number = 64512 }]
  }
  expect_failures = [var.blocked_clients]
}

run "rejects_bad_action" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    trusted_clients = [{ ip_prefix = "192.0.2.0/24", actions = ["SKIP_EVERYTHING"] }]
  }
  expect_failures = [var.trusted_clients]
}

run "rejects_bad_ip_threat_category" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    ip_reputation_enabled    = true
    ip_reputation_categories = ["NOT_A_CATEGORY"]
  }
  expect_failures = [var.ip_reputation_categories]
}
