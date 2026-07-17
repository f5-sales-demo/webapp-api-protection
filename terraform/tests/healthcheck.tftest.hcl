# Plan-level tests for LPC-5a: xcsh_healthcheck.origin parameterization. Targets
# ./modules/http-lb. command = plan (no creds).
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

run "default_is_http_health_check" {
  command = plan
  module { source = "./modules/http-lb" }
  assert {
    condition     = xcsh_healthcheck.origin.http_health_check.path == "/health"
    error_message = "default must be an http health check on /health"
  }
  assert {
    condition     = xcsh_healthcheck.origin.http_health_check.expected_status_codes[0] == "200"
    error_message = "default expected_status_codes must be [200]"
  }
  assert {
    condition     = xcsh_healthcheck.origin.tcp_health_check == null
    error_message = "tcp_health_check must be null by default"
  }
}

run "http_host_header_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    hc_http_host_header = "www.f5-sales-demo.com"
  }
  assert {
    condition     = xcsh_healthcheck.origin.http_health_check.host_header == "www.f5-sales-demo.com"
    error_message = "host_header must render when hc_http_host_header is set"
  }
  assert {
    condition     = xcsh_healthcheck.origin.http_health_check.use_origin_server_name == null
    error_message = "use_origin_server_name must be omitted when host_header is set"
  }
}

run "default_uses_origin_server_name" {
  command = plan
  module { source = "./modules/http-lb" }
  assert {
    condition     = xcsh_healthcheck.origin.http_health_check.use_origin_server_name != null
    error_message = "use_origin_server_name arm must render when no host_header (server default)"
  }
  assert {
    condition     = xcsh_healthcheck.origin.http_health_check.host_header == null
    error_message = "host_header must be null by default"
  }
}

run "tcp_health_check_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    health_check_type   = "tcp"
    hc_tcp_send_payload = "50494e47"
  }
  assert {
    condition     = xcsh_healthcheck.origin.tcp_health_check.send_payload == "50494e47"
    error_message = "tcp send_payload must render"
  }
  assert {
    condition     = xcsh_healthcheck.origin.http_health_check == null
    error_message = "http_health_check must be null for type=tcp"
  }
}

run "thresholds_render" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    hc_healthy_threshold = 5
    hc_interval          = 30
    hc_jitter_percent    = 20
  }
  assert {
    condition     = xcsh_healthcheck.origin.healthy_threshold == 5
    error_message = "healthy_threshold must render"
  }
  assert {
    condition     = xcsh_healthcheck.origin.jitter_percent == 20
    error_message = "jitter_percent must render"
  }
}

run "bad_type_rejected" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { health_check_type = "udp_icmp" }
  expect_failures = [var.health_check_type]
}

