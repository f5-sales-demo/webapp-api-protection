# Plan-level tests for LBA: loadbalancer_algorithm oneof. round_robin (default) is omitted;
# the chosen non-default arm is emitted. command = plan, targets ./modules/http-lb.
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

run "round_robin_default_omits_arms" {
  command = plan
  module { source = "./modules/http-lb" }
  assert {
    condition     = xcsh_http_loadbalancer.this.least_active == null && xcsh_http_loadbalancer.this.random == null && xcsh_http_loadbalancer.this.source_ip_stickiness == null && xcsh_http_loadbalancer.this.ring_hash == null
    error_message = "round_robin default must emit no explicit algorithm arm (server default)"
  }
}

run "least_active_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { lb_algorithm = { mode = "least_active" } }
  assert {
    condition     = xcsh_http_loadbalancer.this.least_active != null
    error_message = "least_active arm must render"
  }
}

run "random_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { lb_algorithm = { mode = "random" } }
  assert {
    condition     = xcsh_http_loadbalancer.this.random != null
    error_message = "random arm must render"
  }
}

run "source_ip_stickiness_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { lb_algorithm = { mode = "source_ip_stickiness" } }
  assert {
    condition     = xcsh_http_loadbalancer.this.source_ip_stickiness != null
    error_message = "source_ip_stickiness arm must render"
  }
}

run "ring_hash_with_policies_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    lb_algorithm = {
      mode = "ring_hash"
      ring_hash_policies = [
        { source_ip = true, terminal = true },
        { header_name = "x-user" },
      ]
    }
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.ring_hash.hash_policy[0].source_ip == true
    error_message = "ring_hash hash_policy source_ip must render"
  }
  assert {
    condition     = xcsh_http_loadbalancer.this.ring_hash.hash_policy[1].header_name == "x-user"
    error_message = "ring_hash hash_policy header_name must render"
  }
}

run "bad_mode_rejected" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { lb_algorithm = { mode = "cookie_stickiness" } }
  expect_failures = [var.lb_algorithm]
}

run "ring_hash_policies_require_ring_hash_mode" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { lb_algorithm = { mode = "random", ring_hash_policies = [{ source_ip = true }] } }
  expect_failures = [var.lb_algorithm]
}
