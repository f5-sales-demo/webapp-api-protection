# Plan-level test: MUD user identification switches between the client-IP default and a
# user_identification policy resource selecting a specific rule type. Targets
# ./modules/http-lb with a dummy origin — no tenant contact.
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

run "userid_http_header_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    mud_user_id      = "user_identification"
    mud_user_id_rule = "http_header_name"
  }
  assert {
    condition     = output.mud_user_id == "user_identification"
    error_message = "user-id method must be user_identification"
  }
  assert {
    condition     = length(xcsh_user_identification.mud) == 1
    error_message = "a user_identification policy must be created when mud_user_id=user_identification"
  }
}

run "userid_ja4_fingerprint_renders" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    mud_user_id      = "user_identification"
    mud_user_id_rule = "ja4_tls_fingerprint"
  }
  assert {
    condition     = length(xcsh_user_identification.mud) == 1
    error_message = "ja4_tls_fingerprint must be an accepted user-id rule type"
  }
}

run "userid_client_ip_no_policy" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    mud_user_id = "client_ip"
  }
  assert {
    condition     = length(xcsh_user_identification.mud) == 0
    error_message = "no user_identification policy when mud_user_id=client_ip (server default)"
  }
}
