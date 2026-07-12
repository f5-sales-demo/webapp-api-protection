# Exhaustive plan-level matrix: every MUD user-identification rule type, and every
# mitigation action at every threat level, must produce a valid plan. Challenge modes
# are covered in mud_challenge.tftest.hcl. Targets ./modules/http-lb — no tenant contact.
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
  mud_user_id       = "user_identification"
}

run "uid_cookie_name" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    mud_user_id_rule = "cookie_name"
  }
  assert {
    condition     = length(xcsh_user_identification.mud) == 1
    error_message = "cookie_name policy must be created"
  }
}

run "uid_http_header_name" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    mud_user_id_rule = "http_header_name"
  }
  assert {
    condition     = length(xcsh_user_identification.mud) == 1
    error_message = "http_header_name policy must be created"
  }
}

run "uid_ip_and_http_header_name" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    mud_user_id_rule = "ip_and_http_header_name"
  }
  assert {
    condition     = length(xcsh_user_identification.mud) == 1
    error_message = "ip_and_http_header_name policy must be created"
  }
}

run "uid_jwt_claim_name" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    mud_user_id_rule = "jwt_claim_name"
  }
  assert {
    condition     = length(xcsh_user_identification.mud) == 1
    error_message = "jwt_claim_name policy must be created"
  }
}

run "uid_query_param_key" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    mud_user_id_rule = "query_param_key"
  }
  assert {
    condition     = length(xcsh_user_identification.mud) == 1
    error_message = "query_param_key policy must be created"
  }
}

run "uid_client_asn" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    mud_user_id_rule = "client_asn"
  }
  assert {
    condition     = length(xcsh_user_identification.mud) == 1
    error_message = "client_asn policy must be created"
  }
}

run "uid_client_city" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    mud_user_id_rule = "client_city"
  }
  assert {
    condition     = length(xcsh_user_identification.mud) == 1
    error_message = "client_city policy must be created"
  }
}

run "uid_client_country" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    mud_user_id_rule = "client_country"
  }
  assert {
    condition     = length(xcsh_user_identification.mud) == 1
    error_message = "client_country policy must be created"
  }
}

run "uid_client_ip" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    mud_user_id_rule = "client_ip"
  }
  assert {
    condition     = length(xcsh_user_identification.mud) == 1
    error_message = "client_ip policy must be created"
  }
}

run "uid_client_region" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    mud_user_id_rule = "client_region"
  }
  assert {
    condition     = length(xcsh_user_identification.mud) == 1
    error_message = "client_region policy must be created"
  }
}

run "uid_tls_fingerprint" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    mud_user_id_rule = "tls_fingerprint"
  }
  assert {
    condition     = length(xcsh_user_identification.mud) == 1
    error_message = "tls_fingerprint policy must be created"
  }
}

run "uid_ip_and_tls_fingerprint" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    mud_user_id_rule = "ip_and_tls_fingerprint"
  }
  assert {
    condition     = length(xcsh_user_identification.mud) == 1
    error_message = "ip_and_tls_fingerprint policy must be created"
  }
}

run "uid_ja4_tls_fingerprint" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    mud_user_id_rule = "ja4_tls_fingerprint"
  }
  assert {
    condition     = length(xcsh_user_identification.mud) == 1
    error_message = "ja4_tls_fingerprint policy must be created"
  }
}

run "uid_ip_and_ja4_tls_fingerprint" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    mud_user_id_rule = "ip_and_ja4_tls_fingerprint"
  }
  assert {
    condition     = length(xcsh_user_identification.mud) == 1
    error_message = "ip_and_ja4_tls_fingerprint policy must be created"
  }
}

run "uid_none" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    mud_user_id_rule = "none"
  }
  assert {
    condition     = length(xcsh_user_identification.mud) == 1
    error_message = "none policy must be created"
  }
}

run "mit_all_block" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    mud_user_id = "client_ip"
    mud_mitigation = {
      low    = "block_temporarily"
      medium = "block_temporarily"
      high   = "block_temporarily"
    }
  }
  assert {
    condition     = output.mud_mitigation.high == "block_temporarily"
    error_message = "all-block mitigation map must render"
  }
}

run "mit_all_captcha" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    mud_user_id = "client_ip"
    mud_mitigation = {
      low    = "captcha_challenge"
      medium = "captcha_challenge"
      high   = "captcha_challenge"
    }
  }
  assert {
    condition     = output.mud_mitigation.high == "captcha_challenge"
    error_message = "all-captcha mitigation map must render"
  }
}

run "mit_all_js" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    mud_user_id = "client_ip"
    mud_mitigation = {
      low    = "javascript_challenge"
      medium = "javascript_challenge"
      high   = "javascript_challenge"
    }
  }
  assert {
    condition     = output.mud_mitigation.high == "javascript_challenge"
    error_message = "all-js mitigation map must render"
  }
}
