# Plan-level tests: every top-level app_firewall oneof arm + enum + bound renders.
# Targets ./modules/http-lb with a dummy origin — no tenant contact. A successful
# plan for each arm proves the dynamic block builds a valid provider value (catches
# the Value Conversion Error class client-side); the assert pins the effective arm.
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

# --- enforcement_mode_choice -------------------------------------------------
run "enforcement_blocking" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { waf_mode = "blocking" }
  assert {
    condition     = output.waf_mode == "blocking"
    error_message = "blocking enforcement arm must render"
  }
}

run "enforcement_monitoring" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { waf_mode = "monitoring" }
  assert {
    condition     = output.waf_mode == "monitoring"
    error_message = "monitoring enforcement arm must render"
  }
}

# --- allowed_response_codes_choice (min 1, max 48) ---------------------------
run "response_codes_omit" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { waf_allowed_response_codes_mode = "omit" }
  assert {
    condition     = output.waf_allowed_response_codes_mode == "omit"
    error_message = "allow_all (omit) arm must render"
  }
}

run "response_codes_list_min" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    waf_allowed_response_codes_mode = "list"
    waf_allowed_response_codes      = [200]
  }
  assert {
    condition     = output.waf_allowed_response_codes_mode == "list"
    error_message = "allowed_response_codes list arm (min 1 entry) must render"
  }
}

run "response_codes_list_max" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    waf_allowed_response_codes_mode = "list"
    waf_allowed_response_codes      = [for i in range(48) : 200 + i]
  }
  assert {
    condition     = length(var.waf_allowed_response_codes) == 48
    error_message = "allowed_response_codes list arm (max 48 entries) must render"
  }
}

# --- blocking_page_choice ----------------------------------------------------
run "blocking_page_omit" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { waf_blocking_page_mode = "omit" }
  assert {
    condition     = output.waf_blocking_page_mode == "omit"
    error_message = "use_default_blocking_page (omit) arm must render"
  }
}

run "blocking_page_custom" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    waf_blocking_page_mode          = "custom"
    waf_blocking_page               = "https://www.f5-sales-demo.com/blocked.html"
    waf_blocking_page_response_code = "Forbidden"
  }
  assert {
    condition     = output.waf_blocking_page_mode == "custom"
    error_message = "custom blocking_page arm must render"
  }
}

# --- bot_protection_choice (each action enum) --------------------------------
run "bot_omit" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { waf_bot_mode = "omit" }
  assert {
    condition     = output.waf_bot_mode == "omit"
    error_message = "default_bot_setting (omit) arm must render"
  }
}

run "bot_custom_block" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    waf_bot_mode    = "custom"
    waf_bot_actions = { good = "BLOCK", malicious = "BLOCK", suspicious = "BLOCK" }
  }
  assert {
    condition     = output.waf_bot_mode == "custom"
    error_message = "bot_protection_setting with BLOCK actions must render"
  }
}

run "bot_custom_report" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    waf_bot_mode    = "custom"
    waf_bot_actions = { good = "REPORT", malicious = "REPORT", suspicious = "REPORT" }
  }
  assert {
    condition     = output.waf_bot_mode == "custom"
    error_message = "bot_protection_setting with REPORT actions must render"
  }
}

run "bot_custom_ignore" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    waf_bot_mode    = "custom"
    waf_bot_actions = { good = "IGNORE", malicious = "IGNORE", suspicious = "IGNORE" }
  }
  assert {
    condition     = output.waf_bot_mode == "custom"
    error_message = "bot_protection_setting with IGNORE actions must render"
  }
}

# --- anonymization_setting (custom pending provider fix) ---------------------
run "anonymization_omit" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { waf_anonymization_mode = "omit" }
  assert {
    condition     = output.waf_anonymization_mode == "omit"
    error_message = "default_anonymization (omit) arm must render"
  }
}

run "anonymization_disable" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { waf_anonymization_mode = "disable" }
  assert {
    condition     = output.waf_anonymization_mode == "disable"
    error_message = "disable_anonymization arm must render"
  }
}

# --- enhance_with_ai_choice --------------------------------------------------
run "ai_omit" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { waf_ai_mode = "omit" }
  assert {
    condition     = output.waf_ai_mode == "omit"
    error_message = "ai omit arm must render"
  }
}

run "ai_enable_high" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    waf_ai_mode        = "enable"
    waf_ai_risk_action = "high"
  }
  assert {
    condition     = output.waf_ai_mode == "enable"
    error_message = "enable_ai_enhancements + mitigate_high_risk_action must render"
  }
}

run "ai_enable_high_medium" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    waf_ai_mode        = "enable"
    waf_ai_risk_action = "high_medium"
  }
  assert {
    condition     = output.waf_ai_mode == "enable"
    error_message = "enable_ai_enhancements + mitigate_high_medium_risk_action must render"
  }
}
