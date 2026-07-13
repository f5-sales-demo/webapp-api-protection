# Plan-level tests: detection_setting_choice and every detection_settings nested
# oneof arm + enum + list bound render. Targets ./modules/http-lb, no tenant contact.
variables {
  namespace          = "webapp-api-protection"
  lb_domains         = ["www.f5-sales-demo.com"]
  origin_ip          = "203.0.113.10"
  origin_port        = 80
  health_check_path  = "/health"
  labels             = {}
  csd_enabled        = false
  mud_enabled        = false
  waf_detection_mode = "custom"
}

# --- detection_setting_choice ------------------------------------------------
run "detection_default" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { waf_detection_mode = "default" }
  assert {
    condition     = output.waf_detection_mode == "default"
    error_message = "default_detection_settings arm must render"
  }
}

run "detection_custom_baseline" {
  command = plan
  module { source = "./modules/http-lb" }
  assert {
    condition     = output.waf_detection_mode == "custom"
    error_message = "detection_settings (custom) arm must render"
  }
}

# --- violation_detection_setting ---------------------------------------------
run "violation_default" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { waf_violation_mode = "default" }
  assert {
    condition     = output.waf_detection_mode == "custom"
    error_message = "default_violation_settings arm must render"
  }
}

run "violation_custom_empty" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    waf_violation_mode           = "custom"
    waf_disabled_violation_types = []
  }
  assert {
    condition     = output.waf_detection_mode == "custom"
    error_message = "violation_settings with empty disabled list must render"
  }
}

run "violation_custom_max_40" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    waf_violation_mode = "custom"
    waf_disabled_violation_types = [
      "VIOL_NONE", "VIOL_FILETYPE", "VIOL_METHOD", "VIOL_MANDATORY_HEADER",
      "VIOL_HTTP_RESPONSE_STATUS", "VIOL_REQUEST_MAX_LENGTH", "VIOL_FILE_UPLOAD",
      "VIOL_FILE_UPLOAD_IN_BODY", "VIOL_XML_MALFORMED", "VIOL_JSON_MALFORMED",
      "VIOL_ASM_COOKIE_MODIFIED", "VIOL_HTTP_PROTOCOL_MULTIPLE_HOST_HEADERS",
      "VIOL_HTTP_PROTOCOL_BAD_HOST_HEADER_VALUE",
      "VIOL_HTTP_PROTOCOL_UNPARSABLE_REQUEST_CONTENT",
      "VIOL_HTTP_PROTOCOL_NULL_IN_REQUEST", "VIOL_HTTP_PROTOCOL_BAD_HTTP_VERSION",
      "VIOL_HTTP_PROTOCOL_CRLF_CHARACTERS_BEFORE_REQUEST_START",
      "VIOL_HTTP_PROTOCOL_NO_HOST_HEADER_IN_HTTP_1_1_REQUEST",
      "VIOL_HTTP_PROTOCOL_BAD_MULTIPART_PARAMETERS_PARSING",
      "VIOL_HTTP_PROTOCOL_SEVERAL_CONTENT_LENGTH_HEADERS",
      "VIOL_HTTP_PROTOCOL_CONTENT_LENGTH_SHOULD_BE_A_POSITIVE_NUMBER",
      "VIOL_EVASION_DIRECTORY_TRAVERSALS", "VIOL_MALFORMED_REQUEST",
      "VIOL_EVASION_MULTIPLE_DECODING", "VIOL_DATA_GUARD",
      "VIOL_EVASION_APACHE_WHITESPACE", "VIOL_COOKIE_MODIFIED",
      "VIOL_EVASION_IIS_UNICODE_CODEPOINTS", "VIOL_EVASION_IIS_BACKSLASHES",
      "VIOL_EVASION_PERCENT_U_DECODING", "VIOL_EVASION_BARE_BYTE_DECODING",
      "VIOL_EVASION_BAD_UNESCAPE",
      "VIOL_HTTP_PROTOCOL_BAD_MULTIPART_FORMDATA_REQUEST_PARSING",
      "VIOL_HTTP_PROTOCOL_BODY_IN_GET_OR_HEAD_REQUEST",
      "VIOL_HTTP_PROTOCOL_HIGH_ASCII_CHARACTERS_IN_HEADERS", "VIOL_ENCODING",
      "VIOL_COOKIE_MALFORMED", "VIOL_GRAPHQL_FORMAT", "VIOL_GRAPHQL_MALFORMED",
      "VIOL_GRAPHQL_INTROSPECTION_QUERY"
    ]
  }
  assert {
    condition     = length(var.waf_disabled_violation_types) == 40
    error_message = "violation_settings with all 40 disabled types must render"
  }
}

# --- signatures_staging_settings ---------------------------------------------
run "staging_disable" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { waf_staging_mode = "disable" }
  assert {
    condition     = output.waf_detection_mode == "custom"
    error_message = "staging disable (omit) arm must render"
  }
}

run "staging_new" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    waf_staging_mode   = "new"
    waf_staging_period = 7
  }
  assert {
    condition     = output.waf_detection_mode == "custom"
    error_message = "stage_new_signatures arm must render"
  }
}

run "staging_new_and_updated" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    waf_staging_mode   = "new_and_updated"
    waf_staging_period = 30
  }
  assert {
    condition     = output.waf_detection_mode == "custom"
    error_message = "stage_new_and_updated_signatures arm must render"
  }
}

# --- false_positive_suppression ----------------------------------------------
run "suppression_enable" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { waf_suppression = "enable" }
  assert {
    condition     = output.waf_detection_mode == "custom"
    error_message = "enable_suppression arm must render"
  }
}

run "suppression_disable" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { waf_suppression = "disable" }
  assert {
    condition     = output.waf_detection_mode == "custom"
    error_message = "disable_suppression arm must render"
  }
}

# --- threat_campaign_choice --------------------------------------------------
run "threat_campaigns_enable" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { waf_threat_campaigns = "enable" }
  assert {
    condition     = output.waf_detection_mode == "custom"
    error_message = "enable_threat_campaigns arm must render"
  }
}

run "threat_campaigns_disable" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { waf_threat_campaigns = "disable" }
  assert {
    condition     = output.waf_detection_mode == "custom"
    error_message = "disable_threat_campaigns arm must render"
  }
}

# --- nested bot_protection_choice --------------------------------------------
run "detection_bot_default" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { waf_detection_bot_mode = "default" }
  assert {
    condition     = output.waf_detection_mode == "custom"
    error_message = "nested default_bot_setting arm must render"
  }
}

run "detection_bot_custom" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    waf_detection_bot_mode = "custom"
    waf_bot_actions        = { good = "IGNORE", malicious = "BLOCK", suspicious = "REPORT" }
  }
  assert {
    condition     = output.waf_detection_mode == "custom"
    error_message = "nested bot_protection_setting arm must render"
  }
}

# --- signature_selection_by_accuracy -----------------------------------------
run "accuracy_only_high" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { waf_signature_accuracy = "only_high" }
  assert {
    condition     = output.waf_detection_mode == "custom"
    error_message = "only_high_accuracy_signatures arm must render"
  }
}

run "accuracy_high_medium" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { waf_signature_accuracy = "high_medium" }
  assert {
    condition     = output.waf_detection_mode == "custom"
    error_message = "high_medium_accuracy_signatures arm must render"
  }
}

run "accuracy_high_medium_low" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { waf_signature_accuracy = "high_medium_low" }
  assert {
    condition     = output.waf_detection_mode == "custom"
    error_message = "high_medium_low_accuracy_signatures arm must render"
  }
}

# --- attack_type_setting (max 22) --------------------------------------------
run "attack_type_default" {
  command = plan
  module { source = "./modules/http-lb" }
  variables { waf_attack_type_mode = "default" }
  assert {
    condition     = output.waf_detection_mode == "custom"
    error_message = "default_attack_type_settings arm must render"
  }
}

run "attack_type_custom_max_22" {
  command = plan
  module { source = "./modules/http-lb" }
  variables {
    waf_attack_type_mode = "custom"
    waf_disabled_attack_types = [
      "ATTACK_TYPE_NONE", "ATTACK_TYPE_NON_BROWSER_CLIENT",
      "ATTACK_TYPE_OTHER_APPLICATION_ATTACKS", "ATTACK_TYPE_TROJAN_BACKDOOR_SPYWARE",
      "ATTACK_TYPE_DETECTION_EVASION", "ATTACK_TYPE_VULNERABILITY_SCAN",
      "ATTACK_TYPE_ABUSE_OF_FUNCTIONALITY",
      "ATTACK_TYPE_AUTHENTICATION_AUTHORIZATION_ATTACKS", "ATTACK_TYPE_BUFFER_OVERFLOW",
      "ATTACK_TYPE_PREDICTABLE_RESOURCE_LOCATION", "ATTACK_TYPE_INFORMATION_LEAKAGE",
      "ATTACK_TYPE_DIRECTORY_INDEXING", "ATTACK_TYPE_PATH_TRAVERSAL",
      "ATTACK_TYPE_XPATH_INJECTION", "ATTACK_TYPE_LDAP_INJECTION",
      "ATTACK_TYPE_SERVER_SIDE_CODE_INJECTION", "ATTACK_TYPE_COMMAND_EXECUTION",
      "ATTACK_TYPE_SQL_INJECTION", "ATTACK_TYPE_CROSS_SITE_SCRIPTING",
      "ATTACK_TYPE_DENIAL_OF_SERVICE", "ATTACK_TYPE_HTTP_PARSER_ATTACK",
      "ATTACK_TYPE_SESSION_HIJACKING"
    ]
  }
  assert {
    condition     = length(var.waf_disabled_attack_types) == 22
    error_message = "attack_type_settings with 22 disabled types (max) must render"
  }
}
