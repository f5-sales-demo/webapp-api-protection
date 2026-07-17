# JWT validation (LPC-3) on the LB top-level jwt_validation block. Uses the inline JWKS arm
# (jwks_config.cleartext); the authorization_server ref arm is deferred to a later ref slice.
# Default (null) omits the block (0-change).
#
# jwks_cleartext takes a readable JWKS JSON document (RFC 7517). The F5 XC API field is named
# "cleartext" but the server validates it as base64 (a bare JSON 500s with "failed to decode
# base64 cleartext JWKS"); the module base64-encodes it, so callers pass plain JSON.

variable "jwt_validation" {
  description = "JWT validation on the LB (inline JWKS). null omits the block."
  type = object({
    jwks_cleartext   = string                           # a readable JWKS JSON document (module base64-encodes for the API)
    action           = optional(string, "block")        # block|report
    target           = optional(string, "all_endpoint") # all_endpoint|api_groups|base_paths
    api_groups       = optional(list(string), [])       # target=api_groups
    base_paths       = optional(list(string), [])       # target=base_paths
    mandatory_claims = optional(list(string), [])       # mandatory_claims.claim_names
    # reserved_claims has three required oneofs; the arm is derived from value presence so a
    # choice is never left empty (the API rejects a nil oneof). issuer set -> validate it, else
    # issuer_disable; audiences non-empty -> validate them, else audience_disable.
    issuer          = optional(string)           # reserved_claims.issuer (absent -> issuer_disable)
    audiences       = optional(list(string), []) # reserved_claims.audience (empty -> audience_disable)
    validate_period = optional(bool, true)       # validate_period_enable (true) vs _disable (false)
  })
  default = null

  validation {
    condition     = var.jwt_validation == null || can(jsondecode(var.jwt_validation.jwks_cleartext))
    error_message = "jwt_validation.jwks_cleartext must be a JWKS JSON document (RFC 7517); the module base64-encodes it."
  }
  validation {
    condition     = var.jwt_validation == null || contains(["block", "report"], var.jwt_validation.action)
    error_message = "jwt_validation.action must be block or report."
  }
  validation {
    condition     = var.jwt_validation == null || contains(["all_endpoint", "api_groups", "base_paths"], var.jwt_validation.target)
    error_message = "jwt_validation.target must be all_endpoint, api_groups, or base_paths."
  }
  validation {
    condition     = var.jwt_validation == null || var.jwt_validation.target != "api_groups" || length(var.jwt_validation.api_groups) > 0
    error_message = "jwt_validation.api_groups is required when target=api_groups."
  }
  validation {
    condition     = var.jwt_validation == null || var.jwt_validation.target != "base_paths" || length(var.jwt_validation.base_paths) > 0
    error_message = "jwt_validation.base_paths is required when target=base_paths."
  }
}
