variable "preserve_native_request_paths" {
  description = "Preserve native demo URI bytes for WAF evaluation instead of canonicalizing paths before routing."
  type        = bool
  default     = false
}
