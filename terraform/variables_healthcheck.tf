# Root passthrough for LPC-5a healthcheck parameterization. Defaults mirror the module so a
# plain apply is 0-change.
variable "health_check_type" {
  type    = string
  default = "http"
}
variable "hc_healthy_threshold" {
  type    = number
  default = 3
}
variable "hc_unhealthy_threshold" {
  type    = number
  default = 1
}
variable "hc_timeout" {
  type    = number
  default = 3
}
variable "hc_interval" {
  type    = number
  default = 15
}
variable "hc_jitter_percent" {
  type    = number
  default = null
}
variable "hc_http_host_header" {
  type    = string
  default = null
}
variable "hc_expected_status_codes" {
  type    = list(string)
  default = ["200"]
}
variable "hc_expected_response" {
  type    = string
  default = null
}
variable "hc_request_headers_to_remove" {
  type    = list(string)
  default = []
}
variable "hc_tcp_send_payload" {
  type    = string
  default = null
}
variable "hc_tcp_expected_response" {
  type    = string
  default = null
}
