# Root passthrough for LPC-5b origin_pool tuning. Defaults mirror the module (0-change).
variable "origin_lb_algorithm" {
  type    = string
  default = "ROUND_ROBIN"
}
variable "origin_endpoint_selection" {
  type    = string
  default = "DISTRIBUTED"
}
variable "origin_connection_timeout" {
  type    = number
  default = null
}
variable "origin_http_idle_timeout" {
  type    = number
  default = null
}
