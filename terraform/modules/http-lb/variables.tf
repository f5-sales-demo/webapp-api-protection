variable "namespace" {
  description = "F5 XC namespace for the load balancer and origin pool."
  type        = string
}

variable "lb_domains" {
  description = "Domains the HTTP load balancer serves (matched on the Host/authority header)."
  type        = list(string)
}

variable "origin_dns_name" {
  description = "Public DNS name of the origin server the pool forwards to."
  type        = string
  default     = "httpbin.org"
}

variable "origin_port" {
  description = "TCP port on the origin."
  type        = number
  default     = 80
}

variable "health_check_path" {
  description = "HTTP path the health check probes on the origin. httpbin's /status/200 always returns 200."
  type        = string
  default     = "/status/200"
}

variable "labels" {
  description = "Labels applied to the load balancer and origin pool."
  type        = map(string)
  default     = {}
}
