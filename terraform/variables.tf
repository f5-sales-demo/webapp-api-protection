variable "namespace" {
  description = "F5 XC namespace this plan creates and deploys the load balancer / origin pool into. HTTP load balancer and origin pool objects live in a user namespace (unlike DNS objects, which are system-scoped)."
  type        = string
  default     = "webapp-api-protection"
}

variable "lb_domains" {
  description = "Domains the HTTP load balancer serves. On production these are www.f5-sales-demo.com and api.f5-sales-demo.com; F5 XC auto-manages their DNS records because the f5-sales-demo.com zone has allow_http_lb_managed_records enabled."
  type        = list(string)
}

variable "origin_dns_name" {
  description = "Public DNS name of the origin server the pool forwards to. Defaults to the public httpbin service."
  type        = string
  default     = "httpbin.org"
}

variable "origin_port" {
  description = "TCP port on the origin. httpbin serves HTTP (200, no redirect) on 80, so plaintext to 80 is the simplest working path."
  type        = number
  default     = 80
}

variable "health_check_path" {
  description = "HTTP path the origin-pool health check probes. httpbin's /status/200 always returns 200."
  type        = string
  default     = "/status/200"
}

variable "labels" {
  description = "Labels applied to managed objects."
  type        = map(string)
  default = {
    managed_by = "terraform"
    use_case   = "webapp-api-protection"
  }
}
