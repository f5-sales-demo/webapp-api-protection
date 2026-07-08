variable "namespace" {
  description = "F5 XC namespace the load balancer and origin pool are created in (required; supplied via TF_VAR_namespace / a GitHub Actions variable / tfvars). Unlike DNS objects, HTTP load balancer and origin pool objects live in a user namespace."
  type        = string
}

variable "lb_domain" {
  description = "Domain the HTTP load balancer serves (required; supplied via TF_VAR_lb_domain / a GitHub Actions variable / tfvars). In the staging tenant use a domain delegated to / reachable in that environment."
  type        = string
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
