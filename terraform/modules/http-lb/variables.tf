variable "namespace" {
  description = "F5 XC namespace for the load balancer and origin pool."
  type        = string
}

variable "lb_domains" {
  description = "Domains the HTTP load balancer serves (matched on the Host/authority header)."
  type        = list(string)
}

variable "origin_ip" {
  description = "Public IP address of the origin server the pool forwards to (the Azure origin server's public IP)."
  type        = string
}

variable "origin_port" {
  description = "TCP port on the origin."
  type        = number
  default     = 80
}

variable "health_check_path" {
  description = "HTTP path the health check probes on the origin. The Azure origin server's nginx returns HTTP 200 on /health for any Host."
  type        = string
  default     = "/health"
}

variable "labels" {
  description = "Labels applied to the load balancer and origin pool."
  type        = map(string)
  default     = {}
}

variable "waf_mode" {
  description = "App firewall enforcement mode: blocking (actively block) or monitoring (detect only)."
  type        = string
  default     = "blocking"

  validation {
    condition     = contains(["blocking", "monitoring"], var.waf_mode)
    error_message = "waf_mode must be \"blocking\" or \"monitoring\"."
  }
}

variable "csd_enabled" {
  description = "Enable Client-Side Defense on the load balancer (inject the CSD telemetry JavaScript on all pages). Requires the CSD tenant addon."
  type        = bool
  default     = true
}
