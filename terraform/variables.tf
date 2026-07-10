variable "namespace" {
  description = "F5 XC namespace this plan creates and deploys the load balancer / origin pool into. HTTP load balancer and origin pool objects live in a user namespace (unlike DNS objects, which are system-scoped)."
  type        = string
  default     = "webapp-api-protection"
}

variable "lb_domains" {
  description = "Domains the HTTP load balancer serves. On production these are www.f5-sales-demo.com and api.f5-sales-demo.com; F5 XC auto-manages their DNS records because the f5-sales-demo.com zone has allow_http_lb_managed_records enabled."
  type        = list(string)
}

variable "origin_port" {
  description = "TCP port on the origin. The Azure origin server serves HTTP (nginx) on 80, so plaintext to 80 is the working path."
  type        = number
  default     = 80
}

variable "health_check_path" {
  description = "HTTP path the origin-pool health check probes. The Azure origin server's nginx returns HTTP 200 JSON on /health for any Host."
  type        = string
  default     = "/health"
}

variable "labels" {
  description = "Labels applied to managed objects."
  type        = map(string)
  default = {
    managed_by = "terraform"
    use_case   = "webapp-api-protection"
  }
}

variable "waf_mode" {
  description = "App firewall enforcement mode on the load balancer: blocking (actively block malicious requests) or monitoring (detect and log only)."
  type        = string
  default     = "blocking"

  validation {
    condition     = contains(["blocking", "monitoring"], var.waf_mode)
    error_message = "waf_mode must be \"blocking\" or \"monitoring\"."
  }
}

variable "csd_enabled" {
  description = "Enable Client-Side Defense: inject the F5 XC telemetry JavaScript on all pages and register the served domain with the CSD reporting engine. Requires the tenant CSD addon (verified via a data-source guard, not managed here)."
  type        = bool
  default     = true
}

variable "mud_enabled" {
  description = "Enable Malicious User Detection: score per-user behavior into threat levels and auto-mitigate (JS challenge / CAPTCHA / temporary block) via a malicious_user_mitigation policy. Requires the tenant MUD addon (verified via a data-source guard, not managed here)."
  type        = bool
  default     = true
}

# ---------------------------------------------------------
# Azure (origin server + traffic generator this plan deploys)
# ---------------------------------------------------------

variable "subscription_id" {
  description = "Azure subscription ID the origin-server and traffic-generator VMs are deployed into. Supply via TF_VAR_subscription_id / terraform.tfvars (never hardcoded in .tf). Locally derive with: az account show --query id -o tsv."
  type        = string
}

variable "location" {
  description = "Azure region for the origin server and traffic generator."
  type        = string
  default     = "eastus2"
}

variable "ssh_public_key_path" {
  description = "Path to the SSH public key installed on the Azure VMs (admin login)."
  type        = string
  default     = "~/.ssh/id_ed25519.pub"
}

variable "environment" {
  description = "Environment label used in Azure resource-group naming and tags (e.g. lab, preprod)."
  type        = string
  default     = "lab"
}

variable "deployer" {
  description = "Override for the Azure deployer identifier used in resource naming/tags. Empty = auto-resolve from Azure AD. Set explicitly for service-principal / managed-identity (CI) auth, where the AD user lookup does not resolve."
  type        = string
  default     = ""
}

variable "azure_tags" {
  description = "Extra tags merged onto the Azure resources (origin server + traffic generator)."
  type        = map(string)
  default     = {}
}

variable "origin_vm_size" {
  description = "Azure VM size for the origin server (runs Docker workloads: httpbin, juice-shop, dvwa, vampi, ...)."
  type        = string
  default     = "Standard_D16s_v3"
}

variable "traffic_gen_vm_size" {
  description = "Azure VM size for the traffic generator (load + attack tooling)."
  type        = string
  default     = "Standard_F16s_v2"
}

variable "traffic_gen_tool_tier" {
  description = "Traffic-generator tool installation tier: standard (default) or full (adds ZAP, Metasploit)."
  type        = string
  default     = "standard"
}
