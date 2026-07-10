# ---------------------------------------------------------
# General
# ---------------------------------------------------------
# NOTE: subscription_id is intentionally NOT declared here. As a child module,
# this config inherits the azurerm/azuread providers (and their subscription_id)
# from the root module — see ../../providers.tf.

variable "component" {
  description = "Component name used in resource naming and tags (e.g. origin-server, traffic-generator)"
  type        = string
}

variable "deployer" {
  description = "Override for deployer identifier (auto-resolved from Azure AD if empty). Required for service principal or managed identity authentication."
  type        = string
  default     = ""
}

variable "location" {
  description = "Azure region for all resources"
  type        = string
  default     = "eastus2"
}

variable "environment" {
  description = "Environment label used in resource group naming and tags"
  type        = string
  default     = "lab"
}

variable "tags" {
  description = "Additional tags merged with standard tags (component, environment, deployer, managed_by)"
  type        = map(string)
  default     = {}
}

# ---------------------------------------------------------
# Network
# ---------------------------------------------------------

variable "address_space" {
  description = "Virtual network address space"
  type        = list(string)
}

variable "subnet_prefixes" {
  description = "Subnet address prefixes"
  type        = list(string)
}

variable "security_rules" {
  description = "Inbound NSG allow rules (Tcp from any). Each: name, priority, and destination port."
  type = list(object({
    name     = string
    priority = number
    port     = string
  }))
  default = []
}

# ---------------------------------------------------------
# Compute
# ---------------------------------------------------------

variable "vm_size" {
  description = "Azure VM size"
  type        = string
  default     = "Standard_D16s_v3"
}

variable "admin_username" {
  description = "SSH admin username for the VM"
  type        = string
  default     = "azureuser"
}

variable "ssh_public_key_path" {
  description = "Path to the SSH public key file"
  type        = string
  default     = "~/.ssh/id_ed25519.pub"
}

variable "disk_size_gb" {
  description = "OS disk size in GB"
  type        = number
  default     = 60
}

variable "custom_data" {
  description = "Base64-encoded cloud-init custom data for the VM"
  type        = string
}
