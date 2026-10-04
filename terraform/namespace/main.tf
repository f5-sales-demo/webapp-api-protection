# Persistent foundation: this root owns only the namespace, independently of
# the application root. Application destroy must never destroy this root.
# The lifecycle runner supplies an absolute path to namespace.tfstate outside
# the checkout and a separate namespace-data TF_DATA_DIR with native locking.
terraform {
  required_version = ">= 1.8"

  required_providers {
    xcsh = {
      source  = "f5-sales-demo/xcsh"
      version = "= 13.0.3"
    }
  }

  backend "local" {}
}

provider "xcsh" {}

variable "namespace" {
  description = "Fixed persistent namespace for the web application showcase."
  type        = string
  default     = "webapp-api-protection"

  validation {
    condition     = var.namespace == "webapp-api-protection"
    error_message = "This foundation manages only webapp-api-protection; other namespaces cannot be adopted."
  }
}

# An existing namespace is imported only after its live UID matches the
# lifecycle receipt. Declaring this resource does not mean it was created by
# Terraform. Namespace metadata has no containing namespace field.
resource "xcsh_namespace" "this" {
  name = var.namespace

  lifecycle {
    prevent_destroy = true
  }
}
