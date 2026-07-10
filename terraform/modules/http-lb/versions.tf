terraform {
  required_version = ">= 1.5"

  required_providers {
    xcsh = {
      source  = "f5-sales-demo/xcsh"
      version = ">= 3.64.0"
    }
  }
}
