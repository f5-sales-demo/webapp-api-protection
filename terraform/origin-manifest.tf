locals {
  origin_applications = jsondecode(file("${path.module}/origin-applications.json")).applications
}

output "origin_application_manifest_sha256" {
  description = "Manifest digest for the pinned origin application URL contract."
  value       = filesha256("${path.module}/origin-applications.json")
}
