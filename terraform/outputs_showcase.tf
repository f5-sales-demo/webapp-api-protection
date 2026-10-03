output "showcase" {
  description = "Application endpoints, VM access metadata, and configured protection modes for the unattended showcase lifecycle."
  value = {
    application_manifest_sha256 = filesha256("${path.module}/origin-applications.json")
    application_urls            = { for app in local.origin_applications : app.id => "http://${module.origin_server.public_ip}${app.prefix}" }
    origin_source               = { commit = var.origin_commit, archive_sha256 = var.origin_archive_sha256, installer_sha256 = var.origin_installer_sha256, python_installer_sha256 = var.origin_python_installer_sha256 }
    generator_source            = { commit = var.traffic_generator_commit, archive_sha256 = var.traffic_generator_sha256, installer_sha256 = var.traffic_generator_installer_sha256 }
    namespace                   = var.namespace
    domains                     = module.http_lb.domains
    loadbalancer_name           = module.http_lb.loadbalancer_name
    origin = {
      public_ip      = module.origin_server.public_ip
      resource_group = module.origin_server.resource_group_name
      vm_name        = module.origin_server.vm_name
      id             = module.origin_server.vm_id
      admin_username = local.azure_admin_username
    }
    generator = {
      public_ip      = module.traffic_generator.public_ip
      resource_group = module.traffic_generator.resource_group_name
      vm_name        = module.traffic_generator.vm_name
      id             = module.traffic_generator.vm_id
      admin_username = local.azure_admin_username
    }
    protection = {
      waf_mode                     = var.waf_mode
      csd_enabled                  = var.csd_enabled
      mud_enabled                  = var.mud_enabled
      mud_user_id                  = var.mud_user_id
      api_definition_choice        = var.api_definition_choice
      api_specification_validation = var.api_specification_validation
      api_validation_request_mode  = var.api_validation_request_mode
      rate_limiting_mode           = var.rate_limit_choice
    }
  }
}
