output "loadbalancer_name" {
  description = "Name of the managed HTTP load balancer."
  value       = module.http_lb.loadbalancer_name
}

output "loadbalancer_id" {
  description = "F5 XC identifier of the HTTP load balancer."
  value       = module.http_lb.loadbalancer_id
}

output "origin_pool_name" {
  description = "Name of the managed origin pool."
  value       = module.http_lb.origin_pool_name
}

output "healthcheck_name" {
  description = "Name of the health check referenced by the origin pool."
  value       = module.http_lb.healthcheck_name
}

output "domains" {
  description = "Domains served by the load balancer."
  value       = module.http_lb.domains
}

output "app_firewall_name" {
  description = "Name of the app firewall (WAF) attached to the load balancer."
  value       = module.http_lb.app_firewall_name
}

output "waf_mode" {
  description = "Enforcement mode of the attached app firewall."
  value       = module.http_lb.waf_mode
}

# --- Azure origin server ------------------------------------------------------

output "origin_server_public_ip" {
  description = "Public IP of the Azure origin server the load balancer forwards to."
  value       = module.origin_server.public_ip
}

output "origin_server_ssh" {
  description = "SSH command for the Azure origin server."
  value       = module.origin_server.ssh_command
}

output "origin_server_urls" {
  description = "Direct URLs on the origin server (bypassing the load balancer)."
  value = {
    health     = module.origin_server.health_check_url
    httpbin    = module.origin_server.httpbin_url
    juice_shop = module.origin_server.juice_shop_url
    dvwa       = module.origin_server.dvwa_url
    vampi      = module.origin_server.vampi_url
    crapi      = module.origin_server.crapi_url
  }
}

# --- Azure traffic generator --------------------------------------------------

output "traffic_generator_public_ip" {
  description = "Public IP of the Azure traffic generator."
  value       = module.traffic_generator.public_ip
}

output "traffic_generator_target" {
  description = "FQDN the traffic generator drives load at (the load balancer)."
  value       = module.traffic_generator.target_fqdn
}

output "traffic_generator_ssh" {
  description = "SSH command for the Azure traffic generator."
  value       = module.traffic_generator.ssh_command
}
