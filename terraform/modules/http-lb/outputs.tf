output "loadbalancer_name" {
  description = "Name of the HTTP load balancer."
  value       = xcsh_http_loadbalancer.this.name
}

output "loadbalancer_id" {
  description = "F5 XC identifier of the HTTP load balancer."
  value       = xcsh_http_loadbalancer.this.id
}

output "origin_pool_name" {
  description = "Name of the origin pool."
  value       = xcsh_origin_pool.origin.name
}

output "healthcheck_name" {
  description = "Name of the health check referenced by the origin pool."
  value       = xcsh_healthcheck.origin.name
}

output "domains" {
  description = "Domains served by the load balancer."
  value       = xcsh_http_loadbalancer.this.domains
}

output "app_firewall_name" {
  description = "Name of the app firewall (WAF) attached to the load balancer."
  value       = xcsh_app_firewall.this.name
}

output "waf_mode" {
  description = "Enforcement mode of the attached app firewall."
  value       = var.waf_mode
}

output "csd_enabled" {
  description = "Whether Client-Side Defense JavaScript injection is enabled on the load balancer."
  value       = var.csd_enabled
}

output "mud_enabled" {
  description = "Whether Malicious User Detection (with auto-mitigation) is enabled on the load balancer."
  value       = var.mud_enabled
}

output "mud_user_id" {
  description = "Effective MUD user-identification method (client_ip or user_identification)."
  value       = var.mud_user_id
}

output "mud_mitigation" {
  description = "Effective MUD mitigation action per threat level (low/medium/high)."
  value       = var.mud_mitigation
}

output "mud_challenge_mode" {
  description = "Effective MUD challenge mode (none/enable_challenge/policy_based_challenge)."
  value       = var.mud_challenge_mode
}
