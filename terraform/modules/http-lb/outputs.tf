output "loadbalancer_name" {
  description = "Name of the HTTP load balancer."
  value       = xcsh_http_loadbalancer.httpbin.name
}

output "loadbalancer_id" {
  description = "F5 XC identifier of the HTTP load balancer."
  value       = xcsh_http_loadbalancer.httpbin.id
}

output "origin_pool_name" {
  description = "Name of the origin pool."
  value       = xcsh_origin_pool.httpbin.name
}

output "healthcheck_name" {
  description = "Name of the health check referenced by the origin pool."
  value       = xcsh_healthcheck.httpbin.name
}

output "domains" {
  description = "Domains served by the load balancer."
  value       = xcsh_http_loadbalancer.httpbin.domains
}
