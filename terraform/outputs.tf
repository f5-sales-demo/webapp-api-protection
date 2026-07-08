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

output "domains" {
  description = "Domains served by the load balancer."
  value       = module.http_lb.domains
}
