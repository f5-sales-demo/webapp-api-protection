output "namespace_name" {
  description = "Namespace managed independently of application resources."
  value       = xcsh_namespace.this.name
}

output "namespace_id" {
  description = "Provider resource ID, not the live system_metadata UID; UID preservation is verified by the lifecycle runner."
  value       = xcsh_namespace.this.id
}
