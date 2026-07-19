# LBA: load-balancing algorithm (loadbalancer_algorithm oneof). round_robin is the server default
# (omit -> materialized + import-suppressed). The other arms are emitted explicitly. ring_hash
# carries a hash_policy list. cookie_stickiness is intentionally excluded: a live PUT probe returns
# 500 ("server error in processing request") for every param shape on this tenant.
variable "lb_algorithm" {
  description = "LB load-balancing algorithm: round_robin (default) | least_active | random | source_ip_stickiness | ring_hash. ring_hash uses ring_hash_policies (header_name / source_ip / terminal)."
  type = object({
    mode = optional(string, "round_robin")
    ring_hash_policies = optional(list(object({
      header_name = optional(string)
      source_ip   = optional(bool, false)
      terminal    = optional(bool, false)
    })), [])
  })
  default = {}

  validation {
    condition     = contains(["round_robin", "least_active", "random", "source_ip_stickiness", "ring_hash"], var.lb_algorithm.mode)
    error_message = "lb_algorithm.mode must be round_robin, least_active, random, source_ip_stickiness, or ring_hash (cookie_stickiness is excluded — tenant returns 500)."
  }
  validation {
    condition     = var.lb_algorithm.mode == "ring_hash" || length(var.lb_algorithm.ring_hash_policies) == 0
    error_message = "lb_algorithm.ring_hash_policies is only valid when mode = ring_hash."
  }
}
