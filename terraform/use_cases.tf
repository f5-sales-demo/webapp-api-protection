resource "xcsh_swagger_object" "showcase" {
  name      = "showcase-form-native"
  namespace = var.namespace
  content   = file("${path.module}/fixtures/showcase-openapi.json")
}
resource "xcsh_swagger_object" "comparison" {
  name      = "comparison-schema"
  namespace = var.namespace
  content   = file("${path.module}/fixtures/comparison-openapi.json")
}
module "use_case" {
  for_each         = toset(["waf", "schema", "endpoint", "rate", "mud"])
  source           = "./modules/comparison"
  namespace        = var.namespace
  category         = each.key
  origin_pool_name = module.http_lb.origin_pool_name
  swagger_path     = xcsh_swagger_object.comparison.path
}
output "use_cases" {
  description = "Simultaneous read-only protection comparisons."
  value       = { for category, pair in module.use_case : category => pair.endpoints }
}
