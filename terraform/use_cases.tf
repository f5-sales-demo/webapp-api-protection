locals {
  showcase_schema_content   = file("${path.module}/fixtures/showcase-openapi.json")
  comparison_schema_content = file("${path.module}/fixtures/comparison-openapi.json")
}

resource "xcsh_swagger_object" "showcase" {
  name      = "showcase-form-${substr(sha256(local.showcase_schema_content), 0, 32)}"
  namespace = var.namespace
  content   = local.showcase_schema_content
  lifecycle { create_before_destroy = true }
}
resource "xcsh_swagger_object" "comparison" {
  name      = "comparison-${substr(sha256(local.comparison_schema_content), 0, 32)}"
  namespace = var.namespace
  content   = local.comparison_schema_content
  lifecycle { create_before_destroy = true }
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
