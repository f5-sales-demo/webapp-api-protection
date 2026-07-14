# xcsh_api_definition (SP2) — the API spec object the LB's api_specification
# references for schema enforcement. Created only when api_definition_choice is
# "specification"; otherwise the LB emits no api_specification block (server
# default disable_api_definition, import-suppressed) and this resource is absent.
#
# The API can be defined from uploaded OpenAPI files (swagger_specs = pinned
# object-store paths; see scripts/swagger-upload.sh) and/or from inventory lists.
# schema-origin is a oneof: strict is the server default (import-suppressed, so we
# omit it) and mixed is emitted explicitly.
resource "xcsh_api_definition" "this" {
  count     = var.api_definition_choice == "specification" ? 1 : 0
  name      = "${var.namespace}-api-def"
  namespace = var.namespace

  # swagger_specs is an attribute (not a block): set it only when non-empty so the
  # empty-list default stays identical to the server default (no import drift).
  swagger_specs = length(var.api_definition_swagger_specs) > 0 ? var.api_definition_swagger_specs : null

  dynamic "api_inventory_inclusion_list" {
    for_each = var.api_definition_inventory_inclusion
    content {
      method = api_inventory_inclusion_list.value.method
      path   = api_inventory_inclusion_list.value.path
    }
  }

  dynamic "api_inventory_exclusion_list" {
    for_each = var.api_definition_inventory_exclusion
    content {
      method = api_inventory_exclusion_list.value.method
      path   = api_inventory_exclusion_list.value.path
    }
  }

  dynamic "non_api_endpoints" {
    for_each = var.api_definition_non_api_endpoints
    content {
      method = non_api_endpoints.value.method
      path   = non_api_endpoints.value.path
    }
  }

  # schema-origin oneof. mixed => emit the block; strict => omit (server default,
  # suppressed on import — see terraform-provider-xcsh
  # tools/import-default-suppressions.json APIDefinition).
  dynamic "mixed_schema_origin" {
    for_each = var.api_definition_schema_origin == "mixed" ? [1] : []
    content {}
  }
}
