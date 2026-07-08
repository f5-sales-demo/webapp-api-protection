terraform {
  # Azure Blob Storage remote state, configured as a PARTIAL backend: no
  # environment-specific values are hardcoded here. Supply them at init time.
  #
  #   CI:    terraform init -backend-config="resource_group_name=$RG" \
  #                         -backend-config="storage_account_name=$SA" \
  #                         -backend-config="container_name=$CONTAINER" \
  #                         -backend-config="key=$KEY"
  #          (values from GitHub Actions repository variables; see .github/workflows/terraform.yml)
  #   Local: terraform init -backend-config=backend.hcl   (copy backend.hcl.example; gitignored)
  #
  # State reuses the shared account bootstrapped for the DNS use case
  # (resource group f5-sales-demo-tfstate / account f5salesdemotfstate /
  # container tfstate) with a distinct key (webapp-api-protection.tfstate), so
  # no new bootstrap is required. Auth is the storage account access key via the
  # ARM_ACCESS_KEY environment variable (never committed).
  backend "azurerm" {}
}
