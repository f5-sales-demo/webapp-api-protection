# webapp-api-protection Terraform reference plan

Terraform plan that provisions an F5 Distributed Cloud HTTP load balancer and
origin pool (pointing at [httpbin](https://httpbin.org)) using the
[`terraform-provider-xcsh`](https://github.com/f5-sales-demo/terraform-provider-xcsh)
provider. It targets the **staging tenant** (`https://nferreira.staging.volterra.us`,
VPN-accessible only), with remote state in Azure Blob Storage.

This is the iteration-1 scaffold. Later iterations attach a web application
firewall (`xcsh_app_firewall`) and API protection (`xcsh_api_definition`) to the
same load balancer.

## Layout

| Path | Purpose |
| --- | --- |
| `versions.tf` | Terraform + provider version pins |
| `providers.tf` | `xcsh` provider (auth from environment) |
| `backend.tf` | Azure Blob Storage remote state (`azurerm`, access-key auth) |
| `variables.tf` / `terraform.tfvars.example` | Inputs (namespace, lb_domain, origin, labels) |
| `main.tf` / `outputs.tf` | Module wiring |
| `modules/http-lb/` | HTTP load balancer + origin pool → httpbin |

## Prerequisites

- Terraform >= 1.5
- The `xcsh` provider. Locally it is consumed via `dev_overrides` (below); CI uses the released
  version pinned in `versions.tf` from the registry.
- Network access to the staging tenant — connect the VPN before running `plan`/`apply`.
- Azure remote-state backend (shared with the DNS use case; already bootstrapped).

### Local provider (dev_overrides)

Build the provider and point Terraform at the binary — each rebuild is picked up with no reinstall:

```sh
make -C ../../terraform-provider-xcsh build   # adjust path to your checkout

cat > ~/.terraformrc <<'RC'
provider_installation {
  dev_overrides {
    "registry.terraform.io/f5-sales-demo/xcsh" = "/absolute/path/to/terraform-provider-xcsh"
  }
  direct {}
}
RC
```

Under `dev_overrides` the provider is not downloaded, but `terraform init` is still required
once to configure the `azurerm` backend.

### Configuration (nothing environment-specific is hardcoded)

No environment values live in the `.tf` files. Supply them at runtime:

| Value | CI source | Local source |
| --- | --- | --- |
| Backend coords (`resource_group_name`, `storage_account_name`, `container_name`, `key`) | GitHub **variables** `TFSTATE_*`, passed via `-backend-config` | `backend.hcl` (copy `backend.hcl.example`; gitignored) |
| `namespace`, `lb_domain` | GitHub **variables** `TF_VAR_namespace` / `TF_VAR_lb_domain` | `terraform.tfvars` (copy the example; gitignored) or `TF_VAR_*` |
| `ARM_ACCESS_KEY` (state auth) | GitHub **secret** | `export ARM_ACCESS_KEY=...` |
| `XCSH_API_URL`, `XCSH_API_TOKEN` (provider auth) | GitHub **secrets** | `export XCSH_API_URL=... XCSH_API_TOKEN=...` |

```sh
export XCSH_API_URL="https://nferreira.staging.volterra.us"
export XCSH_API_TOKEN="<staging-api-token>"    # provider auth (header: APIToken <token>)
export ARM_ACCESS_KEY="<storage-account-key>"  # azurerm backend auth (never committed)
cp backend.hcl.example backend.hcl             # key = webapp-api-protection.tfstate
cp terraform.tfvars.example terraform.tfvars   # sets namespace, lb_domain, origin
```

## Usage

```sh
terraform init -backend-config=backend.hcl   # partial backend: coords from backend.hcl
terraform fmt -check
terraform validate
terraform plan
terraform apply
curl -s "http://<lb_domain>/get"             # httpbin echoes the request as JSON (HTTP 200)
terraform destroy
```

> The HTTP load balancer and origin pool live in a **user namespace** (`var.namespace`) — unlike
> DNS objects, which are fixed to `system`. Set `namespace` to a namespace that exists in the
> staging tenant.
