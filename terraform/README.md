# webapp-api-protection Terraform reference plan

Terraform plan that provisions an F5 Distributed Cloud HTTP load balancer and
origin pool (pointing at [httpbin](https://httpbin.org)) using the
[`terraform-provider-xcsh`](https://github.com/f5-sales-demo/terraform-provider-xcsh)
provider. It targets the **production tenant**
(`https://f5-sales-demo.console.ves.volterra.io`, internet-reachable), with remote
state in Azure Blob Storage.

The plan creates its own namespace (`xcsh_namespace`) and an HTTP load balancer
serving `www.f5-sales-demo.com` and `api.f5-sales-demo.com`. F5 XC auto-manages the
DNS records for those domains (the load balancer sets `http.dns_volterra_managed`,
and the `f5-sales-demo.com` zone has `allow_http_lb_managed_records` enabled — see
the `dns` repo). Later iterations attach a web application firewall
(`xcsh_app_firewall`) and API protection (`xcsh_api_definition`).

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
- Network access to the production tenant (`https://f5-sales-demo.console.ves.volterra.io`, internet-reachable).
- Azure remote-state backend (shared with the DNS use case; already bootstrapped). `ARM_ACCESS_KEY`
  can be fetched via `az storage account keys list -g f5-sales-demo-tfstate -n f5salesdemotfstate --query '[0].value' -o tsv`.
- The `f5-sales-demo.com` DNS zone (the `dns` repo) applied with `allow_http_lb_managed_records = true`
  and `www`/`api` **not** statically managed — this plan's load balancer owns those names.

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
| `namespace`, `lb_domains` | GitHub **variables** `WEBAPP_NAMESPACE` / `WEBAPP_LB_DOMAINS` (JSON list) → `TF_VAR_*` | `terraform.tfvars` (copy the example; gitignored) or `TF_VAR_*` |
| `ARM_ACCESS_KEY` (state auth) | GitHub **secret** | `export ARM_ACCESS_KEY=...` |
| `XCSH_API_URL`, `XCSH_API_TOKEN` (provider auth) | GitHub **secrets** | `export XCSH_API_URL=... XCSH_API_TOKEN=...` |

```sh
export XCSH_API_URL="https://f5-sales-demo.console.ves.volterra.io"
export XCSH_API_TOKEN="<production-api-token>"  # provider auth (header: APIToken <token>)
export ARM_ACCESS_KEY="$(az storage account keys list -g f5-sales-demo-tfstate -n f5salesdemotfstate --query '[0].value' -o tsv)"
cp backend.hcl.example backend.hcl             # key = webapp-api-protection.tfstate
cp terraform.tfvars.example terraform.tfvars   # sets namespace, lb_domains, origin
```

## Usage

```sh
terraform init -backend-config=backend.hcl   # partial backend: coords from backend.hcl
terraform fmt -check
terraform validate
terraform plan
terraform apply
curl -s "http://www.f5-sales-demo.com/get"   # httpbin echoes the request as JSON (HTTP 200)
terraform destroy
```

> The plan **creates its own namespace** (`xcsh_namespace`, default `webapp-api-protection`) and the
> load balancer / origin pool inside it — no dependency object is created out-of-band. Unlike DNS
> objects (fixed to `system`), these live in that user namespace. F5 XC auto-manages the
> `www`/`api.f5-sales-demo.com` records to the load balancer VIP (`http.dns_volterra_managed = true`).
