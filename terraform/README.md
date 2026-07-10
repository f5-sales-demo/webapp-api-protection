# webapp-api-protection Terraform reference plan

A comprehensive, multi-provider reference plan that stands up a complete demo of
F5 Distributed Cloud web-app & API protection **end-to-end**, deploying every
piece itself — no shared/out-of-band dependency objects:

- **Azure origin server** (`modules/origin-server`) — a Linux VM running nginx +
  Docker with a suite of demo/vulnerable apps (httpbin, OWASP Juice Shop, DVWA,
  VAmPI, crAPI, DVGA, RESTaurant, whoami) on port 80, health endpoint `/health`.
  This is the real backend the load balancer forwards to.
- **F5 XC namespace + HTTP load balancer** (`modules/http-lb`) — the plan creates
  its own `xcsh_namespace`, then an HTTP load balancer + origin pool advertised on
  the F5 XC public VIP, serving `www.f5-sales-demo.com` and `api.f5-sales-demo.com`.
  The origin pool points at the Azure origin server's **public IP** (port 80,
  health check `/health`). F5 XC auto-manages the DNS records for those domains
  (the load balancer sets `http.dns_volterra_managed`, and the `f5-sales-demo.com`
  zone has `allow_http_lb_managed_records` enabled — see the `dns` repo). The load
  balancer enforces two app-security controls (see **Security controls** below):
  a **WAF** (`xcsh_app_firewall`) and **API Discovery** (`enable_api_discovery`).
- **Azure traffic generator** (`modules/traffic-generator`) — a Linux VM with load
  and attack tooling (wrk, vegeta, hey, nuclei, sqlmap, ZAP, …) that drives
  **continuous** HTTP load at the load balancer FQDN via a systemd timer, so the
  WAF / API-protection controls always have live traffic to analyze.

It targets the **production tenant** (`https://f5-sales-demo.console.ves.volterra.io`,
internet-reachable), with remote state in Azure Blob Storage.

## Security controls

The `http-lb` module attaches four F5 XC app-security controls to the load balancer:

- **WAF** — `xcsh_app_firewall.this` (`webapp-api-protection-waf`) is referenced by the
  load balancer's `app_firewall {}` block. Enforcement mode is set by the `waf_mode`
  variable: `blocking` (default — actively blocks malicious requests with an F5 XC block
  page) or `monitoring` (detect & log only). The firewall declares the server-default
  oneof markers (`default_detection_settings {}`, `allow_all_response_codes {}`,
  `use_default_blocking_page {}`, `default_bot_setting {}`, `default_anonymization {}`)
  so apply/plan/import stay clean.
- **API Discovery** — the load balancer's `enable_api_discovery {}` block turns on
  learn-from-traffic API discovery. It is independent of API-definition *enforcement*
  (`api_specification` / `xcsh_api_definition`), so no separate resource is required;
  F5 XC learns the API schema from the live traffic the generator produces. Discovered
  endpoints appear asynchronously in the F5 XC console (Web App & API Protection → API
  Discovery).
- **Client-Side Defense** — the load balancer's `client_side_defense { policy {
  js_insert_all_pages {} } }` block injects the F5 XC telemetry JavaScript into served
  pages to detect Magecart/formjacking/skimming (PCI DSS 6.4.3 / 11.6.1). Toggled by the
  `csd_enabled` variable (default `true`). CSD requires the tenant Client-Side Defense
  addon: the plan asserts that dependency via a `data xcsh_addon_service_activation_status`
  guard (state `AS_SUBSCRIBED`) rather than managing the subscription — tenant entitlement
  is owned by a separate tenant plan. The served root domain is registered with the CSD
  reporting engine via `xcsh_protected_domain` (system namespace). Telemetry beacons and
  detected scripts appear in the console (Web App & API Protection → Client-Side Defense).
- **Malicious User Detection** — the load balancer's `enable_malicious_user_detection {}`
  block scores per-user behavior into threat levels (users identified by the server-default
  client IP). Auto-mitigation is wired through the `enable_challenge` block, which references
  an `xcsh_malicious_user_mitigation` policy (`webapp-api-protection-mud`) that escalates by
  threat level: low → JavaScript challenge, medium → CAPTCHA, high → temporary block. Toggled
  by the `mud_enabled` variable (default `true`). MUD is a WAAP capability: the plan asserts
  the tenant WAAP entitlement via a `data xcsh_addon_service_activation_status` guard
  (`f5xc-waap-standard`, state `AS_SUBSCRIBED`) rather than managing the subscription. Flagged
  users and mitigation actions appear in the console (Web App & API Protection → Malicious
  Users).

## Architecture

```
                 (continuous load)
 traffic-generator VM ───────────────► www/api.f5-sales-demo.com
   (Azure, wrk/vegeta/nuclei/…)              │  (F5 XC managed DNS → public VIP)
                                             ▼
                                  F5 XC HTTP load balancer  (modules/http-lb)
                                             │  default_route_pools → origin-pool
                                             ▼
                                  origin pool (public_ip :80, health /health)
                                             │
                                             ▼
                              origin-server VM  (Azure, nginx + Docker apps)
```

## Layout

| Path | Purpose |
| --- | --- |
| `versions.tf` | Terraform + provider pins (`xcsh`, `azurerm`, `azuread`) |
| `providers.tf` | `xcsh` (env auth) + `azurerm`/`azuread` (subscription from var, env auth) |
| `backend.tf` | Azure Blob Storage remote state (`azurerm`, access-key auth) |
| `variables.tf` / `terraform.tfvars.example` | Inputs (F5 XC + Azure) |
| `main.tf` / `outputs.tf` | Module wiring (origin → LB → traffic generator) |
| `modules/http-lb/` | F5 XC HTTP load balancer + origin pool → Azure origin IP |
| `modules/origin-server/` | Azure origin server VM (nginx + Docker demo apps) |
| `modules/traffic-generator/` | Azure traffic generator VM (continuous load) |

The `origin-server` and `traffic-generator` modules were incorporated from the
standalone example plans of the same name. As child modules they have their own
`providers.tf` stripped — they inherit the `azurerm`/`azuread` providers from this
root — and this plan deploys its **own** Azure resources (named
`*-webapp-api-protection-*`), not any resources deployed by those other plans.

## Prerequisites

- Terraform >= 1.5
- The `xcsh` provider. Locally via `dev_overrides` (below); CI uses the released
  version pinned in `versions.tf` from the registry.
- The `azurerm` (`~> 4.0`) and `azuread` (`~> 3.0`) providers (downloaded on init).
- Network access to the production tenant (`https://f5-sales-demo.console.ves.volterra.io`).
- **Azure auth**: `az login` locally (or a service principal via `ARM_*` in CI),
  with rights to create resource groups / VMs / networking in the subscription.
- An SSH public key on disk (default `~/.ssh/id_ed25519.pub`) — installed on both VMs.
- Azure remote-state backend (shared with the DNS use case; already bootstrapped).
  `ARM_ACCESS_KEY` via `az storage account keys list -g f5-sales-demo-tfstate -n
  f5salesdemotfstate --query '[0].value' -o tsv`.
- The `f5-sales-demo.com` DNS zone (the `dns` repo) applied with
  `allow_http_lb_managed_records = true` and `www`/`api` not statically managed.

### Local provider (dev_overrides)

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

Under `dev_overrides` the `xcsh` provider is not downloaded, but `terraform init`
is still required once (backend + `azurerm`/`azuread`).

### Configuration (nothing environment-specific is hardcoded)

| Value | CI source | Local source |
| --- | --- | --- |
| Backend coords (`resource_group_name`, `storage_account_name`, `container_name`, `key`) | GitHub **variables** `TFSTATE_*`, via `-backend-config` | `backend.hcl` (copy `backend.hcl.example`; gitignored) |
| `namespace`, `lb_domains` | GitHub **variables** `WEBAPP_NAMESPACE` / `WEBAPP_LB_DOMAINS` → `TF_VAR_*` | `terraform.tfvars` (copy the example; gitignored) or `TF_VAR_*` |
| `subscription_id`, `location`, VM sizes, `ssh_public_key_path` | GitHub **variables** `TF_VAR_*` | `terraform.tfvars` |
| `ARM_ACCESS_KEY` (state auth) | GitHub **secret** | `export ARM_ACCESS_KEY=...` |
| `XCSH_API_URL`, `XCSH_API_TOKEN` (provider auth) | GitHub **secrets** | `export XCSH_API_URL=... XCSH_API_TOKEN=...` |
| Azure identity (`ARM_CLIENT_ID`/`ARM_CLIENT_SECRET`/`ARM_TENANT_ID`/`ARM_SUBSCRIPTION_ID`) | GitHub **secrets** (service principal) | `az login` |

```sh
export XCSH_API_URL="https://f5-sales-demo.console.ves.volterra.io"
export XCSH_API_TOKEN="<production-api-token>"
export ARM_ACCESS_KEY="$(az storage account keys list -g f5-sales-demo-tfstate -n f5salesdemotfstate --query '[0].value' -o tsv)"
az login                                        # Azure auth for the VM resources
cp backend.hcl.example backend.hcl              # key = webapp-api-protection.tfstate
cp terraform.tfvars.example terraform.tfvars    # set subscription_id, sizes, etc.
```

## Usage

```sh
terraform init -backend-config=backend.hcl
terraform fmt -check -recursive
terraform plan
terraform apply
# The origin VM runs cloud-init (Docker + apps) for several minutes after apply.
curl -s "http://$(terraform output -raw origin_server_public_ip)/health"  # origin nginx → 200 JSON
curl -s "http://www.f5-sales-demo.com/health"                             # through the LB once healthy
# Traffic generator drives continuous load automatically (systemd tgen-continuous.timer):
ssh "$(terraform output -raw traffic_generator_ssh | cut -d' ' -f2-)" \
  'tail -f /opt/traffic-generator/results/continuous.log'
terraform destroy
```

> The plan **creates its own namespace** (`xcsh_namespace`, default
> `webapp-api-protection`) and the load balancer / origin pool inside it, and its
> own Azure resource groups (`rg-origin-server-webapp-api-protection-*`,
> `rg-traffic-generator-webapp-api-protection-*`). F5 XC auto-manages the
> `www`/`api.f5-sales-demo.com` records to the load balancer VIP.
