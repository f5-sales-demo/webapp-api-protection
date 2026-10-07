# Web App & API Protection showcase lifecycle

Run the showcase locally from the repository root. Terraform acceptance is not
security acceptance: only the private live reports establish what passed.
MUD configuration, HTTP denials, or static tests must not be presented as verified
MUD detection. Fresh joined detection and mitigation evidence is required; a
previous control proof does not certify new complete catalog passes.
Client-Side Defense (CSD) enforcement is excluded from this showcase.

## Scope and prerequisites

The lifecycle rejects checked-in F5 Distributed Cloud scope overrides: tenant
`f5-sales-demo`, namespace `webapp-api-protection`, `www.f5-sales-demo.com` and
`api.f5-sales-demo.com`. The approved Azure subscription/Entra tenant are private
operator inputs, never inferred from login. Azure runs in `eastus2`
with two 16-vCPU VMs: origin `Standard_D16s_v3` and generator `Standard_F16s_v2`.
No Customer Edge, AWS, or GCP resources are deployed.

Before invocation, provide an already-authenticated **Azure CLI user** in the
supplied subscription/tenant, F5 Distributed Cloud API credentials, and an
existing SSH key pair (default `~/.ssh/id_ed25519`). The lifecycle does not sign
in, collect credentials, retrieve storage keys, or create service principals.
An identity from another cloud is not authorization for this deployment.

Authorize the operator once, separately from login: create
`~/.local/state/waap-showcase/operator.json`
outside the checkout, in a caller-owned directory with mode **0700**. Use a
caller-owned, non-symlink file with mode **0600** containing:

```json
{
  "subscription_id": "${APPROVED_SUBSCRIPTION_ID}",
  "tenant_id": "${APPROVED_TENANT_ID}",
  "expected_azure_user": "operator@example.com"
}
```

Replace both identity placeholders and the synthetic UPN with the explicitly approved
Azure subscription, Entra tenant and human operator. Keep real IDs, user data and
credentials out of public files. The lifecycle matches that user case-insensitively
and rejects missing authorization, another user, a service principal, or a wrong
subscription/tenant before deployment. This private setup is not login automation.

Required tools: Terraform 1.8 or later, Python 3, Azure CLI, SSH, cURL and dig.
Allow access to the provider registry, the tenant API, Azure APIs and both guests.
The deployment identity needs resource-group, compute and networking permissions.
Azure CLI authentication is still required for application resources, but local state
requires no Azure storage or blob-data permissions. Tenant feature entitlements and
the existing DNS zone's managed-record support must be provisioned before the run.
The namespace must already exist. Previously created Azure storage is left untouched;
it is neither a prerequisite nor a lifecycle cleanup target.

Provider releases are pinned exactly with the root registry lock:
`f5-sales-demo/xcsh` **13.0.3**, `hashicorp/azurerm` **5.7.0**, and
`hashicorp/azuread` **3.10.0**. The lifecycle uses `TF_CLI_CONFIG_FILE=/dev/null`
to exclude development overrides. Provider 12's empty one-of selections are
object attributes (`field = {}`), not nested blocks.

## Four commands

Use existing environment authentication; never write tokens to tracked files:

```sh
export XCSH_API_URL="https://f5-sales-demo.console.ves.volterra.io"
export XCSH_API_TOKEN="<api-token>"

# Approved IDs select the existing private per-subscription data directory.
bash scripts/demo-lifecycle.sh deploy
bash scripts/demo-lifecycle.sh verify
bash scripts/demo-lifecycle.sh rebuild
bash scripts/demo-lifecycle.sh destroy
```

These are separate operations, not a sequence to run blindly. `deploy` validates
both secure local backends and the existing exact namespace. It imports that
confirmed namespace into the persistent namespace-only root when needed, then
saves and applies its guarded namespace plan before provisioning disposable
applications and creating the Terraform-owned versioned schema fixture. Namespace preparation is
part of `deploy`, not an extra manual step. Readiness, traffic and live acceptance
must pass before the application zero-change plan is applied. `verify` reads existing
ownership, checks namespace preservation and fixture integrity, runs live acceptance
and requires zero drift; it never imports, applies or repairs infrastructure.
`rebuild` consumes the exact current reviewed plan and replaces only captured demo VMs or the
owned Swagger version, preserving XC, namespace and network identities. It snapshots private
inputs/state and verifies Azure unique VM identities before rotating rebuilt host keys.
`destroy` deletes only owned disposable application resources and proves their absence;
it retains local state/receipts, namespace and shared DNS zone. Terraform deletes only the owned schema versions.
Rebuild and destroy are destructive and must only be invoked deliberately for this demo.

`plan` saves a fresh private review plan, binding and action summary without applying. `adopt` imports only the exact reviewed mapping in `adoption-review.json`, after state/content verification and backups. Existing resources are never silently adopted by deploy. See the [operator reference](../docs/en/reference/terraform-ownership.mdx) for the comparison endpoints and completion gates.

Each command accepts `--timeout-seconds` (default **1800**, whole-operation
monotonic deadline), `--state-dir` and `--config`. Configuration accepts identical
public fixed scope values, `subscription_id`, `tenant_id`, `ssh_key` and
`expected_azure_user`; a `backend` object is rejected. An explicit `--config`
replaces `~/.local/state/waap-showcase/operator.json`; files are never merged.
Each chosen-file field takes precedence over its corresponding explicit environment
input: `DEMO_AZURE_SUBSCRIPTION_ID`, `DEMO_AZURE_TENANT_ID`, `DEMO_AZURE_USER`.
Environment inputs are used only for absent fields. Missing or malformed UUIDs
block before state creation; absent human authorization blocks live operations.
No scope or operator approval is derived from current Azure or F5 login.
`--state-dir` selects data location only, not the approval file. Existing data
and receipts stay in their original subscription directory. To cut over an old
per-subscription operator file, move it to the base approval path and add the
approved IDs privately; do not copy it or migrate state. Backend secrets are not accepted.
Arbitrary Terraform variables are not shell-sourced. Do not invoke raw
`terraform apply` or `destroy`: that bypasses lifecycle ownership, preservation
and evidence gates.

## State and preservation

The default private local directory is
`~/.local/state/waap-showcase/<approved-subscription-id>/`, outside
the checkout. The lifecycle uses `umask 077`, directory mode 0700 and mode 0600
for state, backups and JSON receipts; symlink traversal is rejected. Keep this
directory between runs. It holds saved plans, provider data, deployed inputs,
outputs, known-hosts and ownership/evidence receipts. Missing receipts are not
permission to rediscover or adopt resources. SSH uses dedicated accept-new
known-hosts (TOFU); changed host keys fail closed.

The application root uses the absolute `<state-dir>/application.tfstate` path and
external `application-data` Terraform data directory. The namespace-only root at
`terraform/namespace` uses `<state-dir>/namespace.tfstate` and `namespace-data`.
Both roots use local backends and native file locking under one lifecycle operation
lock. Namespace state is never included in application destroy; its resource has
`prevent_destroy = true`. Never disable locking. This is a single-machine workflow,
not a shared backend: local locks do not coordinate separate machines or copied state.

State and saved plans can contain secrets. Keep credentials out of tracked files
and never commit state, backups or receipts. The operator is responsible for
secure, recoverable backups of state and receipts; protect copied backups with
mode 0600 and restrict access. Local state has no Azure blob versioning, remote
lease or cloud recovery service. Preserve `application.tfstate.backup` and
`namespace.tfstate.backup` when present; neither substitutes for independently
protected backups. No state or saved plan belongs in a public repository or artifact.

The lifecycle checks initialized backend metadata before initialization. A remote
backend, a different initialized local path, existing incompatible receipts or
unknown state block operation for explicit migration/recovery. There is no automatic
state migration, force-copy, state forgetting or fallback. A stale empty generated
backend configuration is rewritten only when no initialized backend or state exists.
Previously created Azure storage is left untouched; no storage or role operations
are part of this lifecycle.

For manual initialization only (not an alternative deployment workflow), choose
the same external absolute path and Terraform data directory:

```sh
umask 077
STATE_DIR="$HOME/.local/state/waap-showcase/<approved-subscription-id>"
mkdir -p "$STATE_DIR" "$STATE_DIR/application-data" "$STATE_DIR/namespace-data"
chmod 700 "$STATE_DIR" "$STATE_DIR/application-data" "$STATE_DIR/namespace-data"
TF_DATA_DIR="$STATE_DIR/application-data" TF_CLI_CONFIG_FILE=/dev/null \
  terraform -chdir=terraform init -input=false -lockfile=readonly \
  -backend-config="path=$STATE_DIR/application.tfstate"
TF_DATA_DIR="$STATE_DIR/namespace-data" TF_CLI_CONFIG_FILE=/dev/null \
  terraform -chdir=terraform/namespace init -input=false -lockfile=readonly \
  -backend-config="path=$STATE_DIR/namespace.tfstate"
```

Run this only for a fresh location or one already initialized with this exact
local path. Stop if Terraform requests migration. `backend.hcl.example` documents
the equivalent partial configuration; replace its absolute home placeholder before
use. Terraform does not expand `~` or environment variables inside HCL paths.
Do not supply credentials as backend settings or store state under the repository.

Preflight reads the existing `webapp-api-protection` namespace and captures its UID;
it never imports or applies. Deployment imports only that confirmed namespace into
`terraform/namespace`, checking its UID against the session/receipt evidence before
adoption. It never creates an unknown namespace through an out-of-band API path.
The application state must contain no namespace owner; protected/unknown ownership
or incompatible receipts fail closed and remain available for explicit recovery.
Verify and destroy require existing namespace state, a read-only zero-change
namespace preservation plan and unchanged live UID; neither applies that plan.
Application teardown therefore preserves the independently managed namespace.
The exact versioned Swagger stored object and receipt also remain after destroy;
the application never pins `/latest`. Azure storage is not an owned or preserved
lifecycle resource, and neither root bootstraps Azure storage, roles or RBAC.

## Evidence and failure contract

Read `operation-receipt.json`, `run-manifest.json`, `persistent.json`,
`swagger-receipt.json` and `readiness-report.json`, `acceptance-report.json` or
`absence-report.json` in the private state directory. These contain phase status,
command exit codes, exact owned/preserved IDs, fixture version/content, and live
verification results; treat them as sensitive operational data, not public docs.
A successful API apply, a 200 from `/health`, or a plausible graph is insufficient.

Readiness requires completed cloud-init on both guests, native origin
service/replica checks, DNS resolution and the expected routed httpbin response
through **both** domains. `cloud_init: true` means completion under the warning
policy, not a warning-free boot. `cloud_init_info` records each guest's status,
fatal-error count and accepted-warning count. Only the observed Azure pattern
(four copies of the exact first-attempt `reprovisiondata` 404, one per completed
stage) is accepted as `degraded_done`, with a successful cloud-final unit and
all functional checks. Unknown warnings, fatal errors and failed units fail closed.
Warnings during running stages are evaluated at completion within the deadline.
This is a recovered Azure preprovisioning retry, **not** an unused endpoint.
Cloud-init [documents exit 2 as recoverable errors](https://cloudinit.readthedocs.io/en/latest/reference/cli.html#status);
the installed 26.1 [IMDS retry source](https://github.com/canonical/cloud-init/blob/26.1/cloudinit/sources/azure/imds.py)
retries 404 until data is fetched, and [Azure reprovisioning](https://github.com/canonical/cloud-init/blob/26.1/cloudinit/sources/DataSourceAzure.py)
consumes that data before provisioning continues. Guest warning state is never cleared.
The profile in `showcase.tfvars.json` requests blocking
WAF, API discovery, exact schema validation, endpoint denial, rate limiting and
MUD with synthetic header identity; CSD is disabled. Readback must match this
profile before response and log evidence can count.

The shared generator continuously offers **200 aggregate HTTP requests/second**:
180 benign requests/second, divided equally across both authorized domains, and
20 requests/second for rotating catalog attacks. Scanners, subprocesses, browsers
and nested workers share one enforced pacing boundary. TLS/connection probes have
a separate recorded 20-attempt/second limit; slow headers have at most 20 connections.

The explicit catalog covers shell and JavaScript entrypoints plus all eleven CSD
browser simulations. Suites execute in catalog order, with bounded scenario-specific
parallel workers. Each scenario has a fifteen-minute deadline and descendant cleanup.
Missing dependencies, missing fixtures, skips and zero meaningful launches fail
coverage. Browser simulation receipts establish activity only; CSD stays disabled.

Continuous acceptance requires two complete meaningful catalog passes, a fresh
heartbeat and active enabled service, achieved aggregate rate within five percent,
at least 99% benign success and zero baseline transport failures. Private receipts
report the source commit/archive digest, current scenario, outcomes and failures.
Detailed evidence is capped at seven days or 10 GiB. Successful focused-suite passes
do not establish full catalog coverage.

`/usr/local/bin/tgen-control start|stop|status|run-once` controls the supervised service.
Start validates certificates, dependencies and every required application route;
stop terminates workers. An explicitly enabled service resumes after reboot. The
same immutable checksum-verifying installer is used by cloud-init and live updates.
Protections remain enabled, HTTP is retained alongside auto-certificate HTTPS, and
`/WAF/SQL` and `/WAF/XSS` identify synthetic DemoApp-compatible fixtures.

Traffic receipts are measurement evidence. Separate attributed probes must prove
WAF, schema enforcement, endpoint denial, per-user rate limiting, API discovery,
MUD detection and mitigation with unaffected benign controls. Missing attribution
remains incomplete acceptance.

The configured endpoint policy is nominally **20/MINUTE per identified user**.
It is not evidence of a strict global fixed-window cap or a guarantee that the
21st concurrent request will be rejected. Owned probes observed actual attributed
HTTP 429 under sequential and concurrent pressure, but a strict global capacity
of 20 per minute remains unverified. Performance cadence and independent control
proof are separate gates; neither substitutes for the other. Existing failed
history is retained and never relabeled as verified. Helper changes require a
source-generated VM rebuild and new complete catalog passes before live acceptance.

Acceptance requires attributable security events correlated to run/user,
endpoint, method, time, policy and mitigation plus discovery/traffic evidence.
Probes run once; telemetry polling does not repeat attacks. The standalone
verifier defaults to a 900-second deadline and ten-second polls; the lifecycle
passes its remaining whole-operation budget. Missing/asynchronous attribution
is **pending**, never success. MUD requires the verifier's supported live
High-risk detection join, fresh WAF evidence and delayed MUM_BLOCK service event.

Standalone verifier exit codes are 0 verified, 2 failure, 3 pending. The lifecycle
returns nonzero and records `blocked` for failed or pending gates, nonzero drift,
replacement of existing application objects, protected/unknown ownership,
credential mismatch, or deadline expiry. It attempts to stop traffic, retains
partial infrastructure and receipts, and preserves the original error if cleanup
also fails. Inspect the private reports; do not claim full live acceptance or
silently repair drift. Use an explicitly intended rebuild for recreation.

## Credential-free development gates

```sh
bash scripts/pre-commit-local.sh
TF_CLI_CONFIG_FILE=/dev/null terraform -chdir=terraform init -backend=false -input=false -lockfile=readonly
TF_CLI_CONFIG_FILE=/dev/null terraform -chdir=terraform/namespace init -backend=false -input=false -lockfile=readonly
terraform -chdir=terraform fmt -check -recursive
terraform -chdir=terraform validate -no-color
terraform -chdir=terraform/namespace validate -no-color
terraform -chdir=terraform test
```

The focused local hook and Terraform workflow run static Python tests and
existing plan-level module gates. CI never logs in to Azure or runs the lifecycle,
a live Azure plan/apply, or the mutating `tests/e2e` suite. Mocked/static tests
prove implementation contracts only; no security-success claim is valid without
live acceptance reports. For end-to-end operation, use the local authenticated
Azure CLI user prerequisite above.
