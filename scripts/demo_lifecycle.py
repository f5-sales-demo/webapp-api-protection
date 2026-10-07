#!/usr/bin/env python3
"""Run the private, deadline-bounded four-verb WAAP showcase lifecycle."""

from __future__ import annotations

import argparse
import fcntl
import fnmatch
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from demo_lifecycle_adoption import adopt
from demo_lifecycle_ownership import Ownership
from demo_lifecycle_runtime import Runtime
from demo_lifecycle_state import (
    Blocked,
    create_context,
    managed_resources,
    quota_count,
    save_json,
    secure_artifact,
)
from demo_lifecycle_terraform import Terraform

if TYPE_CHECKING:
    from collections.abc import Sequence
    from types import FrameType

    from demo_lifecycle_state import Context, LifecycleOptions

_QUOTA_NEEDS = {"cores": 32, "standarddsv3family": 16, "standardfsv2family": 16}
_SKU_FAMILIES = {
    "Standard_D16s_v3": "standarddsv3family",
    "Standard_F16s_v2": "standardfsv2family",
}
_VM_CORES = 16
_SOA_FIELDS = 7
_CLEANUP_SECONDS = 15
_REQUIRED_WRITES = (
    "Microsoft.Resources/subscriptions/resourceGroups/write",
    "Microsoft.Compute/virtualMachines/write",
    "Microsoft.Network/virtualNetworks/write",
    "Microsoft.Network/publicIPAddresses/write",
)


def _object(value: object, message: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise Blocked(message)
    return value


def _rows(value: object, message: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise Blocked(message)
    return value


def _prerequisites(context: Context, runtime: Runtime) -> None:
    paths = context.paths
    for tool in (
        "terraform",
        "az",
        "ssh",
        "ssh-keygen",
        "curl",
        "bash",
        "python3",
        "dig",
    ):
        if not shutil.which(tool):
            message = "missing prerequisite: " + tool
            raise Blocked(message)
    for path in (
        paths.root / "scripts/demo-verify.sh",
        paths.root / "scripts/swagger-upload.sh",
        paths.app / "showcase.tfvars.json",
        paths.app / "fixtures/showcase-openapi.json",
    ):
        if not path.is_file():
            message = "missing required artifact: " + str(path.relative_to(paths.root))
            raise Blocked(message)
    if context.env.get("XCSH_API_URL", "").rstrip("/") != context.settings.scope[
        "xc_url"
    ] or not context.env.get("XCSH_API_TOKEN"):
        message = "XC URL/token environment missing or wrong tenant"
        raise Blocked(message)
    _key_pair(paths.key, runtime)


def _key_pair(key: Path, runtime: Runtime) -> None:
    if not key.is_file() or key.stat().st_mode & 0o077:
        message = "SSH private key missing or unsafe permissions"
        raise Blocked(message)
    public = key.with_name(key.name + ".pub")
    derived = (
        runtime.run(["ssh-keygen", "-y", "-P", "", "-f", key])[0].strip().split()[:2]
    )
    if not public.is_file() or public.read_text().split()[:2] != derived:
        message = "SSH public/private key mismatch"
        raise Blocked(message)


def _azure_identity(context: Context, runtime: Runtime) -> None:
    expected = context.settings.config.get("expected_azure_user")
    if expected is None:
        message = "authorized Azure user missing; supply private operator config or DEMO_AZURE_USER"
        raise Blocked(message)
    account = _object(
        runtime.az("account", "show"), "Azure authenticated account unavailable"
    )
    scope = context.settings.scope
    if (
        account.get("id") != scope["subscription_id"]
        or account.get("tenantId") != scope["tenant_id"]
        or account.get("state") != "Enabled"
    ):
        message = "Azure authenticated identity/tenant/subscription mismatch"
        raise Blocked(message)
    user = _object(account.get("user"), "Azure authenticated user unavailable")
    if user.get("type") != "user":
        message = "requires existing Azure CLI user authentication; no login automation"
        raise Blocked(message)
    actual = user.get("name")
    if not isinstance(actual, str) or actual.casefold() != expected.casefold():
        message = "Azure authenticated human identity mismatch"
        raise Blocked(message)


def _entitlement_dns(runtime: Runtime) -> None:
    addon = runtime.xc(
        "/api/web/namespaces/system/addon_services/f5xc-waap-standard/activation-status"
    )
    if addon is None or addon.get("state") != "AS_SUBSCRIBED":
        message = "WAAP entitlement is not AS_SUBSCRIBED"
        raise Blocked(message)
    zone = runtime.xc("/api/config/dns/namespaces/system/dns_zones/f5-sales-demo.com")
    if (
        zone is None
        or zone.get("metadata", {}).get("name") != "f5-sales-demo.com"
        or zone.get("spec", {}).get("primary", {}).get("allow_http_lb_managed_records")
        is not True
    ):
        message = "shared DNS identity or managed HTTP listener records unavailable"
        raise Blocked(message)
    # Readiness later verifies concrete LB endpoints.
    soa = (
        runtime.run(
            ["dig", "+time=2", "+tries=1", "+short", "SOA", "f5-sales-demo.com"]
        )[0]
        .strip()
        .split()
    )
    if len(soa) != _SOA_FIELDS or not all(value.isdigit() for value in soa[2:]):
        message = "shared public DNS zone SOA unavailable"
        raise Blocked(message)


def _xc_capacity(runtime: Runtime) -> None:
    """Require capacity for all ten additional comparison hosts and policies."""
    response = runtime.xc("/api/web/namespaces/system/quota/usage")
    if response is None:
        message = "XC quota usage unavailable"
        raise Blocked(message)
    usage = _object(response.get("quota_usage"), "XC quota usage unavailable")
    needs = {
        "HTTP Load Balancer": 10,
        "TLS Certificate": 10,
        "Application Firewall": 10,
        "API Definition": 2,
        "User Identification": 10,
        "Malicious User Mitigation": 1,
    }
    for kind, needed in needs.items():
        row = _object(usage.get(kind), "XC quota category unavailable: " + kind)
        maximum = _object(row.get("limit"), "XC quota limit unavailable").get("maximum")
        current = _object(row.get("usage"), "XC quota consumption unavailable").get(
            "current"
        )
        valid_counts = all(
            isinstance(value, int) and not isinstance(value, bool)
            for value in (maximum, current)
        )
        if not valid_counts:
            message = "unavailable XC capacity: " + kind
            raise Blocked(message)
        maximum, current = cast("int", maximum), cast("int", current)
        if current < 0 or maximum < -1:
            message = "unavailable XC capacity: " + kind
            raise Blocked(message)
        if maximum != -1 and current + needed > maximum:
            message = "insufficient or unavailable XC capacity: " + kind
            raise Blocked(message)


def _permissions(context: Context, runtime: Runtime) -> None:
    subscription = "/subscriptions/" + context.settings.scope["subscription_id"]
    response = _object(
        runtime.az(
            "rest",
            "--method",
            "get",
            "--url",
            "https://management.azure.com"
            + subscription
            + "/providers/Microsoft.Authorization/permissions?api-version=2022-04-01",
        ),
        "Azure effective permissions unavailable",
    )
    permissions = _rows(
        response.get("value"), "Azure effective permissions unavailable"
    )
    for action in _REQUIRED_WRITES:
        if not any(_permits(permission, action) for permission in permissions):
            message = "Azure effective permissions missing required write: " + action
            raise Blocked(message)


def _permits(permission: dict[str, Any], action: str) -> bool:
    return any(
        fnmatch.fnmatchcase(action.lower(), pattern.lower())
        for pattern in permission.get("actions", [])
    ) and not any(
        fnmatch.fnmatchcase(action.lower(), pattern.lower())
        for pattern in permission.get("notActions", [])
    )


def _allocation(resource: dict[str, Any], runtime: Runtime) -> tuple[str, bool]:
    values = resource["values"]
    rid = values["id"]
    vm = _object(
        runtime.az("vm", "show", "--ids", rid, "--show-details"),
        "owned VM allocation unavailable",
    )
    hardware = _object(vm.get("hardwareProfile"), "owned VM allocation SKU unavailable")
    size = hardware.get("vmSize")
    family = _SKU_FAMILIES.get(size) if isinstance(size, str) else None
    if (
        str(vm.get("id", "")).lower() != rid.lower()
        or str(vm.get("location", "")).lower() != "eastus2"
        or family is None
        or size != values.get("size")
    ):
        message = "owned VM allocation identity/SKU mismatch"
        raise Blocked(message)
    power = vm.get("powerState")
    if power not in ("VM running", "VM stopped", "VM deallocated"):
        message = "owned VM allocation state unavailable"
        raise Blocked(message)
    return family, power != "VM deallocated"


def _released_capacity(
    resources: list[dict[str, Any]], runtime: Runtime
) -> dict[str, int]:
    released = dict.fromkeys(_QUOTA_NEEDS, 0)
    seen: set[str] = set()
    for resource in resources:
        if resource["type"] != "azurerm_linux_virtual_machine":
            continue
        rid = resource["values"]["id"]
        if rid.lower() in seen:
            message = "duplicate owned VM allocation"
            raise Blocked(message)
        seen.add(rid.lower())
        family, allocated = _allocation(resource, runtime)
        if allocated:
            released["cores"] += _VM_CORES
            released[family] += _VM_CORES
    return released


def _quota(runtime: Runtime, released: dict[str, int]) -> None:
    usage = _rows(
        runtime.az("vm", "list-usage", "--location", "eastus2"),
        "unavailable eastus2 VM quota response",
    )
    for name, needed in _QUOTA_NEEDS.items():
        entries = [
            row
            for row in usage
            if isinstance(row.get("name"), dict)
            and str(row["name"].get("value", "")).lower() == name
        ]
        if len(entries) != 1 or entries[0].get("unit") != "Count":
            message = "unavailable/unknown-unit eastus2 VM quota: " + name
            raise Blocked(message)
        current = quota_count(entries[0].get("currentValue"))
        limit = quota_count(entries[0].get("limit"))
        if released[name] > current or limit - current + released[name] < needed:
            message = "insufficient/unavailable eastus2 VM quota: " + name
            raise Blocked(message)


def _skus(runtime: Runtime) -> None:
    skus = _rows(
        runtime.az(
            "vm",
            "list-skus",
            "--location",
            "eastus2",
            "--resource-type",
            "virtualMachines",
            "--all",
        ),
        "subscription-aware eastus2 SKU response unavailable",
    )
    for name in _SKU_FAMILIES:
        matches = [row for row in skus if row.get("name") == name]
        if len(matches) != 1 or any(
            row.get("type") == "Location" for row in matches[0].get("restrictions", [])
        ):
            message = "subscription-aware eastus2 SKU unavailable: " + name
            raise Blocked(message)


def _interrupt(_signum: int, _frame: FrameType | None) -> None:
    raise KeyboardInterrupt


class Lifecycle:
    """Coordinate services without duplicating their state or ownership helpers."""

    def __init__(self, args: LifecycleOptions, root: Path | None = None) -> None:
        """Bind the approved private context and the three lifecycle services."""
        self.context = create_context(args, root or Path(__file__).resolve().parents[1])
        self.runtime = Runtime(self.context)
        self.terraform = Terraform(self.context, self.runtime)
        self.ownership = Ownership(self.context, self.runtime, self.terraform)

    def preflight(self, deploying: bool) -> None:
        """Check explicit identity, prerequisites, namespace, entitlement and DNS."""
        _prerequisites(self.context, self.runtime)
        self.terraform.local_backend_check()
        _azure_identity(self.context, self.runtime)
        self.terraform.namespace_prepare()
        _entitlement_dns(self.runtime)
        if deploying:
            self.capacity_permissions()
        self.context.env["TF_CLI_CONFIG_FILE"] = "/dev/null"
        known_hosts = self.context.paths.known_hosts
        if not known_hosts.exists():
            known_hosts.touch(mode=0o600)
        if known_hosts.is_symlink():
            message = "unsafe known_hosts symlink"
            raise Blocked(message)
        known_hosts.chmod(0o600)
        self.runtime.phase("authenticated-scope-prerequisites-entitlement-dns")

    def capacity_permissions(self) -> None:
        """Prove exact ownership before granting rebuild quota credit or deletion."""
        _permissions(self.context, self.runtime)
        _xc_capacity(self.runtime)
        released = dict.fromkeys(_QUOTA_NEEDS, 0)
        if self.context.settings.operation == "rebuild":
            self.terraform.namespace_prepare()
            self.terraform.app_init()
            _deployed_vars(self.context)
            self.ownership.inventory()
            self.ownership.verify_fixture()
            resources = self.context.state.resources
            if resources is None:
                message = "owned VM allocation state unavailable"
                raise Blocked(message)
            released = _released_capacity(resources, self.runtime)
        _quota(self.runtime, released)
        _skus(self.runtime)
        self.runtime.phase("azure-permissions-quota-skus")

    def deploy(self) -> None:
        """Apply the guarded app, prove readiness, then leave verified traffic running."""
        self.terraform.namespace_tf_prepare(create=True)
        self.terraform.app_init()
        _upload_profile(self.context, self.runtime)
        plan = self.terraform.plan("application")
        self.terraform.apply(plan)
        self.terraform.get_outputs()
        self.ownership.inventory()
        self.ownership.verify_phase("readiness")
        self.ownership.traffic("start")
        self.ownership.verify_phase("acceptance")
        noop = self.terraform.plan("post-acceptance-drift", "noop")
        self.terraform.apply(noop)
        self.runtime.phase("zero-change-apply")
        self.terraform.plan("post-second-apply-drift", "noop")

    def plan(self) -> None:
        """Save current declared inputs and a fresh private summarized plan."""
        self.terraform.namespace_tf_prepare()
        self.terraform.app_init()
        _upload_profile(self.context, self.runtime)
        self.terraform.plan("review")

    def adopt(self) -> None:
        """Apply only the reviewed import map after private plan review."""
        self.terraform.namespace_tf_prepare()
        self.terraform.app_init()
        _deployed_vars(self.context)
        adopt(
            self.context,
            self.terraform,
            self.context.paths.state / "adoption-review.json",
        )

    def verify(self) -> None:
        """Verify live app behavior and drift without repairing infrastructure."""
        self.terraform.namespace_tf_prepare()
        self.terraform.app_init()
        _deployed_vars(self.context)
        self.terraform.get_outputs()
        self.ownership.inventory()
        self.ownership.verify_phase("readiness")
        self.ownership.verify_phase("acceptance")
        self.terraform.plan("verify-drift", "noop")

    def destroy(self) -> None:
        """Destroy only proven app ownership and verify the preserved foundation."""
        self.terraform.namespace_tf_prepare()
        self.terraform.app_init()
        _deployed_vars(self.context)
        owned = self.ownership.inventory()
        resources = self.context.state.resources
        if resources is None:
            message = "cleanup ownership state unavailable"
            raise Blocked(message)
        self.ownership.cleanup_access(resources)
        self.ownership.traffic("stop")
        plan = self.terraform.plan("destroy", "destroy", owned)
        self.terraform.apply(plan)
        remaining = _application_resources(self.context, self.terraform)
        if remaining:
            message = "application state remains populated after destroy"
            raise Blocked(message)
        self.ownership.verify_phase("absence")
        self.terraform.namespace_tf_prepare()
        self.runtime.phase("owned-schema-removed")
        self.runtime.phase("persistent-resources-survive")
        self.context.state.outputs = None

    def execute(self) -> None:
        """Lock private subscription state and finalize every completed or failed run."""
        lock_path = self.context.paths.state / "lifecycle.lock"
        secure_artifact(lock_path)
        with lock_path.open("a") as lock:
            lock_path.chmod(0o600)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                message = "another lifecycle operation holds the subscription lock"
                raise Blocked(message) from None
            complete = False
            try:
                self.preflight(self.context.settings.operation in ("deploy", "rebuild"))
                if self.context.settings.operation == "rebuild":
                    self.destroy()
                    self.deploy()
                else:
                    getattr(self, self.context.settings.operation)()
                self.context.state.receipt["status"] = "verified"
                self.runtime.phase("complete")
                complete = True
            finally:
                failure = sys.exception()
                if not complete:
                    _failed_operation(self, failure)
                _finalize_artifacts(self.context, failure)


def _deployed_vars(context: Context) -> None:
    if not context.paths.vars.is_file():
        message = "missing secure deployed variable receipt"
        raise Blocked(message)


def _upload_profile(context: Context, runtime: Runtime) -> None:
    """Prepare declared inputs; Swagger issuance belongs solely to Terraform."""
    paths, scope = context.paths, context.settings.scope
    profile = _object(
        json.loads((paths.app / "showcase.tfvars.json").read_text()),
        "showcase profile unavailable",
    )
    profile.update(
        namespace=scope["namespace"],
        subscription_id=scope["subscription_id"],
        lb_domains=scope["domains"],
        ssh_public_key_path=str(paths.key) + ".pub",
    )
    save_json(paths.vars, profile)
    runtime.phase("declared-profile-prepared")


def _application_resources(
    context: Context, terraform: Terraform
) -> list[dict[str, Any]]:
    value = _object(
        json.loads(terraform.tf(context.paths.app, "show", "-json")[0]),
        "cleanup ownership state unavailable",
    )
    return list(managed_resources(value.get("values", {}).get("root_module", {})))


def _cleanup_traffic(lifecycle: Lifecycle) -> None:
    state = lifecycle.context.state
    if state.outputs is None and state.app_ready:
        original = state.deadline
        state.deadline = time.monotonic() + _CLEANUP_SECONDS
        try:
            resources = _application_resources(lifecycle.context, lifecycle.terraform)
            if not resources or any(
                not row.get("values", {}).get("id") for row in resources
            ):
                message = "cleanup ownership state unavailable"
                raise Blocked(message)
            lifecycle.ownership.cleanup_access(resources)
        finally:
            state.deadline = original
    lifecycle.ownership.traffic("stop", cleanup=True)


def _failed_operation(lifecycle: Lifecycle, failure: BaseException | None) -> None:
    receipt = lifecycle.context.state.receipt
    receipt["status"] = "blocked"
    receipt["error"] = (
        str(failure) if isinstance(failure, Blocked) else type(failure).__name__
    )
    # Cleanup must never replace the original failure, including a second interruption.
    try:
        if lifecycle.context.settings.operation not in ("plan", "adopt"):
            _cleanup_traffic(lifecycle)
    except BaseException:  # pylint: disable=broad-exception-caught
        receipt["cleanup"] = (
            "traffic stop failed or unreachable; original failure retained"
        )
    try:
        lifecycle.runtime.phase("failure", "blocked")
    except BaseException:  # pylint: disable=broad-exception-caught
        if failure is None:
            raise


def _finalize_artifacts(context: Context, failure: BaseException | None) -> None:
    try:
        for path in context.paths.state.rglob("*"):
            secure_artifact(path, private=False)
    # Artifact errors or interruption must not replace an active operation failure.
    except BaseException:  # pylint: disable=broad-exception-caught
        if failure is None:
            raise


def _canonical_state(lifecycle: Lifecycle) -> None:
    """Use one private subscription state and lock across Ubuntu worktrees."""
    canonical = (
        Path.home()
        / ".local/state/waap-showcase"
        / lifecycle.context.settings.scope["subscription_id"]
    )
    if lifecycle.context.paths.state != canonical.resolve():
        message = "deployment state must use the canonical Ubuntu subscription location"
        raise Blocked(message)


def main(argv: Sequence[str] | None = None) -> int:
    """Parse the unchanged CLI and report only safe failure summaries."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "operation", choices=("deploy", "plan", "adopt", "verify", "rebuild", "destroy")
    )
    parser.add_argument(
        "--config",
        type=Path,
        help=(
            "private external JSON instead of ~/.local/state/waap-showcase/operator.json; "
            "approved Azure IDs required"
        ),
    )
    parser.add_argument(
        "--state-dir", type=Path, help="private persistent directory outside checkout"
    )
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    args = parser.parse_args(argv)
    if args.timeout_seconds < 1:
        parser.error("--timeout-seconds must be positive")
    os.umask(0o077)
    signal.signal(signal.SIGTERM, _interrupt)
    try:
        lifecycle = Lifecycle(args)
        _canonical_state(lifecycle)
        lifecycle.execute()
    except (
        Blocked,
        OSError,
        ValueError,
        KeyError,
        subprocess.TimeoutExpired,
        KeyboardInterrupt,
    ) as exc:
        message = str(exc) if isinstance(exc, Blocked) else type(exc).__name__
        print(
            "[blocked] "
            + message
            + "; preserve state and inspect private operation-receipt.json",
            file=sys.stderr,
        )
        return 1
    print(
        "Lifecycle verified; private receipts contain live evidence, "
        "not Terraform acceptance alone."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
