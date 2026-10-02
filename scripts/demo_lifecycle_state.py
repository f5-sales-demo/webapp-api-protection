"""Private lifecycle configuration, ownership guards and execution context."""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, NotRequired, Protocol, TypedDict, cast

if TYPE_CHECKING:
    from collections.abc import Collection, Iterator, Mapping

FIXED: dict[str, Any] = {
    "xc_url": "https://f5-sales-demo.console.ves.volterra.io",
    "namespace": "webapp-api-protection",
    "domains": ["www.f5-sales-demo.com", "api.f5-sales-demo.com"],
}
AZURE_TYPES = {
    "azurerm_resource_group",
    "azurerm_virtual_network",
    "azurerm_subnet",
    "azurerm_public_ip",
    "azurerm_network_security_group",
    "azurerm_network_interface",
    "azurerm_network_interface_security_group_association",
    "azurerm_linux_virtual_machine",
}
XC_TYPES = {
    "xcsh_healthcheck",
    "xcsh_origin_pool",
    "xcsh_app_firewall",
    "xcsh_malicious_user_mitigation",
    "xcsh_user_identification",
    "xcsh_api_discovery",
    "xcsh_http_loadbalancer",
    "xcsh_api_definition",
    "xcsh_service_policy",
    "xcsh_rate_limiter",
    "xcsh_rate_limiter_policy",
    "xcsh_app_api_group",
    "xcsh_data_type",
    "xcsh_route",
    "xcsh_sensitive_data_policy",
    "xcsh_waf_exclusion_policy",
    "xcsh_bgp_asn_set",
    "xcsh_ip_prefix_set",
    "xcsh_api_testing",
}
XC_COLLECTIONS = {
    "xcsh_healthcheck": "healthchecks",
    "xcsh_origin_pool": "origin_pools",
    "xcsh_app_firewall": "app_firewalls",
    "xcsh_http_loadbalancer": "http_loadbalancers",
    "xcsh_malicious_user_mitigation": "malicious_user_mitigations",
    "xcsh_user_identification": "user_identifications",
    "xcsh_api_discovery": "api_discoverys",
    "xcsh_api_definition": "api_definitions",
    "xcsh_service_policy": "service_policys",
    "xcsh_rate_limiter": "rate_limiters",
    "xcsh_rate_limiter_policy": "rate_limiter_policys",
}
_PRIVATE_FILE_MODE = 0o600
_MAXIMUM_QUOTA = 2**53 - 1
_MAXIMUM_UPN_LENGTH = 320
_UUID_PATTERN = (
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


# Frozen cross-service exception identity; renaming violates the CLI contract.
class Blocked(RuntimeError):  # noqa: N818
    """A required gate has not passed; retain partial provisioning."""


class Scope(TypedDict):
    """Public fixture scope and privately approved Azure identifiers."""

    xc_url: str
    namespace: str
    domains: list[str]
    subscription_id: str
    tenant_id: str


class Config(Scope):
    """Validated private operator configuration."""

    ssh_key: NotRequired[str]
    expected_azure_user: NotRequired[str]


class Guest(TypedDict):
    """Azure guest connection evidence."""

    id: str
    admin_username: str
    public_ip: str


class LifecycleOptions(Protocol):
    """CLI options required to initialize a lifecycle context."""

    config: Path | None
    state_dir: Path | None
    timeout_seconds: int
    operation: Literal["deploy", "verify", "rebuild", "destroy"]


def quota_count(value: object) -> int:
    """Normalize exact JSON counts without ambiguous or unsafe numbers."""
    message = "malformed eastus2 VM quota count"
    if isinstance(value, str):
        if not re.fullmatch(r"[0-9]{1,16}", value):
            raise Blocked(message)
        value = int(value)
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not 0 <= value <= _MAXIMUM_QUOTA
        or int(value) != value
    ):
        raise Blocked(message)
    return int(value)


def _approved_id(values: dict[str, Any], key: str, environment: str) -> str:
    approved = values.get(key, os.environ.get(environment))
    if key not in values and environment not in os.environ:
        message = (
            "approved Azure "
            + key
            + " missing; supply private operator config or "
            + environment
        )
        raise Blocked(message)
    if not isinstance(approved, str) or not re.fullmatch(_UUID_PATTERN, approved):
        message = "approved Azure " + key + " must be a canonical UUID"
        raise Blocked(message)
    return approved.lower()


def _validate_user(values: dict[str, Any]) -> None:
    if "expected_azure_user" not in values and "DEMO_AZURE_USER" in os.environ:
        values["expected_azure_user"] = os.environ["DEMO_AZURE_USER"]
    if "expected_azure_user" in values:
        user = values["expected_azure_user"]
        if (
            not isinstance(user, str)
            or not 1 <= len(user) <= _MAXIMUM_UPN_LENGTH
            or not re.fullmatch(r"[!-?A-~]+@[!-?A-~]+", user)
        ):
            message = "authorized Azure user must be a bounded printable UPN without whitespace"
            raise Blocked(message)


def config_values(value: object) -> Config:
    """Validate fixed fixture scope and explicitly approved private identities."""
    if isinstance(value, dict) and "backend" in value:
        message = (
            "backend config is no longer accepted; select local state using --state-dir; "
            "explicit migration required for initialized remote state"
        )
        raise Blocked(message)
    optional = {"subscription_id", "tenant_id", "ssh_key", "expected_azure_user"}
    if not isinstance(value, dict) or set(value) - set(FIXED) - optional:
        message = (
            "unknown config fields; only fixed scope, approved Azure IDs, SSH key "
            "and authorized Azure user accepted"
        )
        raise Blocked(message)
    for key, expected in FIXED.items():
        if key in value and value[key] != expected:
            message = "fixed identity/scope override rejected: " + key
            raise Blocked(message)
    result = dict(FIXED)
    result.update(value)
    _validate_user(result)
    for key, environment in (
        ("subscription_id", "DEMO_AZURE_SUBSCRIPTION_ID"),
        ("tenant_id", "DEMO_AZURE_TENANT_ID"),
    ):
        result[key] = _approved_id(result, key, environment)
    return cast("Config", result)


def secure_directory(path: Path, checkout: Path) -> Path:
    """Create a caller-owned private state directory outside the checkout."""
    path = path.expanduser().absolute()
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        message = "state directory must not traverse symlinks"
        raise Blocked(message)
    path = path.resolve()
    if path == checkout or checkout in path.parents:
        message = "state directory must be outside the checkout"
        raise Blocked(message)
    if path.exists() and (path.is_symlink() or path.stat().st_uid != os.getuid()):
        message = "state directory ownership is unsafe"
        raise Blocked(message)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def secure_artifact(path: Path, private: bool = True) -> None:
    """Reject foreign/symlink artifacts before reading or changing permissions."""
    if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
        message = "persistent artifact must not traverse symlinks"
        raise Blocked(message)
    if path.exists():
        if path.stat().st_uid != os.getuid() or not (path.is_file() or path.is_dir()):
            message = "persistent artifact ownership/type is unsafe"
            raise Blocked(message)
        executable = (
            path.is_file()
            and os.access(path, os.X_OK)
            and not path.name.endswith((".tfstate", ".backup", ".json"))
        )
        if private:
            path.chmod(0o700 if path.is_dir() or executable else 0o600)


def private_json(path: Path) -> Any:
    """Read JSON only after validating private artifact ownership."""
    secure_artifact(path)
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        message = "persistent JSON artifact unreadable; explicit migration required"
        raise Blocked(message) from None


def operator_config(path: Path, checkout: Path) -> Any:
    """Read caller-owned private operator input outside the public checkout."""
    path = path.expanduser().absolute()
    secure_artifact(path, private=False)
    if (
        path.resolve() == checkout.resolve()
        or checkout.resolve() in path.resolve().parents
    ):
        message = "operator config must be outside the checkout"
        raise Blocked(message)
    if not path.is_file() or path.stat().st_mode & 0o777 != _PRIVATE_FILE_MODE:
        message = "operator config must be an existing private mode 0600 file"
        raise Blocked(message)
    return private_json(path)


def save_json(path: Path, value: object) -> None:
    """Atomically save private JSON without replacing a foreign temporary file."""
    secure_artifact(path)
    temporary = path.with_name(path.name + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _guard_change(
    item: dict[str, Any],
    mode: Literal["deploy", "noop", "destroy"],
    owned: Mapping[str, str] | None,
    persistent: Collection[str],
) -> None:
    actions = item["change"]["actions"]
    kind = item.get("type", "")
    if kind == "xcsh_namespace":
        message = (
            "namespace owned by application plan; explicit external migration required"
        )
        raise Blocked(message)
    if kind not in AZURE_TYPES | XC_TYPES and actions != ["no-op"]:
        message = "protected/unknown application resource type: " + kind
        raise Blocked(message)
    before = item["change"].get("before") or {}
    if before.get("id") in persistent and actions != ["no-op"]:
        message = "persistent resource in application plan"
        raise Blocked(message)
    if mode == "noop" and actions != ["no-op"]:
        message = "nonzero drift; verify never repairs infrastructure"
        raise Blocked(message)
    if mode == "destroy":
        _guard_destroy(item, owned)


def _guard_destroy(item: dict[str, Any], owned: Mapping[str, str] | None) -> None:
    actions = item["change"]["actions"]
    before = item["change"].get("before") or {}
    if actions not in (["delete"], ["no-op"]):
        message = "destroy plan includes non-delete change"
        raise Blocked(message)
    if (
        owned is not None
        and actions == ["delete"]
        and owned.get(item["address"]) != before.get("id")
    ):
        message = "destroy plan includes resource not in captured state"
        raise Blocked(message)


def guard_plan(
    plan: dict[str, Any],
    mode: Literal["deploy", "noop", "destroy"],
    owned: Mapping[str, str] | None = None,
    persistent: Collection[str] = (),
) -> None:
    """Reject protected ownership, replacement and unowned deletion."""
    for item in plan.get("resource_changes", []):
        if item.get("mode") != "data":
            _guard_change(item, mode, owned, persistent)
    if mode == "noop" and any(
        value.get("actions") != ["no-op"]
        for value in plan.get("output_changes", {}).values()
    ):
        message = "nonzero output drift"
        raise Blocked(message)


def managed_resources(module: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Yield managed resources recursively from Terraform's module tree."""
    yield from (
        resource
        for resource in module.get("resources", [])
        if resource.get("mode") == "managed"
    )
    for child in module.get("child_modules", []):
        yield from managed_resources(child)


@dataclass(frozen=True)
class Paths:
    """Immutable source and private artifact locations."""

    root: Path
    state: Path
    key: Path
    known_hosts: Path

    @property
    def app(self) -> Path:
        """Return the application Terraform root."""
        return self.root / "terraform"

    @property
    def namespace_root(self) -> Path:
        """Return the independently persisted namespace Terraform root."""
        return self.app / "namespace"

    @property
    def vars(self) -> Path:
        """Return the private application input artifact."""
        return self.state / "application.tfvars.json"

    @property
    def backend(self) -> dict[str, str]:
        """Return the explicit local application backend selection."""
        return {"path": str(self.state / "application.tfstate")}

    @property
    def namespace_backend(self) -> dict[str, str]:
        """Return the explicit local namespace backend selection."""
        return {"path": str(self.state / "namespace.tfstate")}


@dataclass
class RunState:
    """Mutable operation evidence; absent discovery is never empty success."""

    deadline: float
    receipt: dict[str, Any]
    outputs: dict[str, Any] | None = None
    persistent: dict[str, str] = field(default_factory=dict)
    namespace_uid: str | None = None
    app_ready: bool = False
    resources: list[dict[str, Any]] | None = None
    inventory_receipt: dict[str, Any] | None = None


@dataclass(frozen=True)
class Settings:
    """Validated operation and identity settings."""

    config: Config
    scope: Scope
    operation: Literal["deploy", "verify", "rebuild", "destroy"]


@dataclass
class Context:
    """Shared paths, settings, execution environment and mutable run evidence."""

    paths: Paths
    settings: Settings
    state: RunState
    env: dict[str, str]


def _validate_previous_scope(state: Path, scope: Scope) -> None:
    for name in ("operation-receipt.json", "run-manifest.json"):
        previous = state / name
        if previous.exists():
            saved = private_json(previous)
            old_scope = saved.get("scope", saved)
            if any(
                key in old_scope and old_scope[key] != approved
                for key, approved in (
                    ("subscription_id", scope["subscription_id"]),
                    ("tenant_id", scope["tenant_id"]),
                )
            ):
                message = (
                    "existing state approval scope mismatch; "
                    "explicit external migration required"
                )
                raise Blocked(message)
    for path in state.rglob("*"):
        secure_artifact(path, private=False)


def _execution_environment(scope: Scope) -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("TF_", "ARM_"))
    }
    env.update(
        TF_IN_AUTOMATION="1",
        TF_INPUT="0",
        TF_CLI_CONFIG_FILE="/dev/null",
        ARM_USE_CLI="true",
        ARM_USE_AZUREAD="true",
        ARM_SUBSCRIPTION_ID=scope["subscription_id"],
        ARM_TENANT_ID=scope["tenant_id"],
    )
    return env


def create_context(args: LifecycleOptions, root: Path) -> Context:
    """Initialize private approval, paths and receipt without creating resources."""
    os.umask(0o077)
    base = Path.home() / ".local/state/waap-showcase"
    operator = args.config or base / "operator.json"
    supplied = (
        operator_config(operator, root)
        if args.config or operator.exists() or operator.is_symlink()
        else {}
    )
    config = config_values(supplied)
    scope: Scope = {
        "xc_url": config["xc_url"],
        "namespace": config["namespace"],
        "domains": config["domains"],
        "subscription_id": config["subscription_id"],
        "tenant_id": config["tenant_id"],
    }
    state = secure_directory(args.state_dir or base / scope["subscription_id"], root)
    _validate_previous_scope(state, scope)
    paths = Paths(
        root,
        state,
        Path(config.get("ssh_key", "~/.ssh/id_ed25519")).expanduser().resolve(),
        state / "known_hosts",
    )
    receipt: dict[str, Any] = {
        "schema_version": 1,
        "operation": args.operation,
        "scope": scope,
        "phases": [],
        "status": "running",
    }
    return Context(
        paths,
        Settings(config, scope, args.operation),
        RunState(time.monotonic() + args.timeout_seconds, receipt),
        _execution_environment(scope),
    )
