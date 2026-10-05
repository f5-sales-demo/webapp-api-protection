"""Live ownership joins, bounded guest access and immutable recovery evidence."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import time
from typing import TYPE_CHECKING, Any, Literal

from demo_lifecycle_state import (
    AZURE_TYPES,
    XC_COLLECTIONS,
    XC_TYPES,
    Blocked,
    managed_resources,
    private_json,
    save_json,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from pathlib import Path

    from demo_lifecycle_runtime import Runtime
    from demo_lifecycle_state import Context, Guest
    from demo_lifecycle_terraform import Terraform

_ACCESS_BUDGET_SECONDS = 20
_REQUIRED_CATALOG_PASSES = 2
_MAX_IP_OCTET = 255
_GROUP_ID_PARTS = 5
_MIN_PROVIDER_PARTS = 3
_MAX_VERSION_CANDIDATES = 3
_GUEST_KINDS = {
    "linux_virtual_machine": "Microsoft.Compute/virtualMachines",
    "network_interface": "Microsoft.Network/networkInterfaces",
    "public_ip": "Microsoft.Network/publicIPAddresses",
}
_MANIFEST_KEYS = {
    "schema_version",
    "namespace",
    "subscription_id",
    "owned_resources",
    "azure_owned",
    "xc_owned",
    "azure_preserved",
    "xc_preserved",
    "persistent_resource_ids",
    "azure_api_versions",
}


def _resources(context: Context) -> list[dict[str, Any]]:
    resources = context.state.resources
    if resources is None:
        message = "ownership resources not initialized"
        raise Blocked(message)
    return resources


def _scope_matches(context: Context) -> bool:
    config, scope = context.settings.config, context.settings.scope
    return (
        config["subscription_id"] == scope["subscription_id"]
        and config["namespace"] == scope["namespace"]
    )


def _guest_records(
    resources: Sequence[dict[str, Any]], role: Literal["origin", "generator"]
) -> dict[str, dict[str, Any]]:
    module = {"origin": "origin_server", "generator": "traffic_generator"}[role]
    records: dict[str, dict[str, Any]] = {}
    for kind in _GUEST_KINDS:
        address = "module." + module + ".azurerm_" + kind + ".main"
        matches = [
            item
            for item in resources
            if item.get("address") == address and item.get("type") == "azurerm_" + kind
        ]
        if len(matches) != 1:
            message = "owned " + role + " " + kind + " unavailable"
            raise Blocked(message)
        records[kind] = matches[0]["values"]
    return records


def _guest_identity(records: dict[str, dict[str, Any]], subscription: str) -> Guest:
    scope = "/subscriptions/" + subscription + "/resourceGroups/"
    for kind, values in records.items():
        if not re.fullmatch(
            re.escape(scope)
            + r"[^/]+/providers/"
            + re.escape(_GUEST_KINDS[kind])
            + r"/[^/]+",
            values.get("id", ""),
            re.IGNORECASE,
        ):
            message = "owned SSH resource subscription/type mismatch"
            raise Blocked(message)
    vm, nic, pip = (records[kind] for kind in _GUEST_KINDS)
    ip, username = pip.get("ip_address", ""), vm.get("admin_username", "")
    if (
        not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", username)
        or not re.fullmatch(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", ip)
        or any(int(part) > _MAX_IP_OCTET for part in ip.split("."))
    ):
        message = "unsafe owned SSH destination"
        raise Blocked(message)
    if vm.get("network_interface_ids") != [nic["id"]] or [
        item.get("public_ip_address_id") for item in nic.get("ip_configuration", [])
    ] != [pip["id"]]:
        message = "owned SSH VM/NIC/public IP association mismatch"
        raise Blocked(message)
    return {"id": vm["id"], "admin_username": username, "public_ip": ip}


def _live_guest_matches(live: dict[str, Any], guest: Guest, nic_id: str) -> bool:
    nics = [
        item.get("id")
        for item in live.get("networkProfile", {}).get("networkInterfaces", [])
    ]
    return (
        live.get("id", "").lower() == guest["id"].lower()
        and live.get("osProfile", {}).get("adminUsername") == guest["admin_username"]
        and live.get("publicIps") == guest["public_ip"]
        and all(isinstance(item, str) for item in nics)
        and [item.lower() for item in nics] == [nic_id.lower()]
    )


def _azure_type(rid: str, subscription: str) -> tuple[str, str]:
    prefix = "/subscriptions/" + subscription.lower() + "/resourcegroups/"
    if (
        not isinstance(rid, str)
        or not re.fullmatch(r"/[A-Za-z0-9_./-]+", rid)
        or ".." in rid
        or not rid.lower().startswith(prefix)
    ):
        message = "manifest Azure scope/identity mismatch"
        raise Blocked(message)
    parts = rid.split("/providers/")
    if len(parts) == 1:
        if len(rid.split("/")) != _GROUP_ID_PARTS:
            message = "unknown Azure resource-group identity"
            raise Blocked(message)
        return "Microsoft.Resources", "resourceGroups"
    tail = parts[-1].split("/")
    if len(tail) < _MIN_PROVIDER_PARTS or len(tail) % 2 != 1:
        message = "unknown Azure resource identity"
        raise Blocked(message)
    return tail[0], "/".join(tail[1::2])


def _stable_versions(
    catalog: Sequence[dict[str, Any]], resource_type: str
) -> list[str]:
    return sorted(
        {
            version
            for item in catalog
            if item.get("resourceType", "").lower() == resource_type.lower()
            for version in item.get("apiVersions", [])
            if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", version)
        }
    )


def _ancestor_versions(
    catalog: Sequence[dict[str, Any]], resource_type: str
) -> list[str]:
    ancestor = resource_type
    while "/" in ancestor:
        ancestor = ancestor.rsplit("/", 1)[0]
        versions = _stable_versions(catalog, ancestor)
        if versions:
            return versions[::-1][:_MAX_VERSION_CANDIDATES]
    return []


def _confirmed_version(
    runtime: Runtime, rid: str, candidates: list[str], kind: str
) -> str:
    for version in candidates[:]:
        try:
            live = runtime.az(
                "rest",
                "--method",
                "get",
                "--url",
                "https://management.azure.com" + rid + "?api-version=" + version,
            )
        except Blocked as exc:
            # Only the runtime's unsupported-version diagnostic permits another read.
            if "(arm-api-version-unsupported)" in str(exc):
                continue
            raise
        if not isinstance(live, dict) or str(live.get("id", "")).lower() != rid.lower():
            message = "ARM child live identity mismatch"
            raise Blocked(message)
        properties = live.get("properties")
        if (
            not isinstance(properties, dict)
            or properties.get("provisioningState") != "Succeeded"
        ):
            message = "ARM child provisioning state unavailable/not Succeeded"
            raise Blocked(message)
        candidates.remove(version)
        candidates.insert(0, version)
        return version
    message = "no confirmed stable ARM API version for " + kind
    raise Blocked(message)


def _namespace_record(context: Context, uid: str) -> list[dict[str, str]]:
    return [
        {
            "path": "/api/web/namespaces/" + context.settings.scope["namespace"],
            "uid": uid,
        }
    ]


def _check_previous_manifest(context: Context, manifest: Path) -> None:
    prior = private_json(manifest)
    uid = context.state.namespace_uid
    if (
        not isinstance(prior, dict)
        or not uid
        or prior.get("persistent_resource_ids") != context.state.persistent
        or prior.get("azure_preserved") != []
        or prior.get("xc_preserved") != _namespace_record(context, uid)
    ):
        message = (
            "existing run foundation incompatible; explicit external migration required"
        )
        raise Blocked(message)


def _check_application_resources(
    resources: Sequence[dict[str, Any]], persistent: Mapping[str, str]
) -> None:
    if not resources:
        message = "missing application state/resources; refusing unowned operation"
        raise Blocked(message)
    for item in resources:
        if item["type"] == "xcsh_namespace":
            message = "namespace owned by application state; explicit external migration required"
            raise Blocked(message)
        if item["type"] not in AZURE_TYPES | XC_TYPES or not item["values"].get("id"):
            message = "protected/unknown ownership in application state"
            raise Blocked(message)
        if item["values"]["id"] in persistent.values():
            message = "persistent resource present in application state"
            raise Blocked(message)


def _xc_ownership(
    runtime: Runtime, resources: Sequence[dict[str, Any]], namespace: str
) -> list[dict[str, str]]:
    owned: list[dict[str, str]] = []
    for item in resources:
        if item["type"] not in XC_TYPES:
            continue
        collection = XC_COLLECTIONS.get(item["type"])
        name = item["values"].get("name")
        if (
            not collection
            or item["values"].get("namespace") != namespace
            or not re.fullmatch(r"[a-z][a-z0-9-]*[a-z0-9]", name or "")
        ):
            message = "missing catalog-backed XC ownership identity"
            raise Blocked(message)
        path = "/api/config/namespaces/" + namespace + "/" + collection + "/" + name
        live = runtime.xc(path)
        if live is None:
            message = "live XC ownership identity unavailable"
            raise Blocked(message)
        uid = live.get("system_metadata", {}).get("uid")
        if not uid or live.get("metadata", {}).get("name") != name:
            message = "live XC ownership identity unavailable"
            raise Blocked(message)
        owned.append({"path": path, "uid": uid})
    return owned


def _backup_manifest(manifest: Path, snapshot: bytes) -> tuple[Path, str]:
    if manifest.read_bytes() != snapshot:
        message = "manifest changed during recovery"
        raise Blocked(message)
    digest = hashlib.sha256(snapshot).hexdigest()
    backup = manifest.with_name(
        "run-manifest.corrupt-"
        + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        + "-"
        + digest
        + ".json"
    )
    descriptor = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(snapshot)
        stream.flush()
        os.fsync(stream.fileno())
    return backup, digest


class _ReadOnlyClient:
    """Adapt the canonical upload verifier to one pinned GET under the same budget."""

    def __init__(self, runtime: Runtime, path: str, base: str) -> None:
        """Bind an immutable request destination and tenant base."""
        self.runtime = runtime
        self.path = path
        self.base = base

    def remaining(self) -> float:
        """Delegate the shrinking operation deadline."""
        return self.runtime.remaining()

    def request(
        self, method: str, path: str, body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Permit only the pinned GET with no payload or alternative object path."""
        if method != "GET" or path != self.path or body is not None:
            message = "fixture verification must remain read-only"
            raise Blocked(message)
        result = self.runtime.xc(path)
        if result is None:
            message = "fixture preservation object unavailable"
            raise Blocked(message)
        return result


def _fixture_receipt(context: Context) -> dict[str, Any]:
    receipt_path = context.paths.state / "swagger-receipt.json"
    if not receipt_path.is_file() or receipt_path.is_symlink():
        message = "fixture preservation receipt missing"
        raise Blocked(message)
    saved = private_json(receipt_path)
    pinned = private_json(context.paths.vars).get("api_definition_swagger_specs")
    scope = context.settings.scope
    if not isinstance(saved, dict):
        message = "fixture preservation identity mismatch"
        raise Blocked(message)
    if (
        saved.get("api_url") != scope["xc_url"]
        or saved.get("namespace") != scope["namespace"]
        or not isinstance(saved.get("name"), str)
        or not re.fullmatch(r"[a-z](?:[-a-z0-9]*[a-z0-9])?", saved["name"])
        or pinned != [saved.get("path")]
        or not isinstance(saved.get("content"), str)
    ):
        message = "fixture preservation identity mismatch"
        raise Blocked(message)
    return saved


class Ownership:
    """Join provider state to live identity before access, verification or recovery."""

    def __init__(
        self, context: Context, runtime: Runtime, terraform: Terraform
    ) -> None:
        """Bind the three frozen services without controller references."""
        self.context = context
        self.runtime = runtime
        self.terraform = terraform

    def owned_guest(
        self,
        resources: Sequence[dict[str, Any]],
        role: Literal["origin", "generator"],
        candidate: Mapping[str, Any] | None = None,
    ) -> Guest:
        """Join the exact module VM/NIC/PIP state to Azure before any SSH."""
        if not _scope_matches(self.context):
            message = "owned SSH configuration scope mismatch"
            raise Blocked(message)
        records = _guest_records(resources, role)
        guest = _guest_identity(records, self.context.settings.scope["subscription_id"])
        if candidate is not None and any(
            candidate.get(key) != value for key, value in guest.items()
        ):
            message = "SSH output/state identity mismatch"
            raise Blocked(message)
        live = self.runtime.az("vm", "show", "--ids", guest["id"], "--show-details")
        if not isinstance(live, dict) or not _live_guest_matches(
            live, guest, records["network_interface"]["id"]
        ):
            message = "live " + role + " ownership/access mismatch"
            raise Blocked(message)
        return guest

    def ssh_argv(self, guest: Guest, policy: Literal["accept-new", "yes"]) -> list[str]:
        """Build shell-free SSH arguments using the private key and host ledger."""
        return [
            "ssh",
            "-i",
            str(self.context.paths.key),
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "StrictHostKeyChecking=" + policy,
            "-o",
            "UserKnownHostsFile=" + str(self.context.paths.known_hosts),
            guest["admin_username"] + "@" + guest["public_ip"],
        ]

    def enroll_guest(self, guest: Guest) -> None:
        """Bound authenticated host enrollment without replacing existing keys."""
        original = self.context.state.deadline
        self.context.state.deadline = min(
            original, time.monotonic() + _ACCESS_BUDGET_SECONDS
        )
        try:
            self.runtime.run([*self.ssh_argv(guest, "accept-new"), "true"])
        finally:
            self.context.state.deadline = original

    def enroll_guests(self) -> None:
        """Validate both live destinations before contacting either guest."""
        outputs = self.context.state.outputs
        if (
            not outputs
            or outputs.get("namespace") != self.context.settings.scope["namespace"]
            or not _scope_matches(self.context)
        ):
            message = "SSH enrollment scope mismatch"
            raise Blocked(message)
        resources = _resources(self.context)
        roles: tuple[Literal["origin", "generator"], ...] = ("origin", "generator")
        guests = [
            self.owned_guest(resources, role, outputs.get(role, {})) for role in roles
        ]
        for guest in guests:
            self.enroll_guest(guest)

    def cleanup_access(self, resources: list[dict[str, Any]]) -> None:
        """Require only the exactly state-owned live generator after partial apply."""
        self.context.state.outputs = None
        if any(
            item.get("type") not in AZURE_TYPES | XC_TYPES
            or not item.get("address")
            or not item.get("values", {}).get("id")
            for item in resources
        ):
            message = "cleanup ownership state incomplete"
            raise Blocked(message)
        self.context.state.resources = resources
        if not any(
            item["type"] == "azurerm_linux_virtual_machine"
            and item["address"].startswith("module.traffic_generator.")
            for item in resources
        ):
            return
        guest = self.owned_guest(resources, "generator")
        self.context.state.outputs = {"generator": guest}

    def catalog_fixtures(self) -> None:
        """Restore private synthetic fixtures only between two ownership-verified guests."""
        outputs = self.context.state.outputs
        if not outputs:
            message = "fixture destinations unavailable"
            raise Blocked(message)
        resources = _resources(self.context)
        origin = self.owned_guest(resources, "origin", outputs["origin"])
        generator = self.owned_guest(resources, "generator", outputs["generator"])
        payload = self.runtime.run(
            [
                *self.ssh_argv(origin, "yes"),
                "sudo",
                "-n",
                "/usr/local/bin/demo-catalog-fixtures",
            ]
        )[0]
        fixtures = json.loads(payload)
        if fixtures.get(
            "fixture_type"
        ) != "seeded-synthetic-origin-accounts" or not fixtures.get("crapi_tokens"):
            message = "private synthetic fixture export failed"
            raise Blocked(message)
        save_json(self.context.paths.state / "catalog-fixtures.json", fixtures)
        self.runtime.run(
            [
                *self.ssh_argv(generator, "yes"),
                "sudo",
                "-n",
                "/usr/local/bin/demo-install-catalog-fixtures",
            ],
            input_text=json.dumps(fixtures),
        )
        self.runtime.phase("synthetic-catalog-fixtures-restored")

    def traffic(self, action: Literal["start", "stop"], cleanup: bool = False) -> None:
        """Control only the owned generator, granting cleanup its bounded stop budget."""
        if action not in ("start", "stop"):
            message = "unsupported traffic action"
            raise Blocked(message)
        outputs = self.context.state.outputs
        if not outputs:
            return
        original = self.context.state.deadline
        if cleanup:
            self.context.state.deadline = time.monotonic() + _ACCESS_BUDGET_SECONDS
        try:
            guest = self.owned_guest(
                _resources(self.context), "generator", outputs["generator"]
            )
            self.enroll_guest(guest)
            if action == "start":
                self.catalog_fixtures()
            self.runtime.run(
                [
                    *self.ssh_argv(guest, "yes"),
                    "sudo",
                    "-n",
                    "/usr/local/bin/tgen-control",
                    action,
                ]
            )
        finally:
            self.context.state.deadline = original
        self.runtime.phase("traffic-" + action)

    def await_catalog(self) -> None:
        """Wait for two successful current-source full passes before launching fresh controls."""
        outputs = self.context.state.outputs
        if not outputs:
            message = "catalog acceptance output unavailable"
            raise Blocked(message)
        guest = self.owned_guest(
            _resources(self.context), "generator", outputs["generator"]
        )
        while True:
            self.runtime.remaining()
            status = json.loads(
                self.runtime.run(
                    [
                        *self.ssh_argv(guest, "yes"),
                        "sudo",
                        "-n",
                        "/usr/local/bin/tgen-control",
                        "status",
                    ]
                )[0]
            )
            passes = status.get("catalog_passes", [])
            if (
                status.get("service_active") is not True
                or status.get("service_enabled") is not True
                or status.get("failures")
            ):
                message = "continuous catalog inactive or failed; private receipts require repair"
                raise Blocked(message)
            if len(passes) >= _REQUIRED_CATALOG_PASSES and all(
                p.get("passed")
                and p.get("catalog_complete")
                and p.get("catalog_accepted")
                and p.get("source_commit") == status.get("source_commit")
                and p.get("artifact_sha256") == status.get("artifact_sha256")
                for p in passes[-_REQUIRED_CATALOG_PASSES:]
            ):
                self.runtime.phase("two-complete-catalog-passes")
                return
            time.sleep(min(30, self.runtime.remaining()))

    def verify_phase(
        self, phase: Literal["readiness", "acceptance", "absence"]
    ) -> None:
        """Run the original verifier against the shared private evidence artifacts."""
        if phase != "absence":
            self.enroll_guests()
        if phase == "acceptance":
            self.await_catalog()
        paths = self.context.paths
        self.runtime.run(
            [
                "bash",
                paths.root / "scripts/demo-verify.sh",
                "--outputs-json",
                paths.state / "outputs.json",
                "--phase",
                phase,
                "--timeout-seconds",
                str(max(1, min(3600, int(self.runtime.remaining())))),
                "--report",
                paths.state / (phase + "-report.json"),
                "--run-manifest",
                paths.state / "run-manifest.json",
                "--ssh-key",
                paths.key,
                "--known-hosts",
                paths.known_hosts,
            ]
        )
        self.runtime.phase("live-" + phase)

    def azure_api_versions(self, ids: Sequence[str]) -> dict[str, str]:
        """Use exact advertisements or prove bounded ancestor candidates on each child."""
        result: dict[str, str] = {}
        catalogs: dict[str, list[dict[str, Any]]] = {}
        candidates: dict[tuple[str, str], list[str]] = {}
        for rid in ids:
            namespace, resource_type = _azure_type(
                rid, self.context.settings.scope["subscription_id"]
            )
            if namespace not in catalogs:
                catalogs[namespace] = self.runtime.az(
                    "provider", "show", "--namespace", namespace
                ).get("resourceTypes", [])
            versions = _stable_versions(catalogs[namespace], resource_type)
            if versions:
                result[rid] = versions[-1]
                continue
            key = (namespace, resource_type)
            if key not in candidates:
                candidates[key] = _ancestor_versions(catalogs[namespace], resource_type)
            if not candidates[key]:
                message = (
                    "no advertised stable ARM API version for "
                    + namespace
                    + "/"
                    + resource_type
                )
                raise Blocked(message)
            result[rid] = _confirmed_version(
                self.runtime, rid, candidates[key], namespace + "/" + resource_type
            )
        return result

    def recover_manifest(self) -> dict[str, Any]:
        """Repair only the known empty-foundation defect without adopting resources."""
        manifest = self.context.paths.state / "run-manifest.json"
        previous = private_json(manifest)
        snapshot = manifest.read_bytes()
        if (
            not isinstance(previous, dict)
            or set(previous) != _MANIFEST_KEYS
            or previous.get("persistent_resource_ids") != {}
            or previous.get("azure_preserved") != []
        ):
            message = "not the known empty-foundation manifest corruption"
            raise Blocked(message)
        self.terraform.local_backend_check()
        persistent, uid = self.terraform.foundation_proof()
        if previous.get("xc_preserved") != _namespace_record(self.context, uid):
            message = "corrupt manifest prior namespace UID mismatch"
            raise Blocked(message)
        self.context.state.persistent, self.context.state.namespace_uid = (
            persistent,
            uid,
        )
        owned = self.inventory(persist=False)
        expected = dict(previous, persistent_resource_ids=persistent)
        if self.context.state.inventory_receipt != expected:
            message = "corrupt manifest resource identity ledger mismatch"
            raise Blocked(message)
        for rid, version in previous["azure_api_versions"].items():
            live = self.runtime.az(
                "rest",
                "--method",
                "get",
                "--url",
                "https://management.azure.com" + rid + "?api-version=" + version,
            )
            if (
                not isinstance(live, dict)
                or str(live.get("id", "")).lower() != rid.lower()
            ):
                message = "corrupt manifest live Azure identity mismatch"
                raise Blocked(message)
        self.terraform.guard_group_children(_resources(self.context))
        self.verify_fixture()
        backup, digest = _backup_manifest(manifest, snapshot)
        save_json(manifest, self.context.state.inventory_receipt)
        return {
            "backup": str(backup),
            "sha256": digest,
            "namespace_uid": uid,
            "owned_count": len(owned),
        }

    def inventory(self, persist: bool = True) -> dict[str, str]:
        """Prove foundation and live ownership before writing the canonical ledger."""
        state, scope = self.context.state, self.context.settings.scope
        if (
            state.persistent != {"namespace": "system/" + scope["namespace"]}
            or not state.namespace_uid
        ):
            message = "inventory foundation not initialized; explicit external migration required"
            raise Blocked(message)
        self.terraform.foundation_proof()
        manifest = self.context.paths.state / "run-manifest.json"
        if persist and manifest.exists():
            _check_previous_manifest(self.context, manifest)
        value = json.loads(
            self.terraform.tf(self.context.paths.app, "show", "-json")[0]
        )
        resources = list(
            managed_resources(value.get("values", {}).get("root_module", {}))
        )
        _check_application_resources(resources, state.persistent)
        if self.context.settings.operation in ("destroy", "rebuild"):
            self.terraform.guard_group_children(resources)
        state.resources = resources
        xc_owned = _xc_ownership(self.runtime, resources, scope["namespace"])
        namespace = self.runtime.xc("/api/web/namespaces/" + scope["namespace"])
        if namespace is None:
            message = "persistent namespace UID missing or changed"
            raise Blocked(message)
        uid = namespace.get("system_metadata", {}).get("uid")
        if not uid or uid != state.namespace_uid:
            message = "persistent namespace UID missing or changed"
            raise Blocked(message)
        receipt = {
            "schema_version": 1,
            "namespace": scope["namespace"],
            "subscription_id": scope["subscription_id"],
            "owned_resources": [
                {
                    "address": item["address"],
                    "type": item["type"],
                    "id": item["values"]["id"],
                }
                for item in resources
            ],
            "azure_owned": sorted(
                {
                    item["values"]["id"].split("|")[0]
                    for item in resources
                    if item["type"] in AZURE_TYPES
                }
            ),
            "xc_owned": xc_owned,
            "azure_preserved": [],
            "xc_preserved": _namespace_record(self.context, uid),
            "persistent_resource_ids": state.persistent,
        }
        receipt["azure_api_versions"] = self.azure_api_versions(
            receipt["azure_owned"] + receipt["azure_preserved"]
        )
        state.inventory_receipt = receipt
        if persist:
            save_json(manifest, receipt)
        return {item["address"]: item["values"]["id"] for item in resources}

    def verify_fixture(self) -> None:
        """Read the pinned fixture through the canonical verifier with GET only."""
        saved = _fixture_receipt(self.context)
        spec = importlib.util.spec_from_file_location(
            "showcase_swagger_upload",
            self.context.paths.root / "scripts/swagger_upload.py",
        )
        if spec is None or spec.loader is None:
            message = "fixture preservation verifier unavailable"
            raise Blocked(message)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        scope = self.context.settings.scope
        try:
            version = helper.version(saved.get("version"))
            expected = (
                "/api/object_store/namespaces/"
                + scope["namespace"]
                + "/stored_objects/swagger/"
                + helper.label(saved["name"])
                + "/"
                + version
            )
            if expected != saved.get("path"):
                message = "fixture preservation path mismatch"
                raise Blocked(message)
            helper.verify(
                _ReadOnlyClient(self.runtime, expected, scope["xc_url"]),
                expected,
                saved["name"],
                scope["namespace"],
                version,
                saved["content"],
            )
        except helper.UploadError as exc:
            message = "fixture preservation content/version verification failed"
            raise Blocked(message) from exc
