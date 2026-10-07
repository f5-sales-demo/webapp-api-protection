"""Scope-bound Terraform execution and immutable namespace preservation proof."""

from __future__ import annotations

import json
import os
import re
import shutil
import time
from typing import TYPE_CHECKING, Any, Literal

from demo_lifecycle_plan import require_current, seal
from demo_lifecycle_state import (
    AZURE_TYPES,
    XC_COLLECTIONS,
    XC_TYPES,
    Blocked,
    foundation_identity,
    guard_plan,
    managed_resources,
    private_json,
    save_json,
    secure_artifact,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from pathlib import Path

    from demo_lifecycle_runtime import Runtime
    from demo_lifecycle_state import Context

_FORBIDDEN_FLAGS = (
    "-lock=false",
    "-state=",
    "-state-out=",
    "-backup=",
    "-reconfigure",
    "-migrate-state",
    "-force-copy",
    "-backend=false",
)
_INITIALIZED_VERBS = {"apply", "plan", "output", "state", "show", "import"}


def _object(value: object, message: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise Blocked(message)
    return value


def _namespace_attributes(resource: object) -> dict[str, Any]:
    message = "foundation provider state/receipt mismatch"
    row = _object(resource, message)
    instances = row.get("instances", [])
    if not isinstance(instances, list) or len(instances) != 1:
        raise Blocked(message)
    if (
        row.get("mode") != "managed"
        or row.get("type") != "xcsh_namespace"
        or row.get("name") != "this"
        or row.get("module")
    ):
        raise Blocked(message)
    return _object(_object(instances[0], message).get("attributes", {}), message)


def _namespace_identity(
    attributes: Mapping[str, Any],
    namespace: str,
    message: str = "namespace plan identity mismatch",
) -> None:
    if attributes.get("name") != namespace or attributes.get("id") != namespace:
        raise Blocked(message)


def _raw_state(value: object, label: str, namespace: str) -> dict[str, Any]:
    message = "unknown " + label + " state requires explicit migration"
    stored = _object(value, message)
    version, resources = stored.get("version"), stored.get("resources")
    if (
        isinstance(version, bool)
        or not isinstance(version, int)
        or not isinstance(resources, list)
    ):
        raise Blocked(message)
    if label == "namespace":
        if len(resources) > 1:
            message = "unknown namespace state identity requires explicit migration"
            raise Blocked(message)
        try:
            for row in resources:
                _namespace_identity(_namespace_attributes(row), namespace)
        except Blocked:
            message = "unknown namespace state identity requires explicit migration"
            raise Blocked(message) from None
    return stored


def _backend_metadata(value: object, backend: Mapping[str, str]) -> None:
    message = "unknown backend metadata requires explicit migration"
    cached = _object(_object(value, message).get("backend", {}), message)
    config = _object(cached.get("config", {}), message)
    if (
        cached.get("type") != "local"
        or config.get("path") != backend["path"]
        or config.get("workspace_dir") not in (None, "")
        or config.get("backup") not in (None, "")
    ):
        message = "initialized remote/different backend requires explicit migration"
        raise Blocked(message)


def _check_root(
    context: Context, directory: Path, label: str, backend: Mapping[str, str]
) -> set[Path]:
    for path in (
        directory / "terraform.tfstate",
        directory / "terraform.tfstate.backup",
        directory / ".terraform/terraform.tfstate",
        directory / "terraform.tfstate.d",
    ):
        if path.exists() or path.is_symlink():
            message = (
                "checkout has "
                + label
                + " state/backend metadata; explicit migration required"
            )
            raise Blocked(message)
    state = context.paths.state
    data = state / (label + "-data")
    secure_artifact(data)
    metadata = data / "terraform.tfstate"
    paths = (state / (label + ".tfstate"), state / (label + ".tfstate.backup"))
    if metadata.exists():
        _backend_metadata(private_json(metadata), backend)
    for path in paths:
        if path.exists():
            _raw_state(private_json(path), label, context.settings.scope["namespace"])
    environment = data / "environment"
    if environment.exists() and environment.read_text().strip() not in ("", "default"):
        message = "nondefault Terraform workspace requires explicit migration"
        raise Blocked(message)
    generated = state / (
        "backend.json" if label == "application" else "namespace-backend.json"
    )
    if (
        generated.exists()
        and private_json(generated) != backend
        and (
            metadata.exists()
            or any(state.rglob("*.tfstate"))
            or any(state.rglob("*.tfstate.backup"))
        )
    ):
        message = "existing backend config with state requires explicit migration"
        raise Blocked(message)
    return {metadata, *paths}


def _live_identity(live: dict[str, Any] | None, namespace: str) -> dict[str, str]:
    message = "externally managed namespace missing or identity unavailable"
    row = _object(live, message)
    uid = _object(row.get("system_metadata", {}), message).get("uid")
    metadata = _object(row.get("metadata", {}), message)
    if not isinstance(uid, str) or not uid or metadata.get("name") != namespace:
        raise Blocked(message)
    return {"path": "/api/web/namespaces/" + namespace, "uid": uid}


def _previous_foundation(
    context: Context, persistent: Mapping[str, str]
) -> dict[str, Any] | None:
    state = context.paths.state
    saved = state / "persistent.json"
    if saved.exists() and private_json(saved) != persistent:
        message = "existing foundation receipt incompatible; explicit external migration required"
        raise Blocked(message)
    manifest = state / "run-manifest.json"
    if not manifest.exists():
        return None
    message = (
        "existing run foundation incompatible; explicit external migration required"
    )
    previous = _object(private_json(manifest), message)
    if (
        previous.get("persistent_resource_ids") != persistent
        or previous.get("azure_preserved") != []
    ):
        raise Blocked(message)
    return previous


def _preserved_identity(
    context: Context, identity: dict[str, str], previous: dict[str, Any] | None
) -> None:
    state = context.paths.state
    receipt = state / "namespace-receipt.json"
    if (
        (state / "namespace.tfstate").exists()
        and not receipt.exists()
        and previous is None
        and not context.state.namespace_uid
    ):
        message = "managed namespace UID evidence missing; adoption refused"
        raise Blocked(message)
    if receipt.exists() and private_json(receipt) != identity:
        message = (
            "persistent namespace UID changed; explicit external migration required"
        )
        raise Blocked(message)
    if previous is not None and previous.get("xc_preserved", []) != [identity]:
        message = "persistent namespace identity changed; explicit external migration required"
        raise Blocked(message)
    if context.state.namespace_uid and context.state.namespace_uid != identity["uid"]:
        message = "persistent namespace UID changed"
        raise Blocked(message)


def _namespace_plan(value: dict[str, Any], namespace: str) -> None:
    changes = value.get("resource_changes", [])
    message = "namespace plan must preserve the sole namespace; mutation refused"
    if not isinstance(changes, list) or len(changes) != 1:
        raise Blocked(message)
    row = _object(changes[0], message)
    change = _object(row.get("change", {}), message)
    if change.get("importing") or value.get("deferred_changes"):
        raise Blocked(message)
    if (
        row.get("mode", "managed") != "managed"
        or row.get("address") != "xcsh_namespace.this"
        or row.get("type") != "xcsh_namespace"
        or change.get("actions") != ["no-op"]
    ):
        raise Blocked(message)
    for key in ("before", "after"):
        _namespace_identity(_object(change.get(key) or {}, message), namespace)
    unknown = _object(change.get("after_unknown") or {}, message)
    if any(unknown.get(key) for key in ("name", "id")):
        message = "namespace plan identity unknown"
        raise Blocked(message)
    outputs = _object(value.get("output_changes", {}), message)
    for name, output in outputs.items():
        row = _object(output, message)
        if (
            name not in ("namespace_name", "namespace_id")
            or row.get("after_unknown")
            or row.get("after") != namespace
        ):
            message = "namespace plan output identity mismatch"
            raise Blocked(message)


class Terraform:
    """Preserve local state selection and require exact live namespace identity."""

    def __init__(self, context: Context, runtime: Runtime) -> None:
        """Bind the two shared services without initializing any backend."""
        self.context = context
        self.runtime = runtime

    def tf(
        self, directory: Path, *argv: str | Path, allowed: tuple[int, ...] = (0,)
    ) -> tuple[str, int]:
        """Run Terraform only after inspecting both private local backends."""
        os.umask(0o077)
        self.local_backend_check()
        if any(str(argument).startswith(_FORBIDDEN_FLAGS) for argument in argv):
            message = "Terraform state/locking override prohibited"
            raise Blocked(message)
        paths = self.context.paths
        roots = {paths.app: "application-data", paths.namespace_root: "namespace-data"}
        if directory not in roots:
            message = "unknown Terraform root; refusing state selection"
            raise Blocked(message)
        if directory == paths.namespace_root and (
            "destroy" in argv
            or any(str(argument).startswith("-destroy") for argument in argv)
        ):
            message = "namespace Terraform destroy prohibited; application state only"
            raise Blocked(message)
        data = paths.state / roots[directory]
        if (
            argv
            and str(argv[0]) in _INITIALIZED_VERBS
            and not (data / "terraform.tfstate").exists()
        ):
            message = "local backend not initialized; refusing default checkout state"
            raise Blocked(message)
        env = dict(self.context.env, TF_DATA_DIR=str(data), TF_WORKSPACE="default")
        try:
            return self.runtime.run(
                ["terraform", "-chdir=" + str(directory), *argv],
                allowed=allowed,
                env=env,
            )
        finally:
            for path in paths.state.rglob("*"):
                secure_artifact(path, private=False)
            label = roots[directory].removesuffix("-data")
            for path in (
                data,
                data / "terraform.tfstate",
                paths.state / (label + ".tfstate"),
                paths.state / (label + ".tfstate.backup"),
            ):
                secure_artifact(path)

    def local_backend_check(self) -> Path:
        """Refuse backend migration and return the application backend config path."""
        paths = self.context.paths
        for path in paths.state.rglob("*"):
            secure_artifact(path, private=False)
        permitted: set[Path] = set()
        for directory, label, backend in (
            (paths.app, "application", paths.backend),
            (paths.namespace_root, "namespace", paths.namespace_backend),
        ):
            permitted.update(_check_root(self.context, directory, label, backend))
        for path in paths.state.rglob("*"):
            if (
                path.name.endswith((".tfstate", ".tfstate.backup"))
                and path not in permitted
            ):
                message = "unexpected persistent state/backend metadata requires explicit migration"
                raise Blocked(message)
        if (paths.state / "terraform.tfstate.d").exists():
            message = "alternate workspace state requires explicit migration"
            raise Blocked(message)
        return paths.state / "backend.json"

    def app_init(self) -> None:
        """Initialize only the private application backend, then check source HCL."""
        paths = self.context.paths
        backend = self.local_backend_check()
        save_json(backend, paths.backend)
        self.tf(paths.app, "init", "-input=false", "-backend-config=" + str(backend))
        for directory in (paths.app, *sorted((paths.app / "modules").glob("*"))):
            files = sorted(directory.glob("*.tf"))
            if files:
                self.tf(paths.app, "fmt", "-check", *files)
        self.tf(paths.app, "validate")
        self.context.state.app_ready = True
        self.runtime.phase("application-secure-local-backend")

    def namespace_prepare(self) -> None:
        """Read live UID and persist preservation evidence without tenant mutation."""
        self.local_backend_check()
        namespace = self.context.settings.scope["namespace"]
        persistent = foundation_identity(namespace)
        previous = _previous_foundation(self.context, persistent)
        live = self.runtime.xc("/api/web/namespaces/" + namespace, allow_absent=True)
        identity = _live_identity(live, namespace)
        _preserved_identity(self.context, identity, previous)
        self.context.state.namespace_uid = identity["uid"]
        self.context.state.persistent = persistent
        save_json(self.context.paths.state / "persistent.json", persistent)
        save_json(self.context.paths.state / "namespace-receipt.json", identity)
        self.runtime.phase("namespace-identity-preserved")

    def namespace_state_identity(self) -> None:
        """Require the sole provider namespace to match its bare import identity."""
        value = _object(
            json.loads(self.tf(self.context.paths.namespace_root, "show", "-json")[0]),
            "namespace state unavailable",
        )
        resources = list(
            managed_resources(value.get("values", {}).get("root_module", {}))
        )
        if (
            len(resources) != 1
            or resources[0].get("address") != "xcsh_namespace.this"
            or resources[0].get("type") != "xcsh_namespace"
        ):
            message = "namespace Terraform state identity mismatch; adoption refused"
            raise Blocked(message)
        _namespace_identity(
            _object(resources[0].get("values", {}), "namespace state unavailable"),
            self.context.settings.scope["namespace"],
            "namespace Terraform state identity mismatch; adoption refused",
        )

    def namespace_tf_prepare(self, create: bool = False) -> None:
        """Import only the observed namespace and apply only a preservation plan."""
        self.local_backend_check()
        paths = self.context.paths
        if create and self.context.settings.operation not in ("deploy", "rebuild"):
            message = "namespace import/apply permitted only during deployment"
            raise Blocked(message)
        exists = (paths.state / "namespace.tfstate").exists()
        if not exists and not create:
            message = (
                "namespace Terraform state missing; deploy must import foundation first"
            )
            raise Blocked(message)
        if (
            not self.context.state.namespace_uid
            and not (paths.state / "namespace-receipt.json").is_file()
        ):
            message = "namespace UID evidence missing; preflight must confirm identity before import"
            raise Blocked(message)
        self.namespace_prepare()
        backend = paths.state / "namespace-backend.json"
        save_json(backend, paths.namespace_backend)
        self.tf(
            paths.namespace_root,
            "init",
            "-input=false",
            "-backend-config=" + str(backend),
        )
        self.tf(paths.namespace_root, "validate")
        if not exists:
            self.namespace_prepare()
            # The provider imports the bare tenant-scoped name, not system/name.
            self.tf(
                paths.namespace_root,
                "import",
                "-input=false",
                "xcsh_namespace.this",
                self.context.settings.scope["namespace"],
            )
        self.namespace_state_identity()
        plan = paths.state / "namespace.plan"
        secure_artifact(plan)
        _, code = self.tf(
            paths.namespace_root,
            "plan",
            "-input=false",
            "-detailed-exitcode",
            "-out=" + str(plan),
            allowed=(0, 2),
        )
        secure_artifact(plan)
        value = _object(
            json.loads(self.tf(paths.namespace_root, "show", "-json", str(plan))[0]),
            "namespace plan unavailable",
        )
        _namespace_plan(value, self.context.settings.scope["namespace"])
        if not create and code != 0:
            message = "namespace preservation plan is not zero-change"
            raise Blocked(message)
        if create:
            self.namespace_prepare()
            self.tf(paths.namespace_root, "apply", "-input=false", str(plan))
            self.namespace_state_identity()
        self.namespace_prepare()
        self.runtime.phase("namespace-terraform-preserved")

    def foundation_proof(self) -> tuple[dict[str, str], str]:
        """Join receipts, exact provider state and live UID without writing a ledger."""
        self.local_backend_check()
        namespace = self.context.settings.scope["namespace"]
        persistent = foundation_identity(namespace)
        state = self.context.paths.state
        identity = private_json(state / "namespace-receipt.json")
        raw = _raw_state(
            private_json(state / "namespace.tfstate"), "namespace", namespace
        )
        resources = raw["resources"]
        if private_json(state / "persistent.json") != persistent or len(resources) != 1:
            message = "foundation provider state/receipt mismatch"
            raise Blocked(message)
        _namespace_identity(_namespace_attributes(resources[0]), namespace)
        live = self.runtime.xc("/api/web/namespaces/" + namespace)
        expected = _live_identity(live, namespace)
        if identity != expected or self.context.state.namespace_uid not in (
            None,
            expected["uid"],
        ):
            message = "foundation namespace UID identity mismatch"
            raise Blocked(message)
        return persistent, expected["uid"]

    def guard_conflicts(self, plan: dict[str, Any]) -> None:
        """Refuse Azure group adoption and out-of-state XC creation conflicts."""
        for item in plan.get("resource_changes", []):
            if item.get("mode") == "data" or "create" not in item["change"]["actions"]:
                continue
            after = item["change"].get("after") or {}
            if item["type"] == "azurerm_resource_group":
                name = after.get("name")
                if not name or self.runtime.az("group", "exists", "--name", name):
                    message = (
                        "out-of-state Azure resource-group conflict or unknown name"
                    )
                    raise Blocked(message)
            if item["type"] == "xcsh_swagger_object":
                namespace, name = after.get("namespace"), after.get("name")
                if namespace != self.context.settings.scope["namespace"] or not name:
                    message = "unknown Swagger creation identity"
                    raise Blocked(message)
                query = (
                    "?name="
                    + name
                    + "&query_type=EXACT_MATCH&latest_version_only=false"
                )
                listing = self.runtime.xc(
                    "/api/object_store/namespaces/"
                    + namespace
                    + "/stored_objects/swagger"
                    + query
                )
                if listing is None or listing.get("items") != []:
                    message = (
                        "out-of-state Swagger conflict; reviewed adoption required"
                    )
                    raise Blocked(message)
                continue
            if item["type"] in XC_TYPES:
                collection = XC_COLLECTIONS.get(item["type"])
                name, namespace = after.get("name"), after.get("namespace")
                if (
                    not collection
                    or namespace != self.context.settings.scope["namespace"]
                    or not isinstance(name, str)
                    or not re.fullmatch(r"[a-z][a-z0-9-]*[a-z0-9]", name)
                ):
                    message = "unknown XC creation identity; conflict check refused"
                    raise Blocked(message)
                path = (
                    "/api/config/namespaces/"
                    + namespace
                    + "/"
                    + collection
                    + "/"
                    + name
                )
                if self.runtime.xc(path, allow_absent=True) is not None:
                    message = "out-of-state XC resource conflict; adoption refused"
                    raise Blocked(message)

    def guard_group_children(self, resources: Sequence[dict[str, Any]]) -> None:
        """Require all group children to be state-owned or proven VM OS disks."""
        ids = {
            row["values"]["id"].split("|")[0].lower()
            for row in resources
            if row["type"] in AZURE_TYPES
        }
        for item in resources:
            if item["type"] == "azurerm_linux_virtual_machine":
                vm = self.runtime.az("vm", "show", "--ids", item["values"]["id"])
                disk = (
                    vm.get("storageProfile", {})
                    .get("osDisk", {})
                    .get("managedDisk", {})
                    .get("id")
                )
                if not disk:
                    message = "owned VM OS-disk identity unavailable"
                    raise Blocked(message)
                ids.add(disk.lower())
        for item in resources:
            if item["type"] == "azurerm_resource_group":
                children = self.runtime.az(
                    "resource", "list", "--resource-group", item["values"]["name"]
                )
                if any(child["id"].lower() not in ids for child in children):
                    message = "resource group contains unowned children; refusing group destruction"
                    raise Blocked(message)

    def plan(
        self,
        name: str,
        mode: Literal["deploy", "rebuild", "noop", "destroy"] = "deploy",
        owned: Mapping[str, str] | None = None,
    ) -> Path:
        """Create a private plan and enforce ownership, scope and mutation mode."""
        self.local_backend_check()
        paths = self.context.paths
        path = paths.state / (name + ".plan")
        secure_artifact(path)
        argv = [
            "plan",
            "-input=false",
            "-detailed-exitcode",
            "-var-file=" + str(paths.vars),
            "-out=" + str(path),
        ]
        if mode == "destroy":
            argv.append("-destroy")
        _, code = self.tf(paths.app, *argv, allowed=(0, 2))
        secure_artifact(path)
        parsed = _object(
            json.loads(self.tf(paths.app, "show", "-json", path)[0]),
            "application plan unavailable",
        )
        if name != "review":
            guard_plan(parsed, mode, owned, self.context.state.persistent.values())
        if mode in ("deploy", "rebuild") and name != "review":
            self.guard_conflicts(parsed)
        if mode == "noop" and code != 0:
            message = "nonzero detailed-exitcode drift"
            raise Blocked(message)
        seal(self.context, path, parsed)
        self.runtime.phase(name + "-guarded-plan")
        return path

    def reviewed_rebuild(self, owned: Mapping[str, str]) -> Path:
        """Consume the exact current private review plan after ownership checks."""
        path = self.context.paths.state / "review.plan"
        require_current(self.context, path)
        parsed = _object(
            json.loads(self.tf(self.context.paths.app, "show", "-json", path)[0]),
            "reviewed rebuild plan unavailable",
        )
        guard_plan(parsed, "rebuild", owned, self.context.state.persistent.values())
        self.guard_conflicts(parsed)
        backup = self.context.paths.state / ("rebuild-backup-" + str(time.time_ns()))
        backup.mkdir(mode=0o700)
        for name in (
            "application.tfstate",
            "namespace.tfstate",
            self.context.paths.vars.name,
            "swagger-receipt.json",
            "run-manifest.json",
            "outputs.json",
            "review.plan",
            "review.binding.json",
            "review.summary.json",
        ):
            source = self.context.paths.state / name
            secure_artifact(source)
            if source.is_file():
                snapshot = backup / (name + ".snapshot")
                shutil.copyfile(source, snapshot)
                snapshot.chmod(0o600)
        self.runtime.phase("reviewed-rebuild-guarded-plan")
        return path

    def apply(self, plan: Path) -> None:
        """Apply only the freshly bound application plan under the lifecycle lock."""
        require_current(self.context, plan)
        self.tf(self.context.paths.app, "apply", "-input=false", str(plan))

    def get_outputs(self) -> None:
        """Validate showcase output scope before saving private provider output."""
        outputs = _object(
            json.loads(self.tf(self.context.paths.app, "output", "-json")[0]),
            "missing showcase outputs; state lost or incomplete",
        )
        message = "missing showcase outputs; state lost or incomplete"
        showcase = _object(outputs.get("showcase"), message)
        value = _object(showcase.get("value"), message)
        scope = self.context.settings.scope
        if value.get("namespace") != scope["namespace"] or sorted(
            value.get("domains", [])
        ) != sorted(scope["domains"]):
            message = "outputs scope mismatch"
            raise Blocked(message)
        pairs = _object(outputs.get("use_cases"), "use-case outputs missing")
        value["use_cases"] = _object(pairs.get("value"), "use-case outputs missing")
        snapshot = _object(
            json.loads(self.tf(self.context.paths.app, "show", "-json")[0]),
            "application state unavailable",
        )
        objects = [
            row
            for row in managed_resources(
                snapshot.get("values", {}).get("root_module", {})
            )
            if row.get("address") == "xcsh_swagger_object.showcase"
        ]
        if len(objects) != 1:
            message = "Terraform-owned Swagger fixture missing"
            raise Blocked(message)
        fixture = objects[0]["values"]
        save_json(
            self.context.paths.state / "swagger-receipt.json",
            {
                "name": fixture["name"],
                "namespace": fixture["namespace"],
                "version": fixture["version"],
                "path": fixture["path"],
                "sha256": fixture["sha256"],
                "content": fixture["content"],
                "api_url": scope["xc_url"],
            },
        )
        inputs = private_json(self.context.paths.vars)
        inputs["api_definition_swagger_specs"] = [fixture["path"]]
        save_json(self.context.paths.vars, inputs)
        self.context.state.outputs = value
        save_json(self.context.paths.state / "outputs.json", outputs)
