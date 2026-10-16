"""Execute only an explicitly reviewed, source-bound adoption map."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import time
from typing import TYPE_CHECKING

from demo_lifecycle_ai_adoption import OWNERS, validate_ai_imports
from demo_lifecycle_plan import require_current
from demo_lifecycle_state import Blocked, private_json, save_json

if TYPE_CHECKING:
    from pathlib import Path

    from demo_lifecycle_state import Context
    from demo_lifecycle_terraform import Terraform


_MAX_SWAGGER_IMPORTS = 2


def _state_identities(state: Path) -> dict[str, str]:
    """Read authoritative addresses, rejecting duplicate owners before mutation."""
    identities = {}
    for row in private_json(state).get("resources", []):
        if row.get("mode", "managed") != "managed":
            continue
        for instance in row.get("instances", []):
            address = ".".join(
                filter(None, (row.get("module"), row["type"], row["name"]))
            )
            if "index_key" in instance:
                address += "[" + json.dumps(instance["index_key"]) + "]"
            if address in identities:
                message = "adoption state contains duplicate resource addresses"
                raise Blocked(message)
            attributes = instance.get("attributes", {})
            identity = attributes.get("id")
            if row["type"] in {
                "xcsh_http_loadbalancer",
                "xcsh_app_firewall",
                "xcsh_user_identification",
            }:
                if identity != attributes.get("name") or not attributes.get(
                    "namespace"
                ):
                    message = "adoption XC state identity is incomplete"
                    raise Blocked(message)
                identity = attributes["namespace"] + "/" + attributes["name"]
            identities[address] = identity
    return identities


def _pending_imports(state: Path, entries: list[dict]) -> list[dict]:
    """Resume only exact reviewed identities; never import over a different owner."""
    identities = _state_identities(state)
    pending = []
    for entry in entries:
        address, identity = entry["address"], entry["id"]
        if address in identities and identities[address] != identity:
            message = "adoption destination owns a different identity"
            raise Blocked(message)
        if any(
            owner != address and value == identity
            for owner, value in identities.items()
        ):
            message = "adoption identity already has a different Terraform owner"
            raise Blocked(message)
        if address not in identities:
            pending.append(entry)
    return pending


def _require_import_identity(state: Path, entry: dict) -> None:
    """Check the actual saved identity before recording an import as completed."""
    if _state_identities(state).get(entry["address"]) != entry["id"]:
        message = "adoption import did not preserve the reviewed identity"
        raise Blocked(message)


def _move_listeners(
    document: dict, state: Path, terraform: Terraform, context: Context
) -> list[dict]:
    moves = document.get("moves", [])
    permitted_moves = {
        "module.http_lb.xcsh_http_loadbalancer.this": 'module.http_lb.xcsh_http_loadbalancer.this["primary"]',
        "module.http_lb.xcsh_http_loadbalancer.http[0]": 'module.http_lb.xcsh_http_loadbalancer.this["http"]',
    }
    if not isinstance(moves, list) or len(moves) not in (0, len(permitted_moves)):
        message = "adoption requires the reviewed identity-preserving listener moves"
        raise Blocked(message)
    listed = set()
    for move in moves:
        if (
            not isinstance(move, dict)
            or not isinstance(move.get("from"), str)
            or permitted_moves.get(str(move.get("from"))) != move.get("to")
            or move.get("from") in listed
        ):
            message = "adoption listener move differs from reviewed configuration"
            raise Blocked(message)
        listed.add(move["from"])
    snapshot = private_json(state)
    identities = {}
    for row in snapshot.get("resources", []):
        for instance in row.get("instances", []):
            address = row.get("module", "") + "." + row["type"] + "." + row["name"]
            if "index_key" in instance:
                address += "[" + json.dumps(instance["index_key"]) + "]"
            identities[address.lstrip(".")] = instance.get("attributes", {}).get("id")
    if not moves and any(source in identities for source in permitted_moves):
        message = "adoption requires reviewed moves for legacy listener addresses"
        raise Blocked(message)
    for move in moves:
        source, destination = move["from"], move["to"]
        if (
            not move.get("id")
            or identities.get(source, identities.get(destination)) != move["id"]
        ):
            message = "adoption listener identity differs from inventory"
            raise Blocked(message)
        if source in identities and destination in identities:
            message = "adoption listener source and destination both exist"
            raise Blocked(message)
    for move in moves:
        if move["from"] in identities:
            terraform.tf(context.paths.app, "state", "mv", move["from"], move["to"])
    return moves


def _validate_imports(context: Context, terraform: Terraform, entries: list) -> None:
    """Check every declared content-addressed identity before any state mutation."""
    declared = {
        "xcsh_swagger_object.showcase": ("showcase-form-", "showcase-openapi.json"),
        "xcsh_swagger_object.comparison": ("comparison-", "comparison-openapi.json"),
    }
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("address") not in declared:
            message = "adoption import entry is not a declared Swagger owner"
            raise Blocked(message)
        address = entry["address"]
        prefix, filename = declared[address]
        content = (context.paths.app / "fixtures" / filename).read_text()
        sha256 = hashlib.sha256(content.encode()).hexdigest()
        name = prefix + sha256[:32]
        version = entry.get("version")
        if (
            not isinstance(version, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", version)
            or version.lower() == "latest"
        ):
            message = "adoption exact version missing"
            raise Blocked(message)
        if (
            address in seen
            or entry.get("id")
            != context.settings.scope["namespace"] + "/" + name + "/" + version
            or entry.get("sha256") != sha256
            or entry.get("reviewed") is not True
        ):
            message = "adoption identity or ownership review missing"
            raise Blocked(message)
        seen.add(address)
        exact = (
            "/api/object_store/namespaces/"
            + context.settings.scope["namespace"]
            + "/stored_objects/swagger/"
            + name
            + "/"
            + version
        )
        live = terraform.runtime.xc(exact)
        if (
            not isinstance(live, dict)
            or live.get("string_value") != content
            or live.get("metadata", {}).get("version") != version
            or live.get("metadata", {}).get("namespace")
            != context.settings.scope["namespace"]
            or live.get("metadata", {}).get("name") != name
        ):
            message = "adoption exact-version content or metadata differs"
            raise Blocked(message)


def adopt(context: Context, terraform: Terraform, mapping: Path) -> None:
    """Import reviewed declared identities, preserving state and receipt backups."""
    document = private_json(mapping)
    if (
        document.get("schema_version") != 1
        or document.get("scope") != context.settings.scope
    ):
        message = "adoption review scope mismatch"
        raise Blocked(message)
    entries = document.get("imports")
    if not isinstance(entries, list) or not 1 <= len(
        entries
    ) <= _MAX_SWAGGER_IMPORTS + len(OWNERS):
        message = "adoption requires reviewed declared Swagger or AI comparison imports"
        raise Blocked(message)
    plan = context.paths.state / "review.plan"
    require_current(context, plan)
    state = context.paths.state / "application.tfstate"
    if hashlib.sha256(state.read_bytes()).hexdigest() != document.get("state_sha256"):
        message = "adoption state changed since inventory review"
        raise Blocked(message)
    if any(not isinstance(entry, dict) for entry in entries):
        message = "adoption import mapping must contain objects"
        raise Blocked(message)
    ai_entries = [entry for entry in entries if entry.get("address") in OWNERS]
    swagger_entries = [entry for entry in entries if entry.get("address") not in OWNERS]
    if len(swagger_entries) > _MAX_SWAGGER_IMPORTS:
        message = "too many declared Swagger imports"
        raise Blocked(message)
    _validate_imports(context, terraform, swagger_entries)
    validate_ai_imports(context, terraform, ai_entries)
    pending = _pending_imports(state, entries)
    backup = context.paths.state.parent / ("adoption-backup-" + str(time.time_ns()))
    backup.mkdir(mode=0o700)
    for name in (
        "application.tfstate",
        "namespace.tfstate",
        "run-manifest.json",
        "swagger-receipt.json",
        "application.tfvars.json",
        "adoption-review.json",
        "adoption-receipt.json",
        "review.plan",
        "review.binding.json",
        "review.summary.json",
    ):
        source = context.paths.state / name
        if source.is_file():
            shutil.copyfile(source, backup / name)
            (backup / name).chmod(0o600)
    receipt = {
        "schema_version": 2,
        "status": "running",
        "imports": entries,
        "completed": [],
        "already_owned": [entry for entry in entries if entry not in pending],
        "moves": document.get("moves", []),
        "backup": str(backup),
        "review_sha256": hashlib.sha256(mapping.read_bytes()).hexdigest(),
    }

    def checkpoint() -> None:
        receipt["state_sha256"] = hashlib.sha256(state.read_bytes()).hexdigest()
        save_json(backup / "progress.json", receipt)
        save_json(context.paths.state / "adoption-receipt.json", receipt)

    checkpoint()
    try:
        _move_listeners(document, state, terraform, context)
        checkpoint()
        for entry in pending:
            terraform.tf(
                context.paths.app,
                "import",
                "-input=false",
                "-var-file=" + str(context.paths.vars),
                entry["address"],
                entry["id"],
            )
            _require_import_identity(state, entry)
            receipt["completed"].append(entry)
            checkpoint()
        validate_ai_imports(context, terraform, ai_entries)
        receipt["status"] = "passed"
        checkpoint()
    except BaseException as exc:
        # Preserve interruptions and partial imports without exposing private error text.
        receipt["status"] = "failed"
        receipt["error_type"] = type(exc).__name__
        checkpoint()
        raise
