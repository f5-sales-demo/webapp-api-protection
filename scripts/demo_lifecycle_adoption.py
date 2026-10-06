"""Execute only an explicitly reviewed, source-bound adoption map."""

from __future__ import annotations

import hashlib
import re
import shutil
import time
from typing import TYPE_CHECKING

from demo_lifecycle_plan import require_current
from demo_lifecycle_state import Blocked, private_json, save_json

if TYPE_CHECKING:
    from pathlib import Path

    from demo_lifecycle_state import Context
    from demo_lifecycle_terraform import Terraform


def adopt(context: Context, terraform: Terraform, mapping: Path) -> None:
    """Import reviewed Swagger identities, preserving state and receipt backups."""
    document = private_json(mapping)
    if (
        document.get("schema_version") != 1
        or document.get("scope") != context.settings.scope
    ):
        message = "adoption review scope mismatch"
        raise Blocked(message)
    entries = document.get("imports")
    if not isinstance(entries, list) or len(entries) != 1:
        message = "adoption requires the sole reviewed Swagger import"
        raise Blocked(message)
    entry = entries[0]
    if not isinstance(entry, dict):
        message = "adoption import entry must be an object"
        raise Blocked(message)
    version = entry.get("version")
    valid_version = (
        isinstance(version, str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", version)
        and version.lower() != "latest"
    )
    expected_id = (
        context.settings.scope["namespace"] + "/showcase-form-native/" + str(version)
    )
    if (
        not valid_version
        or entry.get("address") != "xcsh_swagger_object.showcase"
        or entry.get("id") != expected_id
        or not entry.get("reviewed")
    ):
        message = "adoption identity or ownership review missing"
        raise Blocked(message)
    plan = context.paths.state / "review.plan"
    require_current(context, plan)
    state = context.paths.state / "application.tfstate"
    if hashlib.sha256(state.read_bytes()).hexdigest() != document.get("state_sha256"):
        message = "adoption state changed since inventory review"
        raise Blocked(message)
    exact = (
        "/api/object_store/namespaces/"
        + context.settings.scope["namespace"]
        + "/stored_objects/swagger/showcase-form-native/"
        + entry["version"]
    )
    live = terraform.runtime.xc(exact)
    if not isinstance(live, dict):
        message = "adoption exact-version readback unavailable"
        raise Blocked(message)
    content = live.get("string_value")
    configured = (context.paths.app / "fixtures/showcase-openapi.json").read_text()
    if (
        content != configured
        or hashlib.sha256(configured.encode()).hexdigest() != entry.get("sha256")
        or live.get("metadata", {}).get("version") != entry["version"]
        or live.get("metadata", {}).get("namespace")
        != context.settings.scope["namespace"]
        or live.get("metadata", {}).get("name") != "showcase-form-native"
    ):
        message = "adoption exact-version content or metadata differs"
        raise Blocked(message)
    backup = context.paths.state.parent / ("adoption-backup-" + str(time.time_ns()))
    backup.mkdir(mode=0o700)
    for name in (
        "application.tfstate",
        "namespace.tfstate",
        "run-manifest.json",
        "swagger-receipt.json",
        "application.tfvars.json",
    ):
        source = context.paths.state / name
        if source.is_file():
            shutil.copyfile(source, backup / name)
            (backup / name).chmod(0o600)
    terraform.tf(
        context.paths.app,
        "import",
        "-input=false",
        "-var-file=" + str(context.paths.vars),
        entry["address"],
        entry["id"],
    )
    save_json(
        context.paths.state / "adoption-receipt.json",
        {
            "schema_version": 1,
            "imports": entries,
            "backup": str(backup),
            "review_sha256": hashlib.sha256(mapping.read_bytes()).hexdigest(),
        },
    )
