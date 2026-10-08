"""Bind private saved plans to exact source, inputs, locks and state."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from typing import TYPE_CHECKING, Any

from demo_lifecycle_state import Blocked, private_json, save_json

if TYPE_CHECKING:
    from pathlib import Path

    from demo_lifecycle_state import Context


def digest(path: Path) -> str | None:
    """Hash an existing regular artifact without exposing its content."""
    if path.is_symlink():
        message = "saved plan binding rejects symbolic links"
        raise Blocked(message)
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def source_digest(root: Path) -> str:
    """Include tracked and untracked source while excluding ignored private files."""
    git = shutil.which("git")
    if git is None:
        message = "git is required for saved plan source binding"
        raise Blocked(message)
    result = subprocess.run(  # noqa: S603 - fixed executable and exact argv
        [
            git,
            "-C",
            str(root),
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
        check=True,
        capture_output=True,
    )
    hashes = {}
    for raw in sorted(set(result.stdout.split(b"\0")) - {b""}):
        relative = raw.decode("utf-8")
        hashes[relative] = digest(root / relative)
    return hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()


def binding(context: Context, plan: Path) -> dict[str, Any]:
    """Capture every mutable input capable of invalidating the plan."""
    paths = context.paths
    return {
        "schema_version": 1,
        "source": source_digest(paths.root),
        "inputs": digest(paths.vars),
        "provider_locks": digest(paths.app / ".terraform.lock.hcl"),
        "application_state": digest(paths.state / "application.tfstate"),
        "namespace_state": digest(paths.state / "namespace.tfstate"),
        "plan": digest(plan),
        "scope": context.settings.scope,
    }


def seal(context: Context, plan: Path, parsed: dict[str, Any]) -> None:
    """Save private binding and a reviewable change report without applying."""
    save_json(plan.with_suffix(".binding.json"), binding(context, plan))
    changes = [
        {
            "address": row["address"],
            "actions": row["change"]["actions"],
            "import": bool(row["change"].get("importing")),
            "moved_from": row.get("previous_address"),
        }
        for row in parsed.get("resource_changes", [])
        if row["change"]["actions"] != ["no-op"]
        or row.get("previous_address")
        or row["change"].get("importing")
    ]
    outputs = {
        key: value["actions"]
        for key, value in parsed.get("output_changes", {}).items()
        if value["actions"] != ["no-op"]
    }
    save_json(
        plan.with_suffix(".summary.json"),
        {
            "resources": changes,
            "outputs": outputs,
            "zero_actions": not changes and not outputs,
        },
    )


def require_current(context: Context, plan: Path) -> None:
    """Reject stale or substituted plans before any application write."""
    saved = private_json(plan.with_suffix(".binding.json"))
    if saved != binding(context, plan):
        message = "saved plan is stale: source, inputs, locks, state or plan changed"
        raise Blocked(message)
