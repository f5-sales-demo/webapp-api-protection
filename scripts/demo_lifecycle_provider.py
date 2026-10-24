"""Require the latest immutable XC provider release before lifecycle work."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

from demo_lifecycle_state import Blocked, save_json

if TYPE_CHECKING:
    from demo_lifecycle_runtime import Runtime
    from demo_lifecycle_state import Context

_RELEASE_URL = (
    "https://api.github.com/repos/f5-sales-demo/terraform-provider-xcsh/releases/latest"
)
_ROOTS = (
    "versions.tf",
    "namespace/main.tf",
    "modules/http-lb/versions.tf",
    "modules/comparison/versions.tf",
)
_LOCKS = (".terraform.lock.hcl", "namespace/.terraform.lock.hcl")


def require_latest_provider(context: Context, runtime: Runtime) -> None:
    """Fail before deployment when any declared XC pin is older than latest."""
    raw, _ = runtime.run(
        ["curl", "--fail", "--silent", "--show-error", "--max-time", "30", _RELEASE_URL]
    )
    release = json.loads(raw)
    tag = release.get("tag_name", "")
    if (
        not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag)
        or release.get("draft") is not False
        or release.get("prerelease") is not False
        or release.get("immutable") is not True
    ):
        message = "latest XC provider release is unavailable or not immutable"
        raise Blocked(message)
    version = tag[1:]
    for relative in _ROOTS:
        source = (context.paths.app / relative).read_text()
        match = re.search(r'version\s*=\s*"= ([0-9.]+)"', source)
        if match is None or match[1] != version:
            message = "XC provider pin must match latest published release " + tag
            raise Blocked(message)
    for relative in _LOCKS:
        source = (context.paths.app / relative).read_text()
        block = re.search(
            r'provider "registry.terraform.io/f5-sales-demo/xcsh" \{(.*?)\n\}',
            source,
            re.DOTALL,
        )
        match = re.search(r'version\s*=\s*"([0-9.]+)"', block[1]) if block else None
        if match is None or match[1] != version:
            message = "XC provider lock must match latest published release " + tag
            raise Blocked(message)
    save_json(
        context.paths.state / "latest-provider-release.json",
        {"tag": tag, "published_at": release["published_at"], "immutable": True},
    )
    runtime.phase("latest-immutable-provider-release")
