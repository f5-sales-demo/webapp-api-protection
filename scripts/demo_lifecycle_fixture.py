"""Read and verify only the exact Terraform-owned Swagger object version."""

from __future__ import annotations

import importlib.util
import re
from typing import TYPE_CHECKING, Any

from demo_lifecycle_state import Blocked, private_json

if TYPE_CHECKING:
    from demo_lifecycle_runtime import Runtime
    from demo_lifecycle_state import Context


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
    name = saved.get("name")
    if not isinstance(name, str) or not re.fullmatch(
        r"[a-z](?:[-a-z0-9]*[a-z0-9])?", name
    ):
        message = "fixture preservation identity mismatch"
        raise Blocked(message)
    if (
        saved.get("api_url") != scope["xc_url"]
        or saved.get("namespace") != scope["namespace"]
        or pinned != [saved.get("path")]
        or not isinstance(saved.get("content"), str)
    ):
        message = "fixture preservation identity mismatch"
        raise Blocked(message)
    return saved


def verify_fixture(context: Context, runtime: Runtime) -> None:
    """Read the pinned fixture through the canonical verifier with GET only."""
    saved = _fixture_receipt(context)
    spec = importlib.util.spec_from_file_location(
        "showcase_swagger_upload",
        context.paths.root / "scripts/swagger_upload.py",
    )
    if spec is None or spec.loader is None:
        message = "fixture preservation verifier unavailable"
        raise Blocked(message)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    scope = context.settings.scope
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
            _ReadOnlyClient(runtime, expected, scope["xc_url"]),
            expected,
            saved["name"],
            scope["namespace"],
            version,
            saved["content"],
        )
    except helper.UploadError as exc:
        message = "fixture preservation content/version verification failed"
        raise Blocked(message) from exc
