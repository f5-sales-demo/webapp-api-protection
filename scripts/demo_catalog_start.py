"""Wait for the new supervised catalog journal before reading pass failures."""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING

from demo_lifecycle_state import Blocked

if TYPE_CHECKING:
    from collections.abc import Sequence

    from demo_lifecycle_runtime import Runtime
    from demo_lifecycle_state import Context

_CATALOG_START_SECONDS = 60


def catalog_status(runtime: Runtime, ssh: Sequence[str]) -> dict:
    """Read the installed control's private status through an owned SSH connection."""
    return json.loads(
        runtime.run([*ssh, "sudo", "-n", "/usr/local/bin/tgen-control", "status"])[0]
    )


def await_catalog_start(
    context: Context, runtime: Runtime, ssh: Sequence[str], previous: dict
) -> None:
    """Require a fresh running journal before interpreting persisted failures."""
    deadline = min(context.state.deadline, time.monotonic() + _CATALOG_START_SECONDS)
    while True:
        status = json.loads(
            runtime.run(
                [
                    *ssh,
                    "sudo",
                    "-n",
                    "/usr/local/bin/tgen-control",
                    "status",
                ]
            )[0]
        )
        fresh = status.get("run_started") is not None and (
            previous.get("service_active") is True
            or status.get("run_started") != previous.get("run_started")
        )
        if fresh:
            if (
                status.get("service_active") is not True
                or status.get("service_enabled") is not True
                or status.get("failures")
            ):
                message = "fresh catalog startup inactive, disabled or failed"
                raise Blocked(message)
            if status.get("status") == "running":
                return
        if time.monotonic() >= deadline:
            message = "catalog startup did not publish a fresh running journal"
            raise Blocked(message)
        runtime.remaining()
        time.sleep(min(1, max(0, deadline - time.monotonic())))
