"""Lifecycle control for the Terraform-installed AI display traffic service."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from collections.abc import Sequence

    from demo_lifecycle_runtime import Runtime
    from demo_lifecycle_state import Context


def control(
    context: Context,
    runtime: Runtime,
    ssh: Sequence[str],
    action: Literal["start", "stop"],
) -> None:
    """Start after readiness, or disable before catalog cleanup; validate service state."""
    if "ai-waf" not in (context.state.outputs or {}).get("use_cases", {}):
        return
    command = "enable" if action == "start" else "disable"
    runtime.run(
        [*ssh, "sudo", "-n", "systemctl", command, "--now", "demo-ai-traffic.service"]
    )
    if action == "start":
        runtime.run(
            [
                *ssh,
                "sudo",
                "-n",
                "systemctl",
                "is-active",
                "--quiet",
                "demo-ai-traffic.service",
            ]
        )
