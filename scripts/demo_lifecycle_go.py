"""Verify the entire declared Go distribution through an ownership-checked guest route."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from demo_lifecycle_state import Blocked

if TYPE_CHECKING:
    from collections.abc import Sequence

    from demo_lifecycle_runtime import Runtime

GO_COMPILER_FILE_COUNT = 15036


def verify_go_toolchain(runtime: Runtime, ssh_argv: Sequence[str]) -> None:
    """Reject compiler content drift during canonical installed-artifact verification."""
    proof, _ = runtime.run(
        [
            *ssh_argv,
            "sudo -n python3 /usr/local/lib/demo-go-artifacts.py toolchain --lock /opt/traffic-generator-go-runtime/artifacts.json --proxy /opt/traffic-generator-go-runtime/proxy --archive /opt/traffic-generator-go1.26.8.linux-amd64.tar.gz --toolchain /opt/traffic-generator-toolchain",
        ]
    )
    compiler = json.loads(proof)
    if (
        compiler.get("verified") is not True
        or compiler.get("checked") != GO_COMPILER_FILE_COUNT
    ):
        message = "installed Go compiler differs from declared distribution"
        raise Blocked(message)
