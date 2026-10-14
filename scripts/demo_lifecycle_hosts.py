"""Preserve SSH trust except after verified owned Azure VM replacement."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any, Literal

from demo_lifecycle_state import Blocked

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from demo_lifecycle_runtime import Runtime
    from demo_lifecycle_state import Context, Guest


def rotate_rebuilt_keys(
    context: Context,
    runtime: Runtime,
    records: Sequence[
        tuple[
            dict[str, dict[str, Any]],
            dict[str, dict[str, Any]],
            Literal["origin", "generator"],
        ]
    ],
    resolve: Callable[[Literal["origin", "generator"]], Guest],
) -> None:
    """Prove all replacement identities before touching any enrolled host entry."""
    rotations: list[str] = []
    for before, after, role in records:
        old_vm, new_vm = before["linux_virtual_machine"], after["linux_virtual_machine"]
        old_id, new_id = (
            old_vm.get("virtual_machine_id"),
            new_vm.get("virtual_machine_id"),
        )
        if not old_id or not new_id:
            message = "rebuild unique VM identity unavailable"
            raise Blocked(message)
        if old_id == new_id:
            continue
        guest = resolve(role)
        live = runtime.az("vm", "show", "--ids", guest["id"], "--show-details")
        if not isinstance(live, dict) or live.get("vmId") != new_id:
            message = "rebuild live unique VM identity mismatch"
            raise Blocked(message)
        if old_vm["id"].lower() != new_vm["id"].lower():
            message = "rebuild changed owned VM resource identity"
            raise Blocked(message)
        if before["public_ip"]["ip_address"] != guest["public_ip"]:
            message = "rebuild changed owned public IP identity"
            raise Blocked(message)
        rotations.append(guest["public_ip"])
    if not rotations:
        return
    ledger = context.paths.known_hosts
    snapshot = ledger.read_bytes()
    backup = ledger.with_name("known_hosts.pre-rebuild-" + str(time.time_ns()))
    with backup.open("xb") as stream:
        backup.chmod(0o600)
        stream.write(snapshot)
    for host in rotations:
        runtime.run(["ssh-keygen", "-R", host, "-f", ledger])
    runtime.phase("owned-rebuilt-host-keys-rotated")
