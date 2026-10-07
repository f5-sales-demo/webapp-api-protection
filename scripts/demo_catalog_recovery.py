"""Enroll only the dedicated forced-command order recovery key on owned guests."""

from __future__ import annotations

import json
import shlex
from typing import TYPE_CHECKING

from demo_lifecycle_state import Blocked, secure_artifact

if TYPE_CHECKING:
    from collections.abc import Callable

    from demo_lifecycle_runtime import Runtime
    from demo_lifecycle_state import Context, Guest


def enroll_order(
    context: Context,
    runtime: Runtime,
    origin: Guest,
    generator: Guest,
    ssh: Callable[[Guest], list[str]],
    fixtures: dict,
) -> None:
    """Install private purpose-specific keys; no tenant credential enters either VM."""
    key = context.paths.state / "order-recovery-key"
    secure_artifact(key)
    if not key.exists():
        runtime.run(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "waap-catalog-order-recovery",
                "-f",
                key,
            ]
        )
    runtime.run(
        [*ssh(origin), "sudo", "-n", "/usr/local/bin/enroll-order-recovery"],
        input_text=key.with_suffix(".pub").read_text().strip(),
    )
    known = runtime.run(
        ["ssh-keygen", "-F", origin["public_ip"], "-f", context.paths.known_hosts]
    )[0]
    rows = [
        line.split() for line in known.splitlines() if line and not line.startswith("#")
    ]
    if not rows:
        message = "owned order recovery host key unavailable"
        raise Blocked(message)
    ledger = (
        "\n".join(origin["public_ip"] + " " + " ".join(row[1:3]) for row in rows) + "\n"
    )
    package = {"key": key.read_text(), "known_hosts": ledger}
    install = "import json,sys,pathlib,os;os.umask(0o077);d=json.load(sys.stdin);p=pathlib.Path('/opt/traffic-generator');[(p/('order-recovery-'+k)).write_text(v) for k,v in d.items()];[(p/('order-recovery-'+k)).chmod(0o600) for k in d]"
    runtime.run(
        [*ssh(generator), "sudo", "-n", "python3", "-B", "-c", shlex.quote(install)],
        input_text=json.dumps(package),
    )
    fixtures["order_recovery"] = {
        "host": origin["public_ip"],
        "key": "/opt/traffic-generator/order-recovery-key",
        "known_hosts": "/opt/traffic-generator/order-recovery-known_hosts",
    }
