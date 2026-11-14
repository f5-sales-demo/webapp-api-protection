"""Collect private catalog telemetry from the canonical Ubuntu operator."""

from __future__ import annotations

import argparse
import fcntl
import time

from demo_catalog_clock import align_generator_clock, catalog_client
from demo_catalog_evidence import collect_pending
from demo_lifecycle import Lifecycle
from demo_verify_types import EvidenceError


def main() -> None:
    """Run the credential-bearing collector only from the canonical Ubuntu operator."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout-seconds", type=int, default=7200)
    args = parser.parse_args()
    lifecycle = Lifecycle(
        argparse.Namespace(
            operation="plan",
            config=None,
            state_dir=None,
            timeout_seconds=args.timeout_seconds,
        )
    )
    state = lifecycle.context.paths.state
    with (state / "lifecycle.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        lifecycle.preflight(False)
        lifecycle.terraform.get_outputs()
        lifecycle.ownership.inventory(persist=False)
        outputs = lifecycle.context.state.outputs
        resources = lifecycle.context.state.resources
        if outputs is None or resources is None:
            message = "catalog operator state unavailable"
            raise EvidenceError(message)
        guest = lifecycle.ownership.owned_guest(
            resources, "generator", outputs["generator"]
        )
        ssh = lifecycle.ownership.ssh_argv(guest, "yes")
        client = catalog_client(lifecycle.context, outputs)
        align_generator_clock(client, lifecycle.runtime, ssh)
        while True:
            lifecycle.runtime.remaining()
            collect_pending(lifecycle.runtime, ssh, outputs, client)
            time.sleep(min(5, lifecycle.runtime.remaining()))


if __name__ == "__main__":
    main()
