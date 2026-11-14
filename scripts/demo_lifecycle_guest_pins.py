"""Verify installed immutable guest artifacts against declared Terraform pins."""

from __future__ import annotations

import json
import shlex
from typing import TYPE_CHECKING, Any

from demo_lifecycle_go import verify_go_toolchain
from demo_lifecycle_state import Blocked
from demo_package_pins import verify_package_pins

if TYPE_CHECKING:
    from demo_lifecycle_ownership import Ownership


def verify(ownership: Ownership, resources: list[dict[str, Any]]) -> None:
    """Check source receipts and exact hashes/modes before readiness or acceptance."""
    outputs = ownership.context.state.outputs
    if outputs is None:
        message = "guest pin outputs unavailable"
        raise Blocked(message)
    for role in ("origin", "generator"):
        guest = ownership.owned_guest(resources, role, outputs[role])
        filename = (
            "/opt/origin-server/install-receipt.json"
            if role == "origin"
            else "/opt/traffic-generator/source-receipt.json"
        )
        raw, _ = ownership.runtime.run(
            [*ownership.ssh_argv(guest, "yes"), "sudo -n cat " + filename]
        )
        receipt = json.loads(raw)
        declared = outputs.get(role + "_source", {})
        actual_hash = receipt.get(
            "archive_sha256" if role == "origin" else "artifact_sha256"
        )
        if receipt.get("source_commit") != declared.get(
            "commit"
        ) or actual_hash != declared.get("archive_sha256"):
            message = "installed " + role + " source differs from Terraform pins"
            raise Blocked(message)
        files = json.loads(
            (ownership.context.paths.app / "guest-files.json").read_text()
        )[role]
        check = (
            "import hashlib,json,pathlib,sys; "
            "expected=json.load(sys.stdin); failures=[]; "
            "\nfor name,record in expected.items():"
            "\n p=pathlib.Path(name)"
            "\n if p.is_symlink() or not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest()!=record['sha256'] or ('mode' in record and (p.stat().st_mode & 0o777) != int(record['mode'], 8)): failures.append(name)"
            "\nprint(json.dumps({'verified':not failures,'checked':len(expected),'failures':failures}))"
        )
        argv = [
            *ownership.ssh_argv(guest, "yes"),
            "sudo -n python3 -c " + shlex.quote(check),
        ]
        result, _ = ownership.runtime.run(argv, input_text=json.dumps(files))
        proof = json.loads(result)
        if proof.get("verified") is not True or proof.get("checked") != len(files):
            message = "installed " + role + " files differ from Terraform artifacts"
            raise Blocked(message)
        if role == "generator":
            verify_go_toolchain(ownership.runtime, ownership.ssh_argv(guest, "yes"))
        verify_package_pins(
            ownership.runtime,
            ownership.ssh_argv(guest, "yes"),
            ownership.context.paths.app,
            role,
        )
    ownership.runtime.phase("declared-guest-pins")
