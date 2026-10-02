"""Synthetic private contexts shared by lifecycle service regression tests."""

from __future__ import annotations

import importlib
import os
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal
from unittest.mock import patch

from demo_test_support import ensure

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

if TYPE_CHECKING:
    import unittest

    import demo_lifecycle as lifecycle
    import demo_lifecycle_ownership as ownership_module
    import demo_lifecycle_runtime as runtime_module
    import demo_lifecycle_state as state_module
    import demo_lifecycle_terraform as terraform_module
    from demo_lifecycle import Lifecycle
    from demo_lifecycle_ownership import Ownership
    from demo_lifecycle_runtime import Runtime
    from demo_lifecycle_state import Context, Guest
    from demo_lifecycle_terraform import Terraform
else:
    lifecycle = importlib.import_module("demo_lifecycle")
    ownership_module = importlib.import_module("demo_lifecycle_ownership")
    runtime_module = importlib.import_module("demo_lifecycle_runtime")
    state_module = importlib.import_module("demo_lifecycle_state")
    terraform_module = importlib.import_module("demo_lifecycle_terraform")

__all__ = [
    "ROOT",
    "TEST_APPROVAL",
    "TEST_SCOPE",
    "Files",
    "Fixture",
    "Options",
    "bind_fixture",
    "guest_state",
    "lifecycle",
    "live_vm",
    "make_fixture",
    "ownership_module",
    "runtime_module",
    "state_module",
    "temporary_files",
    "terraform_module",
]

TEST_APPROVAL = {
    "subscription_id": "00000000-0000-0000-0000-000000000000",
    "tenant_id": "11111111-1111-1111-1111-111111111111",
}
TEST_SCOPE = dict(state_module.FIXED, **TEST_APPROVAL)


@dataclass
class Options:
    """Mutable command options using only synthetic identity evidence."""

    operation: Literal["deploy", "verify", "rebuild", "destroy"] = "deploy"
    config: Path | None = None
    state_dir: Path | None = None
    timeout_seconds: int = 30


@dataclass
class Files:
    """Private temporary file locations and mutable command options."""

    base: Path
    root: Path
    home: Path
    operator_base: Path
    args: Options


@dataclass
class Fixture:
    """Real service owners bound to one synthetic context, never a facade."""

    files: Files
    context: Context
    lifecycle: Lifecycle
    runtime: Runtime
    terraform: Terraform
    ownership: Ownership


@contextmanager
def _temporary_directory() -> Iterator[str]:
    """Keep temporary files alive through the registered test context."""
    with tempfile.TemporaryDirectory() as directory:
        yield directory


def temporary_files(case: unittest.TestCase) -> Files:
    """Register private temporary files and isolate approval environment."""
    temporary = case.enterContext(_temporary_directory())
    base = Path(temporary)
    root = base / "checkout"
    (root / "terraform/namespace").mkdir(parents=True)
    (root / "terraform/showcase.tfvars.json").write_text("{}")
    home = base / "home"
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("DEMO_AZURE_")
    }
    environment.update(
        DEMO_AZURE_SUBSCRIPTION_ID=TEST_APPROVAL["subscription_id"],
        DEMO_AZURE_TENANT_ID=TEST_APPROVAL["tenant_id"],
    )
    home_patch = patch.object(Path, "home", return_value=home)
    home_patch.start()
    case.addCleanup(home_patch.stop)
    env_patch = patch.dict(os.environ, environment, clear=True)
    env_patch.start()
    case.addCleanup(env_patch.stop)
    return Files(
        base,
        root,
        home,
        home / ".local/state/waap-showcase",
        Options(state_dir=base / "state"),
    )


def bind_fixture(files: Files) -> Fixture:
    """Create composed production services using the supplied private files."""
    obj = lifecycle.Lifecycle(files.args, files.root)
    return Fixture(files, obj.context, obj, obj.runtime, obj.terraform, obj.ownership)


def make_fixture(case: unittest.TestCase) -> Fixture:
    """Build an approved synthetic fixture with no cloud or network calls."""
    files = temporary_files(case)
    files.args.config = files.base / "operator.json"
    state_module.save_json(
        files.args.config,
        dict(TEST_APPROVAL, expected_azure_user="operator@example.test"),
    )
    return bind_fixture(files)


def guest_state(
    role: Literal["origin", "generator"],
) -> tuple[list[dict[str, Any]], Guest]:
    """Return exact state ownership joins for one synthetic guest."""
    module = {"origin": "origin_server", "generator": "traffic_generator"}[role]
    prefix = "module." + module + "."
    base = (
        "/subscriptions/"
        + TEST_SCOPE["subscription_id"]
        + "/resourceGroups/"
        + module
        + "/providers/"
    )
    vm_id = base + "Microsoft.Compute/virtualMachines/main"
    nic_id = base + "Microsoft.Network/networkInterfaces/main"
    pip_id = base + "Microsoft.Network/publicIPAddresses/main"
    guest: Guest = {
        "id": vm_id,
        "admin_username": "azureuser",
        "public_ip": "192.0.2.1" if role == "generator" else "192.0.2.2",
    }
    values = [
        (
            "linux_virtual_machine",
            {
                "id": vm_id,
                "admin_username": "azureuser",
                "network_interface_ids": [nic_id],
            },
        ),
        (
            "network_interface",
            {"id": nic_id, "ip_configuration": [{"public_ip_address_id": pip_id}]},
        ),
        ("public_ip", {"id": pip_id, "ip_address": guest["public_ip"]}),
    ]
    return [
        {
            "type": "azurerm_" + kind,
            "address": prefix + "azurerm_" + kind + ".main",
            "values": value,
        }
        for kind, value in values
    ], guest


def live_vm(resources: list[dict[str, Any]], guest: Guest) -> dict[str, Any]:
    """Return a synthetic Azure readback for the exact state-owned VM."""
    ensure(len(resources) >= 2)
    return {
        "id": guest["id"],
        "osProfile": {"adminUsername": guest["admin_username"]},
        "publicIps": guest["public_ip"],
        "networkProfile": {"networkInterfaces": [{"id": resources[1]["values"]["id"]}]},
    }
