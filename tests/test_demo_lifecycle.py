"""Orchestration, native runtime and capacity regressions on actual service owners."""

from __future__ import annotations

import fcntl
import json
import subprocess
import sys
import threading
import time
import unittest
from dataclasses import dataclass, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

from demo_lifecycle_fixtures import (
    ROOT,
    TEST_SCOPE,
    Fixture,
    lifecycle,
    make_fixture,
    runtime_module,
    state_module,
)
from demo_test_support import ensure, ensure_equal, expect_error

PINNED = "/api/object_store/namespaces/webapp-api-protection/stored_objects/swagger/showcase/v1"


def delete_plan(address: str, kind: str, rid: str) -> dict[str, Any]:
    """Build one exact synthetic deletion candidate."""
    change = {"actions": ["delete"], "before": {"id": rid}}
    resource = {"address": address, "type": kind, "change": change}
    return {"resource_changes": [resource]}


def stub(case: unittest.TestCase, owner: object, name: str, **kwargs: Any) -> Mock:
    """Patch the actual service method and restore it after the case."""
    replacement = patch.object(owner, name, **kwargs)
    mocked = replacement.start()
    case.addCleanup(replacement.stop)
    return mocked


def process_context(stderr: str, stdout: str = "") -> Any:
    """Provide the real subprocess context-manager protocol for diagnostics."""
    process = Mock(returncode=1)
    process.communicate.return_value = stdout, stderr
    manager = Mock()
    manager.__enter__ = Mock(return_value=process)
    manager.__exit__ = Mock(return_value=False)
    return patch.object(runtime_module.subprocess, "Popen", return_value=manager)


def fake_deploy(
    case: unittest.TestCase, fixture: Fixture, fail_ready: bool = False
) -> list[str]:
    """Record deployment sequencing without external side effects."""
    calls: list[str] = []
    for method, label in (
        ("namespace_tf_prepare", "backend"),
        ("app_init", "init"),
        ("get_outputs", "outputs"),
    ):
        stub(
            case,
            fixture.terraform,
            method,
            side_effect=lambda *_args, label=label, **_kwargs: calls.append(label),
        )
    stub(case, fixture.runtime, "run", return_value=(PINNED, 0))

    def plan(name: str, *_args: Any) -> Path:
        calls.append(name)
        return Path(name)

    def terraform(*_args: Any, **_kwargs: Any) -> tuple[str, int]:
        calls.append("apply")
        return "", 0

    stub(case, fixture.terraform, "plan", side_effect=plan)
    stub(case, fixture.terraform, "tf", side_effect=terraform)
    stub(case, fixture.terraform, "apply", side_effect=terraform)
    stub(
        case,
        fixture.ownership,
        "inventory",
        side_effect=lambda: calls.append("inventory"),
    )

    def verify(phase: str) -> None:
        calls.append(phase)
        if phase == "readiness" and fail_ready:
            message = "not ready"
            raise lifecycle.Blocked(message)

    stub(case, fixture.ownership, "verify_phase", side_effect=verify)
    stub(
        case,
        fixture.ownership,
        "traffic",
        side_effect=lambda action: calls.append("traffic-" + action),
    )
    return calls


@dataclass
class Capacity:
    """Fixture and explicitly patched service methods for quota evidence."""

    fixture: Fixture
    az: Mock
    namespace: Mock
    inventory: Mock
    verify_fixture: Mock
    outputs: Mock
    verify_phase: Mock


def capacity_fixture(case: unittest.TestCase, allocated: bool = True) -> Capacity:
    """Supply exact synthetic owned VM and subscription capacity readbacks."""
    fixture = make_fixture(case)
    stub(case, lifecycle, "_xc_capacity")
    context = fixture.context
    context.settings = replace(context.settings, operation="rebuild")
    namespace = stub(case, fixture.terraform, "namespace_prepare")
    stub(case, fixture.terraform, "app_init")
    inventory = stub(case, fixture.ownership, "inventory")
    verify_fixture = stub(case, fixture.ownership, "verify_fixture")
    outputs = stub(case, fixture.terraform, "get_outputs")
    verify_phase = stub(case, fixture.ownership, "verify_phase")
    state_module.save_json(context.paths.vars, {})
    base = (
        "/subscriptions/"
        + TEST_SCOPE["subscription_id"]
        + "/resourceGroups/owned/providers/Microsoft.Compute/virtualMachines/"
    )
    resources: list[dict[str, Any]] = [
        {
            "type": "azurerm_linux_virtual_machine",
            "values": {"id": base + str(i), "size": size},
        }
        for i, size in enumerate(("Standard_D16s_v3", "Standard_F16s_v2"))
    ]
    context.state.resources = resources

    def az(*args: str) -> Any:
        if args[0] == "rest":
            return {"value": [{"actions": ["*"], "notActions": []}]}
        if args[1] == "show":
            item = next(row for row in resources if row["values"]["id"] == args[3])
            return {
                "id": args[3],
                "location": "eastus2",
                "hardwareProfile": {"vmSize": item["values"]["size"]},
                "powerState": "VM running" if allocated else "VM deallocated",
            }
        if args[1] == "list-usage":
            return [
                {
                    "name": {"value": name},
                    "limit": count,
                    "currentValue": count,
                    "unit": "Count",
                }
                for name, count in (
                    ("cores", 32),
                    ("standarddsv3family", 16),
                    ("standardfsv2family", 16),
                )
            ]
        return [
            {"name": size, "restrictions": []}
            for size in ("Standard_D16s_v3", "Standard_F16s_v2")
        ]

    return Capacity(
        fixture,
        stub(case, fixture.runtime, "az", side_effect=az),
        namespace,
        inventory,
        verify_fixture,
        outputs,
        verify_phase,
    )


def invalid_quota(previous: Any, field: str, value: Any) -> Any:
    """Bind a malformed quota mutation without late loop captures."""

    def az(*args: str) -> Any:
        result = previous(*args)
        if args[:2] == ("vm", "list-usage"):
            result[0][field] = value
        return result

    return az


def quota_shape(previous: Any, mode: str) -> Any:
    """Bind each unavailable or ambiguous quota response."""

    def az(*args: str) -> Any:
        result = previous(*args)
        if args[:2] == ("vm", "list-usage"):
            if mode == "missing":
                return result[1:]
            if mode == "duplicate":
                return [*result, result[0]]
            if mode == "shape":
                return {}
            result[0]["unit"] = "VMs" if mode == "unknown-unit" else None
        return result

    return az


class Orchestration(unittest.TestCase):
    """Coordinate the real services without a monolithic lifecycle facade."""

    def setUp(self) -> None:
        """Build one approved private fixture."""
        self.fixture = make_fixture(self)

    def test_deploy_order_and_noop_apply(self) -> None:
        """Readiness precedes traffic and drift uses a saved plan."""
        calls = fake_deploy(self, self.fixture)
        self.fixture.lifecycle.deploy()
        ensure_equal(
            calls,
            [
                "backend",
                "init",
                "application",
                "apply",
                "outputs",
                "inventory",
                "readiness",
                "traffic-start",
                "acceptance",
                "post-acceptance-drift",
                "apply",
                "post-second-apply-drift",
            ],
        )
        generated = json.loads(self.fixture.context.paths.vars.read_text())
        ensure_equal(
            generated.get("api_definition_swagger_specs", []),
            [],
        )

    def test_deploy_refreshes_stale_private_mud_profile_from_canonical_profile(
        self,
    ) -> None:
        """Use the current repository profile rather than private stale values."""
        paths = self.fixture.context.paths
        (paths.root / "terraform/showcase.tfvars.json").write_text(
            (ROOT / "terraform/showcase.tfvars.json").read_text()
        )
        state_module.save_json(
            paths.vars, {"mud_enabled": True, "mud_bad_traffic": False}
        )
        fake_deploy(self, self.fixture)
        self.fixture.lifecycle.deploy()
        generated = json.loads(paths.vars.read_text())
        ensure(generated["mud_enabled"] is True)
        ensure(generated["mud_bad_traffic"] is True)

    def test_readiness_failure_never_starts_traffic(self) -> None:
        """Fail closed before traffic or acceptance."""
        calls = fake_deploy(self, self.fixture, True)
        with expect_error(lifecycle.Blocked):
            self.fixture.lifecycle.deploy()
        ensure("traffic-start" not in calls and "acceptance" not in calls)

    def test_deploy_does_not_issue_swagger_outside_terraform(self) -> None:
        """Only Terraform may issue the declared Swagger version."""
        fake_deploy(self, self.fixture)
        command = stub(self, self.fixture.runtime, "run")
        self.fixture.lifecycle.deploy()
        command.assert_not_called()

    def test_missing_external_namespace_blocks(self) -> None:
        """Never create an unavailable external namespace."""
        stub(self, self.fixture.runtime, "xc", return_value=None)
        with expect_error(lifecycle.Blocked, "namespace missing"):
            self.fixture.terraform.namespace_prepare()

    def test_existing_group_never_adopted(self) -> None:
        """Reject group adoption before apply."""
        stub(self, self.fixture.runtime, "az", return_value=True)
        plan = {
            "resource_changes": [
                {
                    "type": "azurerm_resource_group",
                    "change": {"actions": ["create"], "after": {"name": "existing"}},
                }
            ]
        }
        with expect_error(lifecycle.Blocked):
            self.fixture.terraform.guard_conflicts(plan)

    def test_unowned_child_blocks_destroy(self) -> None:
        """Preserve group children absent from owned state."""
        rid = "/subscriptions/s/resourceGroups/g"
        stub(
            self,
            self.fixture.runtime,
            "az",
            return_value=[{"id": rid + "/providers/Microsoft.Compute/disks/unowned"}],
        )
        with expect_error(lifecycle.Blocked):
            self.fixture.terraform.guard_group_children(
                [{"type": "azurerm_resource_group", "values": {"id": rid, "name": "g"}}]
            )

    def test_process_timeout_is_nonzero(self) -> None:
        """Keep the native subprocess total deadline."""
        self.fixture.context.state.deadline = time.monotonic() + 0.05
        with expect_error(subprocess.TimeoutExpired):
            self.fixture.runtime.run(
                [sys.executable, "-c", "import time; time.sleep(10)"]
            )

    def test_shell_payload_remains_literal_argument(self) -> None:
        """Execute argv without shell interpolation."""
        payload = "$(touch /tmp/lifecycle-no-shell); echo unsafe"
        stdout, code = self.fixture.runtime.run(
            [sys.executable, "-c", "import sys; print(sys.argv[1])", payload]
        )
        ensure_equal(code, 0)
        ensure_equal(stdout.strip(), payload)

    def test_rebuild_holds_one_outer_lock(self) -> None:
        """Rebuild executes quota, destroy and deploy under one lock."""
        fixture = self.fixture
        fixture.context.settings = replace(
            fixture.context.settings, operation="rebuild"
        )
        calls: list[str] = []

        def preflight() -> None:
            calls.append("preflight")
            fixture.lifecycle.capacity_permissions()

        stub(
            self,
            fixture.lifecycle,
            "preflight",
            side_effect=lambda _deploying: preflight(),
        )
        for method, label in (
            ("destroy", "destroy"),
            ("capacity_permissions", "quota"),
            ("deploy", "deploy"),
        ):
            stub(
                self,
                fixture.lifecycle,
                method,
                side_effect=lambda label=label: calls.append(label),
            )
        fixture.lifecycle.execute()
        ensure_equal(calls, ["preflight", "quota", "destroy", "deploy"])
        ensure_equal(fixture.context.state.receipt["status"], "verified")

    def test_cleanup_never_masks_primary_failure(self) -> None:
        """Retain the original failure even when cleanup fails."""
        fixture = self.fixture
        stub(self, fixture.lifecycle, "preflight")
        stub(
            self,
            fixture.lifecycle,
            "deploy",
            side_effect=lifecycle.Blocked("primary failure"),
        )
        stub(
            self,
            fixture.ownership,
            "traffic",
            side_effect=lifecycle.Blocked("cleanup failure"),
        )
        with expect_error(lifecycle.Blocked, "primary failure"):
            fixture.lifecycle.execute()
        receipt = json.loads(
            (fixture.context.paths.state / "operation-receipt.json").read_text()
        )
        ensure_equal(receipt["status"], "blocked")
        ensure_equal(receipt["error"], "primary failure")

    def test_missing_tool_blocks_preflight(self) -> None:
        """Check prerequisites before touching external services."""
        with (
            patch.object(lifecycle.shutil, "which", return_value=None),
            expect_error(lifecycle.Blocked, "missing prerequisite"),
        ):
            self.fixture.lifecycle.preflight(True)

    def test_destroy_requires_exact_captured_id(self) -> None:
        """Refuse deletion against a different state identity."""
        plan = delete_plan("vm.main", "azurerm_linux_virtual_machine", "other")
        with expect_error(lifecycle.Blocked):
            state_module.guard_plan(plan, "destroy", {"vm.main": "owned"})

    def test_persistent_id_blocks_even_allowed_type(self) -> None:
        """Preserved identities cannot be destroyed by type allowance."""
        plan = delete_plan("rg.main", "azurerm_resource_group", "persistent")
        with expect_error(lifecycle.Blocked):
            state_module.guard_plan(
                plan, "destroy", {"rg.main": "persistent"}, ["persistent"]
            )

    def test_symlink_directory_rejected(self) -> None:
        """Keep private state directories free of symlink aliases."""
        link = self.fixture.files.base / "link"
        link.symlink_to(self.fixture.context.paths.state, target_is_directory=True)
        with expect_error(lifecycle.Blocked):
            state_module.secure_directory(link, self.fixture.files.root)

    def test_reentrant_lock_rejected(self) -> None:
        """Refuse a competing native lifecycle lock."""
        with (self.fixture.context.paths.state / "lifecycle.lock").open("a") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            with expect_error(lifecycle.Blocked, "another lifecycle"):
                self.fixture.lifecycle.execute()


class RuntimeContract(unittest.TestCase):
    """Exercise subprocess contracts, redaction and readonly profile proof."""

    def setUp(self) -> None:
        """Build one approved private fixture."""
        self.fixture = make_fixture(self)

    def test_acceptance_verifier_exit_code_is_not_success(self) -> None:
        """Record a real failed verifier and stop traffic."""
        fixture = self.fixture
        scripts = fixture.files.root / "scripts"
        scripts.mkdir()
        (scripts / "demo-verify.sh").write_text("exit 2\n")
        stub(self, fixture.lifecycle, "preflight")
        stub(self, fixture.ownership, "enroll_guests")
        stub(self, fixture.ownership, "await_catalog")
        stub(self, fixture.ownership, "verify_guest_pins")
        stub(
            self,
            fixture.lifecycle,
            "deploy",
            side_effect=lambda: fixture.ownership.verify_phase("acceptance"),
        )
        traffic = stub(self, fixture.ownership, "traffic")
        with expect_error(lifecycle.Blocked, "bash exit 2"):
            fixture.lifecycle.execute()
        ensure_equal(fixture.context.state.receipt["commands"][-1]["exit_code"], 2)
        ensure(
            "live-acceptance"
            not in [p["name"] for p in fixture.context.state.receipt["phases"]]
        )
        traffic.assert_called_once_with("stop", cleanup=True)

    def test_registry_configuration_is_not_inherited(self) -> None:
        """Disable inherited registry and plugin cache configuration."""
        ensure_equal(self.fixture.context.env["TF_CLI_CONFIG_FILE"], "/dev/null")
        ensure("TF_PLUGIN_CACHE_DIR" not in self.fixture.context.env)

    def test_cached_backend_migration_failure_is_not_reconfigured(self) -> None:
        """Do not retry a backend failure with migration overrides."""
        mocked = stub(
            self,
            self.fixture.terraform,
            "tf",
            side_effect=lifecycle.Blocked(
                "required subprocess failed: terraform exit 1 (state-lock)"
            ),
        )
        with expect_error(lifecycle.Blocked):
            self.fixture.terraform.app_init()
        ensure_equal(mocked.call_count, 1)
        ensure(not self.fixture.context.state.app_ready)
        ensure("-reconfigure" not in mocked.call_args.args)
        ensure("-migrate-state" not in mocked.call_args.args)

    def test_runtime_fmt_excludes_fixture_and_test_roots(self) -> None:
        """Format only runtime Terraform sources."""
        app = self.fixture.context.paths.app
        (app / "main.tf").write_text("terraform {}\n")
        for folder in ("tests", "fixtures", "modules/http-lb"):
            target = app / folder
            target.mkdir(parents=True)
            (target / "main.tf").write_text("terraform {}\n")
        mocked = stub(self, self.fixture.terraform, "tf", return_value=("", 0))
        self.fixture.terraform.app_init()
        fmt = [call.args for call in mocked.call_args_list if "fmt" in call.args]
        ensure_equal(len(fmt), 2)
        ensure(all("-recursive" not in args for args in fmt))
        ensure_equal({args[0] for args in fmt}, {app})
        ensure_equal(
            {str(args[-1]) for args in fmt},
            {str(app / "main.tf"), str(app / "modules/http-lb/main.tf")},
        )

    def test_profile_uses_actual_user_identification_mode(self) -> None:
        """Read actual source profile without accepting synthetic proof."""
        profile = json.loads((ROOT / "terraform/showcase.tfvars.json").read_text())
        ensure_equal(profile["mud_user_id"], "user_identification")
        ensure_equal(profile["mud_user_id_rule"], "http_header_name")
        ensure_equal(profile["rate_limit_choice"], "api_rate_limit")

    def test_nonzero_acceptance_is_redacted_and_stops_traffic(self) -> None:
        """Withhold stderr secrets from errors and persisted receipts."""
        fixture = self.fixture
        stub(self, fixture.lifecycle, "preflight")
        stub(
            self,
            fixture.lifecycle,
            "deploy",
            side_effect=lambda: fixture.runtime.run(
                [
                    sys.executable,
                    "-c",
                    'import sys; print("secret-token", file=sys.stderr); sys.exit(7)',
                ]
            ),
        )
        traffic = stub(self, fixture.ownership, "traffic")
        with expect_error(lifecycle.Blocked, "exit 7") as caught:
            fixture.lifecycle.execute()
        traffic.assert_called_once_with("stop", cleanup=True)
        receipt = json.loads(
            (fixture.context.paths.state / "operation-receipt.json").read_text()
        )
        ensure_equal(receipt["status"], "blocked")
        ensure_equal(receipt["commands"][-1]["exit_code"], 7)
        ensure("secret-token" not in str(caught.exception) + json.dumps(receipt))

    def test_interrupt_retains_primary_failure_and_stops_traffic(self) -> None:
        """Persist interruption and perform bounded cleanup."""
        fixture = self.fixture
        stub(self, fixture.lifecycle, "preflight")
        stub(self, fixture.lifecycle, "deploy", side_effect=KeyboardInterrupt)
        traffic = stub(self, fixture.ownership, "traffic")
        with expect_error(KeyboardInterrupt):
            fixture.lifecycle.execute()
        traffic.assert_called_once_with("stop", cleanup=True)
        ensure_equal(fixture.context.state.receipt["error"], "KeyboardInterrupt")

    def test_xc_conflict_or_unknown_identity_blocks(self) -> None:
        """Refuse conflicting or unresolved XC create identities."""
        xc = stub(
            self,
            self.fixture.runtime,
            "xc",
            return_value={"metadata": {"name": "existing"}},
        )
        after: dict[str, Any] = {
            "name": "existing",
            "namespace": state_module.FIXED["namespace"],
        }
        plan = {
            "resource_changes": [
                {
                    "type": "xcsh_origin_pool",
                    "change": {"actions": ["create"], "after": after},
                }
            ]
        }
        with expect_error(lifecycle.Blocked, "conflict"):
            self.fixture.terraform.guard_conflicts(plan)
        xc.assert_called_once()
        after["name"] = None
        xc.reset_mock()
        with expect_error(lifecycle.Blocked, "unknown XC"):
            self.fixture.terraform.guard_conflicts(plan)
        xc.assert_not_called()

    def test_subprocess_version_error_classification_preserves_denial_priority(
        self,
    ) -> None:
        """Permission and authentication diagnostics outrank unsupported versions."""
        for stderr, expected in (
            ("ERROR: (InvalidApiVersionParameter)", "arm-api-version-unsupported"),
            ("ERROR: (UnsupportedApiVersion)", "arm-api-version-unsupported"),
            ("403 InvalidApiVersionParameter", "HTTP-403-permission"),
            ("401 UnsupportedApiVersion", "authentication"),
            ("ResourceNotFound 404", "upstream-output-withheld"),
            ("request timeout", "timeout"),
        ):
            with self.subTest(stderr=stderr):
                with process_context(stderr), expect_error(lifecycle.Blocked, expected):
                    self.fixture.runtime.run(["az", "rest"])
                ensure_equal(
                    self.fixture.context.state.receipt["commands"][-1]["diagnostic"],
                    expected,
                )

    def test_subprocess_diagnostics_are_bounded_and_redacted(self) -> None:
        """Classify only bounded evidence and never persist upstream text."""
        withheld = "upstream-output-withheld"
        oneof = (
            "Oneof fields should be exclusive: blocking_page, use_default_blocking_page"
        )
        cases = [
            (
                "terraform",
                f"HTTP 400: {oneof}; body=string:///secret-token",
                "HTTP-400-configuration",
            ),
            ("terraform", f"Error: {oneof}", withheld),
            (
                "terraform",
                "Error acquiring the state lock\nError message: resource temporarily unavailable",
                "state-lock",
            ),
            ("terraform", "Error releasing the state lock", "state-lock"),
            ("terraform", "request blocked by policy; lock_timeout=30", withheld),
            ("az", "state lock field rejected", withheld),
            (
                "az",
                "https://example.invalid/401?code=403&quota=unlimited&timeout=30",
                withheld,
            ),
            ("az", "https://example.invalid/401/path/403?status=401", withheld),
            (
                "az",
                "account 401234; resource 403999; block quota_limit timeout_seconds",
                withheld,
            ),
            ("az", "AuthorizationFailed: secret-token", "permission"),
            (
                "az",
                "AuthorizationPermissionMismatch: secret-token",
                "blob-data-permission",
            ),
            ("az", "quota exceeded: secret-token", "quota"),
            ("az", "request timeout: secret-token", "timeout"),
        ]
        for program, stderr, expected in cases:
            with self.subTest(program=program, stderr=stderr):
                with (
                    process_context(stderr, "secret-stdout"),
                    expect_error(lifecycle.Blocked, expected) as caught,
                ):
                    self.fixture.runtime.run([program, "apply"])
                receipt = json.loads(
                    (
                        self.fixture.context.paths.state / "operation-receipt.json"
                    ).read_text()
                )
                ensure_equal(receipt["commands"][-1]["diagnostic"], expected)
                ensure_equal(receipt["commands"][-1]["exit_code"], 1)
                persisted = str(caught.exception) + json.dumps(receipt)
                for secret in ("secret-token", "secret-stdout", "string:///", stderr):
                    ensure(secret not in persisted)


class ReviewedDefects(unittest.TestCase):
    """Keep precise capacity, cleanup and native HTTP deadline regressions."""

    def setUp(self) -> None:
        """Build one approved private fixture."""
        self.fixture = make_fixture(self)

    def test_rebuild_missing_write_destroys_nothing(self) -> None:
        """Refuse missing writes before destruction even without owned resources."""
        fixture = self.fixture
        fixture.context.settings = replace(
            fixture.context.settings, operation="rebuild"
        )
        stub(
            self,
            fixture.runtime,
            "az",
            return_value={
                "value": [
                    {
                        "actions": ["*"],
                        "notActions": ["Microsoft.Compute/virtualMachines/write"],
                    }
                ]
            },
        )
        stub(
            self,
            fixture.lifecycle,
            "preflight",
            side_effect=lambda deploying: (
                fixture.lifecycle.capacity_permissions() if deploying else None
            ),
        )
        destroy = stub(self, fixture.lifecycle, "destroy")
        deploy = stub(self, fixture.lifecycle, "deploy")
        with expect_error(lifecycle.Blocked, "Microsoft.Compute/virtualMachines/write"):
            fixture.lifecycle.execute()
        destroy.assert_not_called()
        deploy.assert_not_called()
        ensure(fixture.context.state.resources is None)

    def test_live_shape_string_quotas_pass_deploy(self) -> None:
        """Normalize actual Azure string quota counts."""
        capacity = capacity_fixture(self)
        context = capacity.fixture.context
        context.settings = replace(context.settings, operation="deploy")
        previous = capacity.az.side_effect

        def az(*args: str) -> Any:
            if args[:2] == ("vm", "list-usage"):
                return [
                    {
                        "name": {"value": name},
                        "currentValue": current,
                        "limit": limit,
                        "unit": "Count",
                    }
                    for name, current, limit in (
                        ("cores", "52", "362"),
                        ("standardDSv3Family", "0", "350"),
                        ("standardFSv2Family", "0", "350"),
                    )
                ]
            return previous(*args)

        capacity.az.side_effect = az
        capacity.fixture.lifecycle.capacity_permissions()
        capacity.inventory.assert_not_called()
        ensure(
            "azure-permissions-quota-skus"
            in [p["name"] for p in context.state.receipt["phases"]]
        )

    def test_quota_counts_normalize_exact_nonnegative_numbers(self) -> None:
        """Accept only exact finite nonnegative quota counts."""
        for value in (0, 32, 32.0, "0", "32", 2**53 - 1, str(2**53 - 1)):
            with self.subTest(value=value):
                ensure_equal(state_module.quota_count(value), int(value))

    def test_malformed_quota_counts_fail_blocked(self) -> None:
        """Reject malformed current and maximum quota evidence."""
        invalid: tuple[Any, ...] = (
            None,
            True,
            False,
            -1,
            "-1",
            1.5,
            "1.5",
            "",
            " 32",
            "+32",
            "\uff11\uff12",
            "1e3",
            float("nan"),
            float("inf"),
            -float("inf"),
            2**53,
            str(2**53),
            "9" * 5000,
            [],
            {},
        )
        for field in ("currentValue", "limit"):
            for value in invalid:
                with self.subTest(field=field, value=str(value)[:32]):
                    capacity = capacity_fixture(self)
                    capacity.az.side_effect = invalid_quota(
                        capacity.az.side_effect, field, value
                    )
                    with expect_error(lifecycle.Blocked, "malformed.*quota"):
                        capacity.fixture.lifecycle.capacity_permissions()

    def test_missing_duplicate_or_unknown_unit_quotas_fail_blocked(self) -> None:
        """Reject missing, duplicate or dimensionally ambiguous capacity."""
        for mode in ("missing", "duplicate", "unknown-unit", "missing-unit", "shape"):
            with self.subTest(mode=mode):
                capacity = capacity_fixture(self)
                capacity.az.side_effect = quota_shape(capacity.az.side_effect, mode)
                with expect_error(lifecycle.Blocked, "eastus2 VM quota"):
                    capacity.fixture.lifecycle.capacity_permissions()

    def test_no_role_or_storage_access_required(self) -> None:
        """Unrelated role assignment and storage permissions are unnecessary."""
        capacity = capacity_fixture(self)
        previous = capacity.az.side_effect

        def az(*args: str) -> Any:
            if args[:3] == ("rest", "--method", "get") and "/permissions?" in args[-1]:
                return {
                    "value": [
                        {
                            "actions": ["*"],
                            "notActions": [
                                "Microsoft.Authorization/roleAssignments/write",
                                "Microsoft.Storage/*",
                            ],
                        }
                    ]
                }
            return previous(*args)

        capacity.az.side_effect = az
        capacity.fixture.lifecycle.capacity_permissions()
        capacity.verify_phase.assert_not_called()
        capacity.outputs.assert_not_called()
        ensure(
            all(
                "storage" not in call.args and "Microsoft.Storage" not in str(call.args)
                for call in capacity.az.call_args_list
            )
        )

    def test_owned_unhealthy_rebuild_keeps_ownership_guards_and_can_repair(
        self,
    ) -> None:
        """Repair owned unhealthy guests without requiring working outputs."""
        capacity = capacity_fixture(self)
        obj = capacity.fixture.lifecycle
        stub(
            self,
            obj,
            "preflight",
            side_effect=lambda _deploying: obj.capacity_permissions(),
        )
        capacity.verify_phase.side_effect = lifecycle.Blocked("not ready")
        capacity.outputs.side_effect = lifecycle.Blocked("missing showcase")
        destroy = stub(self, obj, "destroy")
        deploy = stub(self, obj, "deploy")
        obj.execute()
        destroy.assert_called_once_with()
        deploy.assert_called_once_with()
        capacity.namespace.assert_called_once_with()
        capacity.inventory.assert_called_once_with()
        capacity.verify_fixture.assert_called_once_with()
        capacity.verify_phase.assert_not_called()
        capacity.outputs.assert_not_called()

    def test_unhealthy_rebuild_does_not_skip_ownership_failure(self) -> None:
        """Do not relax inventory ownership checks to repair readiness."""
        capacity = capacity_fixture(self)
        obj = capacity.fixture.lifecycle
        stub(
            self,
            obj,
            "preflight",
            side_effect=lambda _deploying: obj.capacity_permissions(),
        )
        capacity.inventory.side_effect = lifecycle.Blocked("unowned group child")
        capacity.verify_phase.side_effect = lifecycle.Blocked("not ready")
        destroy = stub(self, obj, "destroy")
        with expect_error(lifecycle.Blocked, "unowned group child"):
            obj.execute()
        destroy.assert_not_called()

    def test_rebuild_credits_only_exact_owned_allocated_cores(self) -> None:
        """Credit only verified owned allocated VMs."""
        capacity = capacity_fixture(self)
        capacity.fixture.lifecycle.capacity_permissions()
        capacity.namespace.assert_called_once_with()
        capacity.inventory.assert_called_once()
        capacity.verify_fixture.assert_called_once()

    def test_deploy_still_requires_32_free_cores(self) -> None:
        """New deployment gets no rebuild quota credit."""
        capacity = capacity_fixture(self)
        context = capacity.fixture.context
        context.settings = replace(context.settings, operation="deploy")
        with expect_error(lifecycle.Blocked, "VM quota"):
            capacity.fixture.lifecycle.capacity_permissions()
        capacity.inventory.assert_not_called()

    def test_owned_credit_rejects_live_identity_mismatch(self) -> None:
        """Refuse quota credit for an unrelated live VM."""
        capacity = capacity_fixture(self)
        previous = capacity.az.side_effect

        def az(*args: str) -> Any:
            value = previous(*args)
            if args[:2] == ("vm", "show"):
                value["id"] = "unowned"
            return value

        capacity.az.side_effect = az
        with expect_error(lifecycle.Blocked, "identity/SKU mismatch"):
            capacity.fixture.lifecycle.capacity_permissions()

    def test_deallocated_owned_vms_do_not_release_quota(self) -> None:
        """Already deallocated VMs cannot be credited again."""
        capacity = capacity_fixture(self, False)
        with expect_error(lifecycle.Blocked, "VM quota"):
            capacity.fixture.lifecycle.capacity_permissions()

    def test_rebuild_sku_failure_precedes_destroy(self) -> None:
        """Unavailable SKUs block rebuild before destruction."""
        capacity = capacity_fixture(self)
        previous = capacity.az.side_effect
        capacity.az.side_effect = lambda *args: (
            [] if args[:2] == ("vm", "list-skus") else previous(*args)
        )
        obj = capacity.fixture.lifecycle
        stub(
            self,
            obj,
            "preflight",
            side_effect=lambda _deploying: obj.capacity_permissions(),
        )
        destroy = stub(self, obj, "destroy")
        with expect_error(lifecycle.Blocked, "SKU unavailable"):
            obj.execute()
        destroy.assert_not_called()

    def test_slow_drip_response_obeys_total_deadline(self) -> None:
        """Resetting socket timeouts cannot extend the total deadline."""
        fixture = self.fixture
        fixture.context.env.update({"XCSH_API_TOKEN": "synthetic"})
        fixture.context.state.deadline = time.monotonic() + 0.015
        sock = Mock()
        response = Mock()
        response.fp = Mock(raw=Mock(_sock=sock))
        response.length = None
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)

        def drip(*_args: Any) -> bytes:
            time.sleep(0.02)
            return b" "

        response.read1.side_effect = drip
        with (
            patch.object(fixture.runtime.opener, "open", return_value=response),
            expect_error(lifecycle.Blocked, "deadline exceeded"),
        ):
            fixture.runtime.xc("/test")
        response.read.assert_not_called()
        sock.settimeout.assert_called_once()

    def test_real_http_slow_body_cannot_extend_deadline(self) -> None:
        """Retain native HTTP loopback proof bounded below half a second."""
        server = ThreadingHTTPServer(("127.0.0.1", 0), SlowBody)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            fixture = self.fixture
            fixture.context.env.update({"XCSH_API_TOKEN": "synthetic"})
            fixture.context.state.deadline = time.monotonic() + 0.08
            start = time.monotonic()
            with (
                patch.dict(
                    fixture.context.settings.scope,
                    xc_url="http://127.0.0.1:" + str(server.server_port),
                ),
                expect_error(lifecycle.Blocked),
            ):
                fixture.runtime.xc("/slow")
            ensure(time.monotonic() - start < 0.5)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_truncated_response_is_not_accepted(self) -> None:
        """Refuse incomplete bodies even when the available prefix is valid JSON."""
        fixture = self.fixture
        fixture.context.env.update({"XCSH_API_TOKEN": "synthetic"})
        response = Mock()
        response.fp = Mock(raw=Mock(_sock=Mock()))
        response.length = 10
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read1.side_effect = [b"{}", b""]
        with (
            patch.object(fixture.runtime.opener, "open", return_value=response),
            expect_error(lifecycle.Blocked, "truncated XC response"),
        ):
            fixture.runtime.xc("/test")


class SlowBody(BaseHTTPRequestHandler):
    """Native loopback server producing an intentionally slow response body."""

    def do_GET(self) -> None:  # pylint: disable=invalid-name
        """Implement the required stdlib HTTP request method spelling."""
        self.send_response(200)
        self.send_header("Content-Length", "100")
        self.end_headers()
        try:
            for _ in range(100):
                self.wfile.write(b" ")
                self.wfile.flush()
                time.sleep(0.02)
        except (BrokenPipeError, ConnectionResetError):
            pass


if __name__ == "__main__":
    unittest.main()
