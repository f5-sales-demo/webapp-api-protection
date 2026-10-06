"""Synthetic authorization and state guard regressions for canonical services."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

from demo_lifecycle_fixtures import (
    ROOT,
    TEST_APPROVAL,
    TEST_SCOPE,
    Files,
    Fixture,
    bind_fixture,
    lifecycle,
    runtime_module,
    state_module,
    temporary_files,
)
from demo_test_support import ensure, ensure_equal, expect_error


def config_file(
    files: Files, name: str = "operator.json", value: dict[str, Any] | None = None
) -> Path:
    """Save a synthetic private operator document outside the checkout."""
    ensure(files.args.state_dir is not None)
    if files.args.state_dir is None:
        message = "state directory required"
        raise AssertionError(message)
    files.args.state_dir.mkdir(mode=0o700, exist_ok=True)
    files.operator_base.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = files.operator_base / name
    state_module.save_json(
        path,
        dict(
            TEST_APPROVAL,
            **(
                value
                if value is not None
                else {"expected_azure_user": "operator@example.com"}
            ),
        ),
    )
    return path


@dataclass
class Preflight:
    """Actual service bindings and the mocks installed on their owners."""

    fixture: Fixture
    az: Mock
    namespace_prepare: Mock
    capacity_permissions: Mock


def preflight_fixture(
    case: unittest.TestCase, files: Files, *, authorized: bool = True
) -> Preflight:
    """Prepare prerequisites without cloud, network or private operator reads."""
    if authorized:
        config_file(files)
    fixture = bind_fixture(files)
    for relative in (
        "scripts/demo-verify.sh",
        "scripts/swagger-upload.sh",
        "terraform/showcase.tfvars.json",
        "terraform/fixtures/showcase-openapi.json",
    ):
        path = files.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
    key = files.base / "key"
    fixture.context.paths = replace(fixture.context.paths, key=key)
    key.write_text("synthetic")
    key.chmod(0o600)
    key.with_name("key.pub").write_text("ssh-ed25519 synthetic")
    fixture.context.env.update(
        {"XCSH_API_URL": state_module.FIXED["xc_url"], "XCSH_API_TOKEN": "synthetic"}
    )
    mocks = []
    for owner, name, options in (
        (fixture.terraform, "local_backend_check", {}),
        (
            fixture.runtime,
            "run",
            {
                "side_effect": [
                    ("ssh-ed25519 synthetic", 0),
                    ("ns.example.test hostmaster.example.test 1 2 3 4 5", 0),
                ]
            },
        ),
        (
            fixture.runtime,
            "az",
            {
                "return_value": {
                    "id": TEST_SCOPE["subscription_id"],
                    "tenantId": TEST_SCOPE["tenant_id"],
                    "state": "Enabled",
                    "user": {"type": "user", "name": "OPERATOR@EXAMPLE.COM"},
                }
            },
        ),
        (fixture.terraform, "namespace_prepare", {}),
        (
            fixture.runtime,
            "xc",
            {
                "return_value": {
                    "state": "AS_SUBSCRIBED",
                    "metadata": {"name": "f5-sales-demo.com"},
                    "spec": {"primary": {"allow_http_lb_managed_records": True}},
                }
            },
        ),
        (fixture.lifecycle, "capacity_permissions", {}),
    ):
        mock_patch = patch.object(owner, name, **options)
        mocks.append(mock_patch.start())
        case.addCleanup(mock_patch.stop)
    return Preflight(fixture, mocks[2], mocks[3], mocks[5])


class OperatorConfiguration(unittest.TestCase):
    """Private approval selection, validation and filesystem isolation."""

    def setUp(self) -> None:
        self.files = temporary_files(self)

    def test_default_private_operator_file(self):
        path = config_file(self.files)
        obj = bind_fixture(self.files).context
        ensure_equal(
            obj.settings.config["expected_azure_user"], "operator@example.com"
        )
        ensure_equal(path.stat().st_mode & 0o777, 0o600)
        ensure_equal(obj.paths.state.stat().st_mode & 0o777, 0o700)
        ensure("expected_azure_user" not in obj.state.receipt["scope"])

    def test_explicit_config_replaces_default_without_merge(self):
        config_file(
            self.files,
            value={"expected_azure_user": "other@example.com", "ssh_key": "/unused"},
        )
        self.files.args.config = config_file(self.files, "explicit.json")
        obj = bind_fixture(self.files).context
        ensure_equal(
            obj.settings.config["expected_azure_user"], "operator@example.com"
        )
        ensure(str(obj.paths.key) != "/unused")

    def test_config_overrides_environment(self):
        config_file(self.files)
        with patch.dict(os.environ, {"DEMO_AZURE_USER": "env@example.com"}):
            ensure_equal(
                bind_fixture(self.files).context.settings.config["expected_azure_user"],
                "operator@example.com",
            )

    def test_environment_only_when_chosen_config_omits_user(self):
        config_file(self.files, value={"expected_azure_user": "other@example.com"})
        self.files.args.config = config_file(self.files, "explicit.json", {})
        with patch.dict(os.environ, {"DEMO_AZURE_USER": "env@example.com"}):
            ensure_equal(
                bind_fixture(self.files).context.settings.config["expected_azure_user"],
                "env@example.com",
            )
        ensure(
            "expected_azure_user"
            not in bind_fixture(self.files).context.settings.config
        )

    def test_environment_without_operator_file(self):
        with patch.dict(os.environ, {"DEMO_AZURE_USER": "env@example.com"}):
            ensure_equal(
                bind_fixture(self.files).context.settings.config["expected_azure_user"],
                "env@example.com",
            )

    def test_approved_ids_override_environment_without_global_mutation(self):
        path = config_file(self.files)
        before = dict(state_module.FIXED)
        with patch.dict(
            os.environ,
            {
                "DEMO_AZURE_SUBSCRIPTION_ID": TEST_APPROVAL["tenant_id"],
                "DEMO_AZURE_TENANT_ID": TEST_APPROVAL["subscription_id"],
            },
        ):
            first = bind_fixture(self.files).context
        self.files.args.config = config_file(
            self.files,
            "other.json",
            {
                "subscription_id": TEST_APPROVAL["tenant_id"],
                "tenant_id": TEST_APPROVAL["subscription_id"],
            },
        )
        second = bind_fixture(self.files).context
        ensure_equal(first.settings.scope, TEST_SCOPE)
        ensure_equal(
            second.settings.scope["subscription_id"], TEST_APPROVAL["tenant_id"]
        )
        ensure_equal(state_module.FIXED, before)
        ensure("subscription_id" not in state_module.FIXED)
        ensure_equal(first.env["ARM_SUBSCRIPTION_ID"], TEST_APPROVAL["subscription_id"])
        ensure_equal(first.env["ARM_TENANT_ID"], TEST_APPROVAL["tenant_id"])
        ensure_equal(first.state.receipt["scope"], TEST_SCOPE)
        ensure("expected_azure_user" not in first.state.receipt["scope"])
        ensure_equal(path.parent, self.files.operator_base)

    def test_chosen_config_missing_ids_uses_explicit_environment_only(self):
        config_file(self.files)
        explicit = config_file(self.files, "empty.json")
        state_module.save_json(explicit, {})
        self.files.args.config = explicit
        with patch.dict(
            os.environ,
            {
                "DEMO_AZURE_SUBSCRIPTION_ID": TEST_APPROVAL["tenant_id"],
                "DEMO_AZURE_TENANT_ID": TEST_APPROVAL["subscription_id"],
            },
        ):
            obj = bind_fixture(self.files).context
        ensure_equal(obj.settings.scope["subscription_id"], TEST_APPROVAL["tenant_id"])
        ensure("expected_azure_user" not in obj.settings.config)

    def test_missing_ids_block_before_state_creation_or_identity_probe(self):
        for missing in ("DEMO_AZURE_SUBSCRIPTION_ID", "DEMO_AZURE_TENANT_ID"):
            environment = dict(os.environ)
            environment.pop(missing)
            with (
                self.subTest(missing=missing),
                patch.dict(os.environ, environment, clear=True),
            ):
                with patch.object(runtime_module.Runtime, "az") as az:
                    with expect_error(
                        state_module.Blocked, "approved Azure .* missing"
                    ):
                        bind_fixture(self.files)
                    az.assert_not_called()
                ensure(self.files.args.state_dir is not None)
                ensure(
                    self.files.args.state_dir is not None
                    and not self.files.args.state_dir.exists()
                )

    def test_malformed_ids_rejected_without_echoing_input(self):
        for key in TEST_APPROVAL:
            invalid_values: tuple[object, ...] = (
                None,
                True,
                {},
                [],
                "",
                "private-malformed-value",
                TEST_APPROVAL[key] + "\n",
                "{" + TEST_APPROVAL[key] + "}",
            )
            for invalid in invalid_values:
                with self.subTest(key=key, invalid=invalid):
                    with expect_error(state_module.Blocked, "canonical UUID") as error:
                        state_module.config_values(
                            dict(TEST_APPROVAL, **{key: invalid})
                        )
                    ensure(error.exception is not None)
                    ensure("private-malformed-value" not in str(error.exception))

    def test_existing_receipts_reject_changed_approved_scope(self):
        obj = bind_fixture(self.files).context
        for filename, value in (
            (
                "operation-receipt.json",
                {
                    "scope": {
                        "subscription_id": TEST_APPROVAL["tenant_id"],
                        "tenant_id": TEST_APPROVAL["tenant_id"],
                    }
                },
            ),
            ("run-manifest.json", {"subscription_id": TEST_APPROVAL["tenant_id"]}),
        ):
            with self.subTest(filename=filename):
                path = obj.paths.state / filename
                state_module.save_json(path, value)
                with expect_error(state_module.Blocked, "explicit external migration"):
                    bind_fixture(self.files)
                path.unlink()

    def test_default_approval_does_not_follow_state_dir(self):
        ensure(self.files.args.state_dir is not None)
        if self.files.args.state_dir is None:
            message = "state directory required"
            raise AssertionError(message)
        self.files.args.state_dir.mkdir(mode=0o700)
        state_module.save_json(
            self.files.args.state_dir / "operator.json",
            dict(TEST_APPROVAL, expected_azure_user="foreign@example.com"),
        )
        obj = bind_fixture(self.files).context
        ensure("expected_azure_user" not in obj.settings.config)

    def test_cli_help_requires_no_approval(self):
        script = ROOT / "scripts/demo_lifecycle.py"
        environment = {
            k: v for k, v in os.environ.items() if not k.startswith("DEMO_AZURE_")
        }
        # Only the trusted interpreter and this checkout's fixed CLI receive --help.
        result = subprocess.run(  # noqa: S603
            [sys.executable, str(script), "--help"],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        ensure_equal(result.returncode, 0)
        ensure("operator.json; approved Azure IDs required" in result.stdout)

    def test_invalid_authorized_upns_do_not_leak_values(self):
        invalid_values: tuple[object, ...] = (
            None,
            True,
            {},
            [],
            "",
            "no-at-sign",
            "@example.com",
            "operator@",
            "operator@@example.com",
            "operator@example.com\n",
            "operator @example.com",
            "operator\x00@example.com",
            "öperator@example.com",
            "a" * 309 + "@example.com",
        )
        for value in invalid_values:
            with (
                self.subTest(value=value),
                expect_error(state_module.Blocked, "bounded printable UPN"),
            ):
                state_module.config_values({"expected_azure_user": value})
        with (
            patch.dict(os.environ, {"DEMO_AZURE_USER": ""}),
            expect_error(state_module.Blocked, "bounded printable UPN"),
        ):
            bind_fixture(self.files)
        guest = "operator_example.test#EXT#@tenant.example.test"
        ensure_equal(
            state_module.config_values({"expected_azure_user": guest})[
                "expected_azure_user"
            ],
            guest,
        )

    def test_unsafe_file_permissions_and_symlinks_rejected(self):
        path = config_file(self.files)
        path.chmod(0o644)
        with expect_error(state_module.Blocked, "mode 0600"):
            bind_fixture(self.files)
        ensure_equal(path.stat().st_mode & 0o777, 0o644)
        path.chmod(0o600)
        ensure(self.files.args.state_dir is not None)
        if self.files.args.state_dir is None:
            message = "state directory required"
            raise AssertionError(message)
        link = self.files.args.state_dir / "link.json"
        link.symlink_to(path)
        self.files.args.config = link
        with expect_error(state_module.Blocked, "symlinks"):
            bind_fixture(self.files)

    def test_broken_default_symlink_rejected(self):
        self.files.operator_base.mkdir(parents=True)
        (self.files.operator_base / "operator.json").symlink_to(
            self.files.base / "absent"
        )
        with expect_error(state_module.Blocked, "symlinks"):
            bind_fixture(self.files)

    def test_config_checkout_scope_missing_and_malformed_rejected(self):
        self.files.args.config = self.files.root / "operator.json"
        state_module.save_json(self.files.args.config, {})
        with expect_error(state_module.Blocked, "outside the checkout"):
            bind_fixture(self.files)
        self.files.args.config = self.files.base / "absent.json"
        with expect_error(state_module.Blocked, "existing private"):
            bind_fixture(self.files)
        self.files.args.config = config_file(self.files)
        self.files.args.config.write_text("{malformed")
        with expect_error(state_module.Blocked, "JSON artifact unreadable"):
            bind_fixture(self.files)

    def test_foreign_owner_parent_symlink_and_directory_rejected(self):
        path = config_file(self.files)
        with (
            patch.object(os, "getuid", return_value=path.stat().st_uid + 1),
            expect_error(state_module.Blocked, "ownership/type"),
        ):
            state_module.operator_config(path, self.files.root)
        link = self.files.base / "linked-state"
        link.symlink_to(self.files.args.state_dir, target_is_directory=True)
        with expect_error(state_module.Blocked, "symlinks"):
            state_module.operator_config(link / "operator.json", self.files.root)
        ensure(self.files.args.state_dir is not None)
        if self.files.args.state_dir is None:
            message = "state directory required"
            raise AssertionError(message)
        with expect_error(state_module.Blocked, "existing private"):
            state_module.operator_config(self.files.args.state_dir, self.files.root)

    def test_default_home_profile_without_state_argument(self):
        self.files.args.state_dir = None
        home = self.files.base / "home"
        state = home / ".local/state/waap-showcase" / TEST_SCOPE["subscription_id"]
        state.mkdir(parents=True, mode=0o700)
        state_module.save_json(
            state.parent / "operator.json",
            dict(TEST_APPROVAL, expected_azure_user="operator@example.com"),
        )
        with patch.object(Path, "home", return_value=home):
            obj = bind_fixture(self.files).context
        ensure_equal(obj.paths.state, state)
        ensure_equal(
            obj.settings.config["expected_azure_user"], "operator@example.com"
        )

    def test_operator_config_preserves_fixed_scope_restrictions(self):
        for key in state_module.FIXED:
            with self.subTest(key=key):
                config_file(
                    self.files,
                    value={
                        key: "other",
                        "expected_azure_user": "operator@example.com",
                    },
                )
                with expect_error(
                    state_module.Blocked, "fixed identity/scope override"
                ):
                    bind_fixture(self.files)


class OperatorPreflight(unittest.TestCase):
    """Only explicit approved human identity can reach subsequent gates."""

    def setUp(self) -> None:
        self.files = temporary_files(self)

    def test_missing_authorization_never_infers_current_user(self):
        obj = preflight_fixture(self, self.files, authorized=False)
        with (
            patch.object(lifecycle.shutil, "which", return_value="/synthetic/tool"),
            expect_error(state_module.Blocked, "authorized Azure user missing"),
        ):
            obj.fixture.lifecycle.preflight(True)
        obj.az.assert_not_called()
        obj.namespace_prepare.assert_not_called()
        obj.capacity_permissions.assert_not_called()

    def test_casefold_exact_approved_human_passes(self):
        obj = preflight_fixture(self, self.files)
        with patch.object(lifecycle.shutil, "which", return_value="/synthetic/tool"):
            obj.fixture.lifecycle.preflight(True)
        obj.capacity_permissions.assert_called_once()
        ensure(
            "operator@example.com"
            not in json.dumps(obj.fixture.context.state.receipt).lower()
        )

    def test_wrong_human_type_subscription_tenant_or_state_blocks(self):
        for field, value in (
            ("name", "another@example.com"),
            ("name", None),
            ("type", "servicePrincipal"),
            ("id", "other"),
            ("tenantId", "other"),
            ("state", "Disabled"),
        ):
            with self.subTest(field=field, value=value):
                obj = preflight_fixture(self, self.files)
                account = obj.az.return_value
                (account["user"] if field in ("name", "type") else account)[field] = (
                    value
                )
                with (
                    patch.object(
                        lifecycle.shutil, "which", return_value="/synthetic/tool"
                    ),
                    expect_error(state_module.Blocked) as caught,
                ):
                    obj.fixture.lifecycle.preflight(True)
                ensure(caught.exception is not None)
                ensure("@" not in str(caught.exception))
                obj.namespace_prepare.assert_not_called()
                obj.capacity_permissions.assert_not_called()


class Guards(unittest.TestCase):
    """State and plan guards retain their original negative cases."""

    def test_identity_override_rejected(self):
        with expect_error(state_module.Blocked):
            state_module.config_values({"subscription_id": "example"})

    def test_unknown_config_rejected(self):
        with expect_error(state_module.Blocked):
            state_module.config_values({"command": "$(touch /tmp/unsafe)"})

    def test_fixed_config_accepted(self):
        files = temporary_files(self)
        ensure(files.root.exists())
        ensure_equal(
            state_module.config_values(TEST_APPROVAL)["namespace"],
            "webapp-api-protection",
        )

    def test_noop_guard_rejects_change(self):
        with expect_error(state_module.Blocked):
            state_module.guard_plan(
                {
                    "resource_changes": [
                        {
                            "mode": "managed",
                            "type": "azurerm_linux_virtual_machine",
                            "change": {"actions": ["update"]},
                        }
                    ]
                },
                "noop",
            )

    def test_destroy_rejects_namespace(self):
        with expect_error(state_module.Blocked):
            state_module.guard_plan(
                {
                    "resource_changes": [
                        {
                            "mode": "managed",
                            "type": "xcsh_namespace",
                            "change": {"actions": ["delete"]},
                        }
                    ]
                },
                "destroy",
            )

    def test_deploy_rejects_even_unchanged_namespace_ownership(self):
        with expect_error(state_module.Blocked, "explicit external migration"):
            state_module.guard_plan(
                {
                    "resource_changes": [
                        {
                            "mode": "managed",
                            "type": "xcsh_namespace",
                            "change": {"actions": ["no-op"]},
                        }
                    ]
                },
                "deploy",
            )

    def test_destroy_rejects_create(self):
        with expect_error(state_module.Blocked):
            state_module.guard_plan(
                {
                    "resource_changes": [
                        {
                            "mode": "managed",
                            "type": "azurerm_linux_virtual_machine",
                            "change": {"actions": ["create"]},
                        }
                    ]
                },
                "destroy",
            )

    def test_noop_output_drift_rejected(self):
        with expect_error(state_module.Blocked):
            state_module.guard_plan(
                {"output_changes": {"showcase": {"actions": ["update"]}}}, "noop"
            )

    def test_state_dir_inside_checkout_rejected(self):
        with expect_error(state_module.Blocked):
            state_module.secure_directory(ROOT / "unsafe-state", ROOT)

    def test_private_file_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            state_module.save_json(path, {"phase": "test"})
            ensure_equal(path.stat().st_mode & 0o777, 0o600)

    def test_unknown_destroy_type_rejected(self):
        with expect_error(state_module.Blocked):
            state_module.guard_plan(
                {
                    "resource_changes": [
                        {
                            "mode": "managed",
                            "type": "xcsh_dns_zone",
                            "change": {"actions": ["delete"]},
                        }
                    ]
                },
                "destroy",
            )
