"""Terraform wiring and private local-state regressions; no cloud acceptance claims."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import time
import unittest
from collections import Counter
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch
from urllib.parse import urlsplit

import hcl2
from demo_lifecycle_fixtures import (
    ROOT,
    Fixture,
    make_fixture,
    state_module,
    terraform_module,
)
from demo_test_support import ensure, ensure_equal, expect_error


def expression(module: dict[str, Any], key: str) -> Any:
    """Read the parser's scalar or singleton-list representation."""
    value = module[key]
    return value[0] if isinstance(value, list) else value


def render_guest(profile: dict[str, Any], defaults: dict[str, Any]) -> dict[str, Any]:
    """Render the exact root expression into the guest JSON scalar."""
    effective_mud = profile["mud_enabled"] and profile.get(
        "mud_bad_traffic", defaults["mud_bad_traffic"]
    )
    template = (ROOT / "terraform/cloud-init/traffic-generator.yaml").read_text()
    config_line = next(
        line.strip()
        for line in template.splitlines()
        if line.strip().startswith('{"target_domains":')
    )
    replacements = {
        "target_domains": json.dumps(profile["lb_domains"]),
        "target_origin_ip": "192.0.2.1",
        "tool_tier": "core",
        "mud_bad_traffic": json.dumps(effective_mud),
    }
    for key, value in replacements.items():
        config_line = config_line.replace("${" + key + "}", value)
    return json.loads(config_line)


class TerraformWiring(unittest.TestCase):
    def test_generator_identity_is_not_deferred_by_load_balancer(self):
        config = hcl2.loads((ROOT / "terraform/main.tf").read_text())
        modules = {
            name: values for block in config["module"] for name, values in block.items()
        }
        generator = modules["traffic_generator"]
        ensure("depends_on" not in generator)
        ensure_equal(expression(generator, "deployer"), "${var.deployer}")
        ensure_equal(expression(generator, "component"), "traffic-generator")
        ensure("module.origin_server.public_ip" in expression(generator, "custom_data"))
        ensure("jsonencode(var.lb_domains)" in expression(generator, "custom_data"))
        ensure_equal(
            expression(modules["http_lb"], "origin_ip"),
            "${module.origin_server.public_ip}",
        )

    def test_showcase_profile_renders_complete_mixed_targets(self):
        profile = json.loads((ROOT / "terraform/showcase.tfvars.json").read_text())
        config = hcl2.loads((ROOT / "terraform/main.tf").read_text())
        modules = {
            name: values for block in config["module"] for name, values in block.items()
        }
        rendered = modules["traffic_generator"]["custom_data"]
        ensure(
            'templatefile("${path.module}/cloud-init/traffic-generator.yaml"'
            in rendered
        )
        ensure('"target_domains": "${jsonencode(var.lb_domains)}"' in rendered)
        ensure(
            '"mud_bad_traffic": "${var.mud_enabled && var.mud_bad_traffic}"' in rendered
        )
        declaration = (
            'variable "mud_bad_traffic" {'
            + (ROOT / "terraform/variables.tf")
            .read_text()
            .split('variable "mud_bad_traffic" {', 1)[1]
            .split("}", 1)[0]
            + "}"
        )
        variables = hcl2.loads(declaration)
        defaults = {
            name: value.get("default")
            for block in variables["variable"]
            for name, value in block.items()
        }
        ensure(defaults["mud_bad_traffic"] is False)
        ensure(profile["mud_enabled"] is True)
        ensure(profile.get("mud_bad_traffic", defaults["mud_bad_traffic"]) is True)
        guest = render_guest(profile, defaults)
        spec = importlib.util.spec_from_file_location(
            "profile_demo_traffic", ROOT / "scripts/demo_traffic.py"
        )
        if spec is None or spec.loader is None:
            self.fail("traffic module loader unavailable")
        traffic = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {spec.name: traffic}):
            spec.loader.exec_module(traffic)
            generated = traffic.targets(
                guest["target_domains"],
                "profile-regression",
                0,
                guest["mud_bad_traffic"],
            )
            counts = Counter(
                (urlsplit(target["url"]).hostname, target["header"]["X-Demo-Class"][0])
                for target in generated
            )
            ensure_equal(len(generated), 1500)
            expected = {
                "benign": 675,
                "waf": 15,
                "schema": 10,
                "endpoint-denial": 10,
                "rate-limit": 25,
                "mud": 15,
            }
            for domain in profile["lb_domains"]:
                for traffic_class, count in expected.items():
                    ensure_equal(counts[(domain, traffic_class)], count)
                ensure_equal(
                    sum(counts[(domain, traffic_class)] for traffic_class in expected),
                    750,
                )
            ensure_equal(len(counts), 12)
            for enabled, bad in ((False, True), (True, False), (False, False)):
                with (
                    self.subTest(mud_enabled=enabled, mud_bad_traffic=bad),
                    expect_error(ValueError, "showcase requires mud_bad_traffic"),
                ):
                    traffic.targets(
                        guest["target_domains"],
                        "disabled-regression",
                        0,
                        enabled and bad,
                    )


class LocalBackend(unittest.TestCase):
    def setUp(self):
        self.fixture = make_fixture(self)

    def prepare_namespace(self):
        runtime = self.fixture.runtime
        terraform = self.fixture.terraform
        az_mock = self.enterContext(
            patch.object(
                runtime,
                "az",
                side_effect=AssertionError(
                    "namespace/local backend must not call Azure"
                ),
            )
        )
        xc_mock = self.enterContext(
            patch.object(
                runtime,
                "xc",
                return_value={
                    "metadata": {"name": state_module.FIXED["namespace"]},
                    "system_metadata": {"uid": "namespace-uid"},
                },
            )
        )
        tf_mock = self.enterContext(patch.object(terraform, "tf"))
        return az_mock, xc_mock, tf_mock

    def test_namespace_readonly_and_local_path(self):
        az_mock, _, tf_mock = self.prepare_namespace()
        self.fixture.terraform.namespace_prepare()
        ensure_equal(
            self.fixture.context.state.persistent,
            {"namespace": "system/" + state_module.FIXED["namespace"]},
        )
        ensure_equal(self.fixture.context.state.namespace_uid, "namespace-uid")
        ensure_equal(
            self.fixture.context.paths.backend,
            {"path": str(self.fixture.context.paths.state / "application.tfstate")},
        )
        az_mock.assert_not_called()
        tf_mock.assert_not_called()

    def test_missing_namespace_never_created(self):
        _, xc_mock, _ = self.prepare_namespace()
        xc_mock.return_value = None
        with expect_error(state_module.Blocked, "namespace missing"):
            self.fixture.terraform.namespace_prepare()
        xc_mock.assert_called_once_with(
            f"/api/web/namespaces/{state_module.FIXED['namespace']}",
            allow_absent=True,
        )

    def test_old_receipts_require_explicit_migration(self):
        _, xc_mock, _ = self.prepare_namespace()
        for filename, value in (
            (
                "persistent.json",
                {
                    "namespace": "system/" + state_module.FIXED["namespace"],
                    "storage_account": "old",
                },
            ),
            (
                "run-manifest.json",
                {
                    "persistent_resource_ids": self.fixture.context.state.persistent,
                    "azure_preserved": ["old"],
                },
            ),
        ):
            with self.subTest(filename=filename):
                path = self.fixture.context.paths.state / filename
                state_module.save_json(path, value)
                with expect_error(state_module.Blocked, "explicit external migration"):
                    self.fixture.terraform.namespace_prepare()
                path.unlink()
        xc_mock.assert_not_called()

    def test_namespace_uid_change_blocks(self):
        _, xc_mock, _ = self.prepare_namespace()
        self.fixture.terraform.namespace_prepare()
        xc_mock.return_value["system_metadata"]["uid"] = "different"
        with expect_error(state_module.Blocked, "UID changed"):
            self.fixture.terraform.namespace_prepare()
        self.fixture.context.state.namespace_uid = None
        with expect_error(state_module.Blocked, "UID changed"):
            self.fixture.terraform.namespace_prepare()

    def test_checkout_state_never_transferred(self):
        _, _, tf_mock = self.prepare_namespace()
        paths = self.fixture.context.paths
        (paths.app / "terraform.tfstate").write_text("existing state")
        with expect_error(state_module.Blocked, "explicit migration"):
            self.fixture.terraform.app_init()
        ensure_equal((paths.app / "terraform.tfstate").read_text(), "existing state")
        tf_mock.assert_not_called()

    def test_namespace_in_application_state_requires_migration(self):
        value = {
            "values": {
                "root_module": {
                    "resources": [
                        {
                            "mode": "managed",
                            "type": "xcsh_namespace",
                            "values": {"id": "system/webapp-api-protection"},
                        }
                    ]
                }
            }
        }
        with (
            patch.object(
                self.fixture.terraform, "tf", return_value=(json.dumps(value), 0)
            ),
            expect_error(state_module.Blocked, "explicit external migration"),
        ):
            self.fixture.ownership.inventory()

    def test_backend_config_always_rejected(self):
        # Rejected legacy path is evidence only, never accessed.
        for backend in (
            {},
            {"path": "/tmp/state"},  # noqa: S108
            {"access_key": "secret"},
            {"storage_account_name": "otheraccount123"},
        ):
            with (
                self.subTest(backend=backend),
                expect_error(state_module.Blocked, "--state-dir"),
            ):
                state_module.config_values({"backend": backend})

    def test_remote_and_alternate_initialized_backend_fail_before_init(self):
        _, _, tf_mock = self.prepare_namespace()
        paths = self.fixture.context.paths
        data = paths.state / "application-data"
        data.mkdir()
        # These rejected backend paths are never opened.
        for kind, config in (
            ("azurerm", {}),
            ("local", {"path": "/tmp/other.tfstate"}),  # noqa: S108
            (
                "local",
                {"path": paths.backend["path"], "workspace_dir": "/tmp/workspaces"},  # noqa: S108
            ),
        ):
            with self.subTest(kind=kind, config=config):
                state_module.save_json(
                    data / "terraform.tfstate",
                    {"backend": {"type": kind, "config": config}},
                )
                with expect_error(state_module.Blocked, "explicit migration"):
                    self.fixture.terraform.app_init()
        tf_mock.assert_not_called()

    def test_empty_uninitialized_generated_config_can_be_replaced(self):
        self.prepare_namespace()
        paths = self.fixture.context.paths
        state_module.save_json(
            paths.state / "backend.json", {"storage_account_name": "old"}
        )
        self.fixture.terraform.app_init()
        ensure_equal(
            json.loads((paths.state / "backend.json").read_text()), paths.backend
        )

    def test_old_generated_config_with_state_is_not_replaced(self):
        self.prepare_namespace()
        paths = self.fixture.context.paths
        state_module.save_json(
            paths.state / "backend.json", {"storage_account_name": "old"}
        )
        state_module.save_json(
            paths.state / "application.tfstate", {"version": 4, "resources": []}
        )
        with expect_error(state_module.Blocked, "explicit migration"):
            self.fixture.terraform.app_init()
        ensure_equal(
            json.loads((paths.state / "backend.json").read_text()),
            {"storage_account_name": "old"},
        )

    def test_existing_local_state_is_preserved_and_private(self):
        self.prepare_namespace()
        state = self.fixture.context.paths.state / "application.tfstate"
        value = {"version": 4, "resources": [], "serial": 17}
        state_module.save_json(state, value)
        state.chmod(0o644)
        self.fixture.terraform.app_init()
        ensure_equal(json.loads(state.read_text()), value)
        ensure_equal(state.stat().st_mode & 0o777, 0o600)

    def test_symlink_artifact_blocks_before_init(self):
        _, _, tf_mock = self.prepare_namespace()
        paths = self.fixture.context.paths
        (paths.state / "application.tfstate").symlink_to(paths.app / "other")
        with expect_error(state_module.Blocked, "symlinks"):
            self.fixture.terraform.app_init()
        tf_mock.assert_not_called()

    def test_unexpected_state_is_not_ignored(self):
        _, _, tf_mock = self.prepare_namespace()
        state_module.save_json(
            self.fixture.context.paths.state / "unknown.tfstate",
            {"backend": {"type": "azurerm"}},
        )
        with expect_error(state_module.Blocked, "unexpected persistent state"):
            self.fixture.terraform.app_init()
        tf_mock.assert_not_called()

    def test_nondefault_workspace_and_unknown_state_fail_closed(self):
        _, _, tf_mock = self.prepare_namespace()
        paths = self.fixture.context.paths
        data = paths.state / "application-data"
        data.mkdir()
        (data / "environment").write_text("production")
        with expect_error(state_module.Blocked, "workspace"):
            self.fixture.terraform.app_init()
        (data / "environment").write_text("default")
        state_module.save_json(paths.state / "application.tfstate", {})
        with expect_error(state_module.Blocked, "unknown application state"):
            self.fixture.terraform.app_init()
        tf_mock.assert_not_called()

    def test_foreign_artifact_owner_blocks(self):
        self.prepare_namespace()
        state_module.save_json(
            self.fixture.context.paths.state / "application.tfstate",
            {"version": 4, "resources": []},
        )
        with (
            patch.object(state_module.os, "getuid", return_value=-1),
            expect_error(state_module.Blocked, "ownership"),
        ):
            self.fixture.terraform.local_backend_check()


@dataclass
class FoundationData:
    """Namespace-only JSON proof and mocks owned by the canonical services."""

    state_value: dict[str, Any]
    show: dict[str, Any]
    plan: dict[str, Any]
    az_mock: Mock
    xc_mock: Mock
    tf_mock: Mock


def foundation(
    case: unittest.TestCase, fixture: Fixture, *, existing: bool = False, code: int = 0
) -> FoundationData:
    paths = fixture.context.paths
    az_mock = case.enterContext(
        patch.object(
            fixture.runtime,
            "az",
            side_effect=AssertionError("foundation must not use Azure"),
        )
    )
    xc_mock = case.enterContext(
        patch.object(
            fixture.runtime,
            "xc",
            return_value={
                "metadata": {"name": state_module.FIXED["namespace"]},
                "system_metadata": {"uid": "confirmed-live-uid"},
            },
        )
    )
    identity = {
        "name": state_module.FIXED["namespace"],
        "id": state_module.FIXED["namespace"],
    }
    state_module.save_json(
        paths.state / "namespace-receipt.json",
        {
            "path": "/api/web/namespaces/webapp-api-protection",
            "uid": "confirmed-live-uid",
        },
    )
    state_value = {
        "version": 4,
        "resources": [
            {
                "mode": "managed",
                "type": "xcsh_namespace",
                "name": "this",
                "instances": [{"attributes": identity}],
            }
        ],
    }
    show = {
        "values": {
            "root_module": {
                "resources": [
                    {
                        "mode": "managed",
                        "type": "xcsh_namespace",
                        "address": "xcsh_namespace.this",
                        "values": identity,
                    }
                ]
            }
        }
    }
    plan = {
        "resource_changes": [
            {
                "mode": "managed",
                "type": "xcsh_namespace",
                "address": "xcsh_namespace.this",
                "change": {
                    "actions": ["no-op"],
                    "before": identity.copy(),
                    "after": identity.copy(),
                },
            }
        ],
        "output_changes": {
            "namespace_name": {"actions": ["no-op"], "after": identity["name"]},
            "namespace_id": {"actions": ["no-op"], "after": identity["id"]},
        },
    }
    if existing:
        state_module.save_json(paths.state / "namespace.tfstate", state_value)

    def tf(directory: Path, *argv: str, **_kwargs: object) -> tuple[str, int]:
        ensure_equal(directory, paths.namespace_root)
        if argv[0] == "import":
            state_module.save_json(paths.state / "namespace.tfstate", state_value)
        if argv[0] == "show":
            return json.dumps(plan if len(argv) == 3 else show), 0
        if argv[0] == "plan":
            (paths.state / "namespace.plan").write_text("saved-plan")
            return "", code
        return "", 0

    tf_mock = case.enterContext(patch.object(fixture.terraform, "tf", side_effect=tf))
    return FoundationData(state_value, show, plan, az_mock, xc_mock, tf_mock)


def verbs(data: FoundationData) -> list[str]:
    return [call.args[1] for call in data.tf_mock.call_args_list]


class NamespaceTerraform(unittest.TestCase):
    def setUp(self):
        self.fixture = make_fixture(self)

    def test_fresh_import_uses_confirmed_identity_and_saved_plan(self):
        data = foundation(self, self.fixture, code=2)
        paths = self.fixture.context.paths
        self.fixture.terraform.namespace_tf_prepare(create=True)
        ensure_equal(verbs(data).count("import"), 1)
        data.tf_mock.assert_any_call(
            paths.namespace_root,
            "import",
            "-input=false",
            "xcsh_namespace.this",
            "webapp-api-protection",
        )
        data.tf_mock.assert_any_call(
            paths.namespace_root,
            "init",
            "-input=false",
            "-backend-config=" + str(paths.state / "namespace-backend.json"),
        )
        data.tf_mock.assert_any_call(
            paths.namespace_root,
            "apply",
            "-input=false",
            str(paths.state / "namespace.plan"),
        )
        ensure_equal(
            json.loads((paths.state / "namespace-receipt.json").read_text())["uid"],
            "confirmed-live-uid",
        )
        ensure_equal((paths.state / "namespace.plan").stat().st_mode & 0o777, 0o600)
        data.az_mock.assert_not_called()

    def test_existing_state_never_reimported(self):
        data = foundation(self, self.fixture, existing=True)
        self.fixture.terraform.namespace_tf_prepare(create=True)
        ensure("import" not in verbs(data))

    def test_preservation_is_readonly_and_missing_state_blocks(self):
        data = foundation(self, self.fixture, existing=True)
        self.fixture.terraform.namespace_tf_prepare()
        ensure("import" not in verbs(data))
        ensure("apply" not in verbs(data))
        (self.fixture.context.paths.state / "namespace.tfstate").unlink()
        data.tf_mock.reset_mock()
        with expect_error(state_module.Blocked, "state missing"):
            self.fixture.terraform.namespace_tf_prepare()
        data.tf_mock.assert_not_called()

    def test_import_without_prior_confirmed_uid_is_refused(self):
        data = foundation(self, self.fixture)
        (self.fixture.context.paths.state / "namespace-receipt.json").unlink()
        with expect_error(state_module.Blocked, "UID evidence missing"):
            self.fixture.terraform.namespace_tf_prepare(create=True)
        data.tf_mock.assert_not_called()

    def test_existing_state_without_uid_evidence_is_refused(self):
        data = foundation(self, self.fixture, existing=True)
        (self.fixture.context.paths.state / "namespace-receipt.json").unlink()
        with expect_error(state_module.Blocked, "UID evidence missing"):
            self.fixture.terraform.namespace_prepare()
        data.tf_mock.assert_not_called()

    def test_verify_cannot_enable_namespace_import_or_apply(self):
        data = foundation(self, self.fixture)
        self.fixture.context.settings = replace(
            self.fixture.context.settings, operation="verify"
        )
        with expect_error(state_module.Blocked, "only during deployment"):
            self.fixture.terraform.namespace_tf_prepare(create=True)
        data.tf_mock.assert_not_called()

    def test_uid_mismatch_blocks_before_import(self):
        data = foundation(self, self.fixture)
        state_module.save_json(
            self.fixture.context.paths.state / "namespace-receipt.json",
            {"path": "/api/web/namespaces/webapp-api-protection", "uid": "different"},
        )
        with expect_error(state_module.Blocked, "UID changed"):
            self.fixture.terraform.namespace_tf_prepare(create=True)
        data.tf_mock.assert_not_called()

    def test_uid_change_during_import_blocks_apply(self):
        data = foundation(self, self.fixture)
        good = data.xc_mock.return_value
        bad = {"metadata": good["metadata"], "system_metadata": {"uid": "changed"}}
        data.xc_mock.side_effect = [good, good, bad]
        with expect_error(state_module.Blocked, "UID changed"):
            self.fixture.terraform.namespace_tf_prepare(create=True)
        ensure("apply" not in verbs(data))

    def test_plan_mutations_unknown_and_replacements_block(self):
        for actions in (
            ["create"],
            ["update"],
            ["delete"],
            ["delete", "create"],
            ["create", "delete"],
        ):
            with self.subTest(actions=actions):
                data = foundation(self, self.fixture, existing=True)
                data.plan["resource_changes"][0]["change"]["actions"] = actions
                with expect_error(state_module.Blocked, "mutation refused"):
                    self.fixture.terraform.namespace_tf_prepare(create=True)
                ensure("apply" not in verbs(data))
        data = foundation(self, self.fixture, existing=True)
        data.plan["resource_changes"].append({"mode": "data", "type": "unknown"})
        with expect_error(state_module.Blocked, "mutation refused"):
            self.fixture.terraform.namespace_tf_prepare(create=True)

    def test_unknown_state_and_wrong_imported_id_block(self):
        data = foundation(self, self.fixture, existing=True)
        paths = self.fixture.context.paths
        data.state_value["resources"][0]["type"] = "xcsh_origin_pool"
        state_module.save_json(paths.state / "namespace.tfstate", data.state_value)
        with expect_error(state_module.Blocked, "unknown namespace state"):
            self.fixture.terraform.namespace_tf_prepare(create=True)
        data.tf_mock.assert_not_called()
        (paths.state / "namespace.tfstate").unlink()
        data = foundation(self, self.fixture)
        data.show["values"]["root_module"]["resources"][0]["values"]["id"] = (
            "system/other"
        )
        with expect_error(state_module.Blocked, "state identity mismatch"):
            self.fixture.terraform.namespace_tf_prepare(create=True)
        ensure("apply" not in verbs(data))

    def test_destroy_drift_blocks_before_application_actions(self):
        data = foundation(self, self.fixture, existing=True, code=2)
        self.fixture.context.settings = replace(
            self.fixture.context.settings, operation="destroy"
        )
        with (
            patch.object(self.fixture.terraform, "app_init") as app_init,
            expect_error(state_module.Blocked, "zero-change"),
        ):
            self.fixture.lifecycle.destroy()
        app_init.assert_not_called()
        ensure("apply" not in verbs(data))

    def test_unknown_plan_identity_and_outputs_block(self):
        for mutation in ("id", "unknown", "output"):
            with self.subTest(mutation=mutation):
                data = foundation(self, self.fixture, existing=True)
                if mutation == "id":
                    data.plan["resource_changes"][0]["change"]["after"]["id"] = (
                        "system/other"
                    )
                elif mutation == "unknown":
                    data.plan["resource_changes"][0]["change"]["after_unknown"] = {
                        "id": True
                    }
                else:
                    data.plan["output_changes"]["namespace_id"]["after"] = (
                        "fabricated-uid"
                    )
                with expect_error(state_module.Blocked):
                    self.fixture.terraform.namespace_tf_prepare(create=True)
                ensure("apply" not in verbs(data))

    def test_namespace_provider_id_is_bare_name_not_preservation_receipt(self):
        data = foundation(self, self.fixture, existing=True)
        self.fixture.terraform.namespace_tf_prepare()
        ensure_equal(
            self.fixture.context.state.persistent["namespace"],
            "system/webapp-api-protection",
        )
        data.state_value["resources"][0]["instances"][0]["attributes"]["id"] = (
            self.fixture.context.state.persistent["namespace"]
        )
        state_module.save_json(
            self.fixture.context.paths.state / "namespace.tfstate", data.state_value
        )
        data.tf_mock.reset_mock()
        with expect_error(state_module.Blocked, "unknown namespace state identity"):
            self.fixture.terraform.namespace_tf_prepare()
        data.tf_mock.assert_not_called()

    def test_runtime_roots_are_isolated_and_auth_is_preserved(self):
        # Synthetic credential proves preservation without a network call.
        self.fixture.context.env["XCSH_API_TOKEN"] = "test-only-token"  # noqa: S105
        paths = self.fixture.context.paths
        with patch.object(
            self.fixture.runtime, "run", return_value=("", 0)
        ) as run_mock:
            for root, label in (
                (paths.app, "application"),
                (paths.namespace_root, "namespace"),
            ):
                with patch.object(
                    terraform_module.os, "umask", wraps=terraform_module.os.umask
                ) as umask:
                    self.fixture.terraform.tf(root, "init")
                    umask.assert_called_once_with(0o077)
                env = run_mock.call_args.kwargs["env"]
                ensure_equal(env["TF_DATA_DIR"], str(paths.state / (label + "-data")))
                ensure_equal(env["TF_WORKSPACE"], "default")
                ensure_equal(env["XCSH_API_TOKEN"], "test-only-token")
            with expect_error(state_module.Blocked, "unknown Terraform root"):
                self.fixture.terraform.tf(paths.app / "other", "init")

    def test_namespace_destroy_commands_are_always_refused(self):
        with patch.object(self.fixture.runtime, "run") as run_mock:
            for args in (("destroy",), ("plan", "-destroy"), ("apply", "-destroy")):
                with (
                    self.subTest(args=args),
                    expect_error(state_module.Blocked, "destroy prohibited"),
                ):
                    self.fixture.terraform.tf(
                        self.fixture.context.paths.namespace_root, *args
                    )
            run_mock.assert_not_called()

    def test_namespace_backend_cannot_point_at_application_state(self):
        paths = self.fixture.context.paths
        data = paths.state / "namespace-data"
        data.mkdir()
        state_module.save_json(
            data / "terraform.tfstate",
            {"backend": {"type": "local", "config": paths.backend}},
        )
        with (
            patch.object(self.fixture.runtime, "run") as run_mock,
            expect_error(state_module.Blocked, "different backend"),
        ):
            self.fixture.terraform.tf(paths.namespace_root, "init")
        run_mock.assert_not_called()

    def test_namespace_state_backup_and_metadata_are_private(self):
        proof = foundation(self, self.fixture, existing=True)
        paths = self.fixture.context.paths
        backup = paths.state / "namespace.tfstate.backup"
        state_module.save_json(backup, proof.state_value)
        backup.chmod(0o644)
        data = paths.state / "namespace-data"
        data.mkdir()
        metadata = data / "terraform.tfstate"
        state_module.save_json(
            metadata, {"backend": {"type": "local", "config": paths.namespace_backend}}
        )
        metadata.chmod(0o644)
        data.chmod(0o755)
        self.fixture.terraform.local_backend_check()
        ensure_equal(backup.stat().st_mode & 0o777, 0o600)
        ensure_equal(metadata.stat().st_mode & 0o777, 0o600)
        ensure_equal(data.stat().st_mode & 0o777, 0o700)

    def test_actual_namespace_root_matches_lifecycle_contract(self):
        root = ROOT / "terraform"
        source = (root / "namespace/main.tf").read_text()
        outputs = (root / "namespace/outputs.tf").read_text()
        for required in (
            'backend "local" {}',
            'provider "xcsh" {}',
            "f5-sales-demo/xcsh",
            '"= 13.0.3"',
            'resource "xcsh_namespace" "this"',
            "prevent_destroy = true",
        ):
            ensure(required in source)
        ensure('var.namespace == "webapp-api-protection"' in source)
        ensure("value       = xcsh_namespace.this.id" in outputs)
        ensure("namespace_uid" not in outputs)
        ensure(
            not any(
                'resource "xcsh_namespace"' in path.read_text()
                for path in root.glob("*.tf")
            )
        )

    def test_unrelated_file_permissions_are_not_clobbered(self):
        unrelated = self.fixture.context.paths.state / "operator-notes.txt"
        unrelated.write_text("owned but unrelated")
        unrelated.chmod(0o644)
        self.fixture.terraform.local_backend_check()
        ensure_equal(unrelated.stat().st_mode & 0o777, 0o644)


class LocalTerraformRuntime(unittest.TestCase):
    def setUp(self):
        self.fixture = make_fixture(self)

    @unittest.skipUnless(shutil.which("terraform"), "Terraform unavailable")
    def test_external_state_permissions_backup_and_native_file_lock(self):
        self.fixture.context.state.deadline = time.monotonic() + 60
        paths = self.fixture.context.paths
        terraform = self.fixture.terraform
        inherited_umask, _ = self.fixture.runtime.run(
            [sys.executable, "-c", "import os; print(os.umask(0o077))"]
        )
        ensure_equal(int(inherited_umask), 0o077)
        hcl = paths.app / "main.tf"
        hcl.write_text(
            'terraform {\n  backend "local" {}\n}\nresource "terraform_data" "proof" {\n  input = "first"\n}\n'
        )
        terraform.tf(paths.app, "fmt")
        terraform.app_init()
        metadata = json.loads(
            (paths.state / "application-data/terraform.tfstate").read_text()
        )
        ensure_equal(metadata["backend"]["type"], "local")
        ensure_equal(metadata["backend"]["config"]["path"], paths.backend["path"])
        terraform.tf(paths.app, "apply", "-input=false", "-auto-approve")
        state = paths.state / "application.tfstate"
        ensure(state.is_file())
        ensure(not list(paths.app.rglob("*.tfstate")))
        ensure_equal(state.stat().st_mode & 0o777, 0o600)
        ensure_equal(paths.state.stat().st_mode & 0o777, 0o700)
        # Native POSIX record locking is distinct from the outer lifecycle flock.
        # Fixed Python program operates only on fixture-owned local state.
        with subprocess.Popen(  # noqa: S603
            [
                sys.executable,
                "-c",
                'import fcntl,sys; f=open(sys.argv[1], "r+"); fcntl.lockf(f, fcntl.LOCK_EX); print("locked", flush=True); sys.stdin.read(1)',
                str(state),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ) as holder:
            try:
                if holder.stdout is None:
                    self.fail("native lock holder stdout unavailable")
                ensure_equal(holder.stdout.readline().strip(), "locked")
                with expect_error(state_module.Blocked, "state-lock"):
                    terraform.tf(paths.app, "plan", "-input=false", "-lock-timeout=0s")
            finally:
                holder.communicate(input="x", timeout=5)
        terraform.tf(paths.app, "plan", "-input=false")
        hcl.write_text(hcl.read_text().replace('"first"', '"second"'))
        terraform.tf(paths.app, "apply", "-input=false", "-auto-approve")
        backup = paths.state / "application.tfstate.backup"
        ensure_equal(backup.stat().st_mode & 0o777, 0o600)
        serial = json.loads(state.read_text())["serial"]
        terraform.app_init()
        ensure_equal(json.loads(state.read_text())["serial"], serial)
        terraform.tf(paths.app, "apply", "-destroy", "-input=false", "-auto-approve")
        ensure_equal(json.loads(state.read_text())["resources"], [])
        ensure(backup.is_file())
        ensure(not list(paths.app.rglob("*.tfstate")))

    def test_uninitialized_runtime_cannot_default_to_checkout_state(self):
        with (
            patch.object(self.fixture.runtime, "run") as run_mock,
            expect_error(state_module.Blocked, "not initialized"),
        ):
            self.fixture.terraform.tf(
                self.fixture.context.paths.app, "apply", "-auto-approve"
            )
        run_mock.assert_not_called()

    def test_state_lock_and_migration_overrides_rejected(self):
        with patch.object(self.fixture.runtime, "run") as run_mock:
            for option in (
                "-lock=false",
                "-state=/tmp/state",
                "-migrate-state",
                "-reconfigure",
                "-force-copy",
                "-backend=false",
            ):
                with (
                    self.subTest(option=option),
                    expect_error(state_module.Blocked, "override"),
                ):
                    self.fixture.terraform.tf(
                        self.fixture.context.paths.app, "init", option
                    )
            run_mock.assert_not_called()
