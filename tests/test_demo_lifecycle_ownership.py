"""Ownership, recovery and SSH regression cases bound to canonical services."""

from __future__ import annotations

import json
import subprocess
import time
import unittest
from dataclasses import dataclass, replace
from typing import Any
from unittest.mock import Mock, patch

from demo_lifecycle_fixtures import (
    ROOT,
    TEST_SCOPE,
    Fixture,
    guest_state,
    live_vm,
    make_fixture,
    state_module,
)
from demo_test_support import ensure, ensure_equal, expect_error


@dataclass
class ChildVersions:
    """Advertised ancestor and exact child readback used by version probes."""

    fixture: Fixture
    base: str
    versions: list[str]
    az: Mock

    def read(self, *args: str) -> dict[str, Any]:
        if args[0] == "provider":
            return {
                "resourceTypes": [
                    {"resourceType": "virtualNetworks", "apiVersions": self.versions}
                ]
            }
        rid = args[-1].split("?")[0].removeprefix("https://management.azure.com")
        return {"id": rid, "properties": {"provisioningState": "Succeeded"}}


def child_version_fixture(
    case: unittest.TestCase, versions: list[str] | None = None
) -> ChildVersions:
    fixture = make_fixture(case)
    base = (
        "/subscriptions/"
        + TEST_SCOPE["subscription_id"]
        + "/resourceGroups/originlab/providers/Microsoft.Network/virtualNetworks/owned/subnets/"
    )
    result = ChildVersions(
        fixture,
        base,
        versions or ["2026-05-01", "2025-01-01", "2024-01-01", "2023-01-01"],
        Mock(),
    )
    result.az.side_effect = result.read
    replacement = patch.object(fixture.runtime, "az", result.az)
    replacement.start()
    case.addCleanup(replacement.stop)
    return result


@dataclass
class Recovery:
    """Real foundation files plus isolated live read mocks."""

    fixture: Fixture
    prior: dict[str, Any]
    xc: Mock
    verify: Mock


def recovery_setup(case: unittest.TestCase) -> Recovery:
    fixture = make_fixture(case)
    state, paths = fixture.context.state, fixture.context.paths
    namespace = state_module.FIXED["namespace"]
    identity = {"path": "/api/web/namespaces/" + namespace, "uid": "uid-" + namespace}
    state_module.save_json(
        paths.state / "persistent.json", {"namespace": "system/" + namespace}
    )
    state_module.save_json(paths.state / "namespace-receipt.json", identity)
    state_module.save_json(
        paths.state / "namespace.tfstate",
        {
            "version": 4,
            "resources": [
                {
                    "mode": "managed",
                    "type": "xcsh_namespace",
                    "name": "this",
                    "instances": [{"attributes": {"name": namespace, "id": namespace}}],
                }
            ],
        },
    )
    state.persistent = {"namespace": "system/" + namespace}
    state.namespace_uid = identity["uid"]
    rid = (
        "/subscriptions/"
        + TEST_SCOPE["subscription_id"]
        + "/resourceGroups/application"
    )
    resources = [
        {
            "mode": "managed",
            "type": "azurerm_resource_group",
            "address": "rg.main",
            "values": {"id": rid, "name": "application"},
        }
    ]
    xc = Mock(
        return_value={
            "metadata": {"name": namespace},
            "system_metadata": {"uid": identity["uid"]},
        }
    )
    verify = Mock()
    replacements = [
        patch.object(
            fixture.terraform,
            "tf",
            return_value=(
                json.dumps({"values": {"root_module": {"resources": resources}}}),
                0,
            ),
        ),
        patch.object(fixture.runtime, "xc", xc),
        patch.object(
            fixture.ownership, "azure_api_versions", return_value={rid: "2024-01-01"}
        ),
        patch.object(fixture.runtime, "az", return_value={"id": rid}),
        patch.object(fixture.terraform, "guard_group_children"),
        patch.object(fixture.ownership, "verify_fixture", verify),
        patch.object(fixture.terraform, "local_backend_check"),
    ]
    for replacement in replacements:
        replacement.start()
        case.addCleanup(replacement.stop)
    fixture.ownership.inventory(persist=False)
    ensure(state.inventory_receipt is not None)
    prior = dict(state.inventory_receipt or {})
    prior["persistent_resource_ids"] = {}
    state_module.save_json(paths.state / "run-manifest.json", prior)
    state.persistent, state.namespace_uid = {}, None
    return Recovery(fixture, prior, xc, verify)


@dataclass
class Enrollment:
    """State-owned destinations and mutable negative-test live JSON."""

    fixture: Fixture
    live: dict[str, Any]
    outputs: dict[str, Any]
    resources: list[dict[str, Any]]
    run: Mock


def prepare_enrollment(case: unittest.TestCase) -> Enrollment:
    fixture = make_fixture(case)
    resources: list[dict[str, Any]] = []
    outputs: dict[str, Any] = {"namespace": state_module.FIXED["namespace"]}
    live: dict[str, Any] = {}
    for role in ("origin", "generator"):
        owned, guest = guest_state(role)
        resources.extend(owned)
        outputs[role] = guest
        live[guest["id"]] = live_vm(owned, guest)
    fixture.context.state.resources = resources
    fixture.context.state.outputs = outputs
    run = Mock(return_value=("", 0))
    for replacement in (
        patch.object(fixture.runtime, "az", side_effect=lambda *args: live[args[3]]),
        patch.object(fixture.runtime, "run", run),
    ):
        replacement.start()
        case.addCleanup(replacement.stop)
    return Enrollment(fixture, live, outputs, resources, run)


class ARMVersionOwnership(unittest.TestCase):
    def setUp(self):
        self.fixture = make_fixture(self)

    def test_arm_manifest_captures_external_storage_versions(self):
        group = (
            "/subscriptions/" + TEST_SCOPE["subscription_id"] + "/resourceGroups/demo"
        )
        storage = group + "/providers/Microsoft.Storage/storageAccounts/state"
        container = storage + "/blobServices/default/containers/tfstate"
        catalogs = {
            "Microsoft.Resources": [
                {"resourceType": "resourceGroups", "apiVersions": ["2024-03-01"]}
            ],
            "Microsoft.Storage": [
                {"resourceType": "storageAccounts", "apiVersions": ["2024-01-01"]},
                {
                    "resourceType": "storageAccounts/blobServices/containers",
                    "apiVersions": ["2023-05-01", "2025-01-01-preview"],
                },
            ],
        }
        with patch.object(
            self.fixture.runtime,
            "az",
            side_effect=lambda *args: {"resourceTypes": catalogs[args[-1]]},
        ) as az:
            ensure_equal(
                self.fixture.ownership.azure_api_versions([group, storage, container]),
                {group: "2024-03-01", storage: "2024-01-01", container: "2023-05-01"},
            )
            ensure_equal(az.call_count, 2)
            with expect_error(state_module.Blocked, "scope"):
                self.fixture.ownership.azure_api_versions(
                    ["/subscriptions/other/resourceGroups/demo"]
                )
        with (
            patch.object(
                self.fixture.runtime, "az", return_value={"resourceTypes": []}
            ),
            expect_error(state_module.Blocked, "no advertised stable"),
        ):
            self.fixture.ownership.azure_api_versions([storage])

    def test_missing_child_advertisement_confirms_each_exact_owned_child(self):
        child = child_version_fixture(self)
        ids = [child.base + "origin", child.base + "generator"]
        ensure_equal(
            child.fixture.ownership.azure_api_versions(ids),
            dict.fromkeys(ids, "2026-05-01"),
        )
        ensure_equal(child.az.call_count, 3)
        ensure_equal(
            [call.args[-1] for call in child.az.call_args_list[1:]],
            [
                "https://management.azure.com" + rid + "?api-version=2026-05-01"
                for rid in ids
            ],
        )

    def test_child_candidates_skip_only_explicit_unsupported_versions(self):
        child = child_version_fixture(self)

        def az(*args: str):
            if args[0] == "rest" and args[-1].endswith("2026-05-01"):
                message = "required subprocess failed: az exit 1 (arm-api-version-unsupported)"
                raise state_module.Blocked(message)
            return child.read(*args)

        child.az.side_effect = az
        ensure_equal(
            child.fixture.ownership.azure_api_versions(
                [child.base + "origin", child.base + "generator"]
            ),
            {
                child.base + "origin": "2025-01-01",
                child.base + "generator": "2025-01-01",
            },
        )
        ensure_equal(child.az.call_count, 4)

    def test_child_candidates_bound_all_unsupported_reads(self):
        child = child_version_fixture(self)

        def az(*args: str):
            if args[0] == "rest":
                message = "required subprocess failed: az exit 1 (arm-api-version-unsupported)"
                raise state_module.Blocked(message)
            return child.read(*args)

        child.az.side_effect = az
        with expect_error(state_module.Blocked, "no confirmed stable"):
            child.fixture.ownership.azure_api_versions([child.base + "origin"])
        ensure_equal(child.az.call_count, 4)

    def test_child_candidates_never_fallback_on_absence_denial_or_timeout(self):
        for error in (
            state_module.Blocked("HTTP-403-permission"),
            state_module.Blocked("HTTP-401-authentication"),
            state_module.Blocked("ResourceNotFound 404"),
            state_module.Blocked("timeout"),
            subprocess.TimeoutExpired("az", 1),
        ):
            with self.subTest(error=str(error)):
                child = child_version_fixture(self)

                def az(
                    *args: str,
                    failure: BaseException = error,
                    probe: ChildVersions = child,
                ):
                    if args[0] == "rest":
                        raise failure
                    return probe.read(*args)

                child.az.side_effect = az
                with expect_error(type(error)):
                    child.fixture.ownership.azure_api_versions([child.base + "origin"])
                ensure_equal(child.az.call_count, 2)

    def test_child_read_requires_exact_identity_and_success(self):
        cases: tuple[dict[str, Any], ...] = (
            {},
            {"id": "wrong", "properties": {"provisioningState": "Succeeded"}},
            {"properties": {"provisioningState": "Failed"}},
            {"properties": {}},
            {"properties": {"provisioningState": "Updating"}},
            {"properties": None},
            {"properties": []},
        )
        for live in cases:
            with self.subTest(live=live):
                child = child_version_fixture(self)

                def az(
                    *args: str,
                    value_json: str = json.dumps(live),
                    probe: ChildVersions = child,
                ):
                    if args[0] == "provider":
                        return probe.read(*args)
                    return dict({"id": probe.base + "origin"}, **json.loads(value_json))

                child.az.side_effect = az
                with expect_error(state_module.Blocked):
                    child.fixture.ownership.azure_api_versions([child.base + "origin"])
                ensure_equal(child.az.call_count, 2)

    def test_child_missing_stable_ancestor_blocks_without_live_read(self):
        child = child_version_fixture(self, ["2026-05-01-preview"])
        with expect_error(state_module.Blocked, "no advertised stable"):
            child.fixture.ownership.azure_api_versions([child.base + "origin"])
        ensure_equal(child.az.call_count, 1)

    def test_child_uses_nearest_advertised_ancestor_only(self):
        child = child_version_fixture(self)
        catalogs = [
            {"resourceType": "virtualNetworks", "apiVersions": ["2026-05-01"]},
            {"resourceType": "virtualNetworks/subnets", "apiVersions": ["2024-01-01"]},
        ]
        rid = child.base + "origin/children/child"
        child.az.side_effect = lambda *args: (
            {"resourceTypes": catalogs}
            if args[0] == "provider"
            else {"id": rid, "properties": {"provisioningState": "Succeeded"}}
        )
        ensure_equal(
            child.fixture.ownership.azure_api_versions([rid]), {rid: "2024-01-01"}
        )
        ensure(child.az.call_args.args[-1].endswith("api-version=2024-01-01"))


class ManifestOwnership(unittest.TestCase):
    def setUp(self):
        self.fixture = make_fixture(self)

    def test_premature_inventory_cannot_clobber_receipt(self):
        path = self.fixture.context.paths.state / "run-manifest.json"
        state_module.save_json(
            path,
            {"persistent_resource_ids": {"namespace": "system/webapp-api-protection"}},
        )
        before = path.read_bytes()
        with (
            patch.object(self.fixture.terraform, "tf") as tf,
            patch.object(self.fixture.runtime, "xc") as xc,
        ):
            with expect_error(state_module.Blocked, "foundation not initialized"):
                self.fixture.ownership.inventory()
            ensure_equal(path.read_bytes(), before)
            tf.assert_not_called()
            xc.assert_not_called()

    def test_exact_corruption_recovery_preserves_private_snapshot(self):
        recovery = recovery_setup(self)
        fixture = recovery.fixture
        path = fixture.context.paths.state / "run-manifest.json"
        before = path.read_bytes()
        states = {
            path: path.read_bytes()
            for path in fixture.context.paths.state.glob("*.tfstate")
        }
        result = fixture.ownership.recover_manifest()
        backup = path.parent / result["backup"]
        ensure_equal(backup.read_bytes(), before)
        ensure_equal(backup.stat().st_mode & 0o777, 0o600)
        ensure_equal(path.stat().st_mode & 0o777, 0o600)
        ensure_equal({path: path.read_bytes() for path in states}, states)
        ensure_equal(
            json.loads(path.read_text()),
            dict(
                recovery.prior, persistent_resource_ids=fixture.context.state.persistent
            ),
        )
        recovery.verify.assert_called_once_with()

    def test_corruption_recovery_rejects_unknown_wrong_uid_and_ids(self):
        for defect in ("unknown", "uid", "id", "state", "receipt"):
            with self.subTest(defect=defect):
                recovery = recovery_setup(self)
                path = recovery.fixture.context.paths.state / "run-manifest.json"
                prior = recovery.prior
                if defect == "unknown":
                    prior["unknown"] = True
                elif defect == "uid":
                    prior["xc_preserved"][0]["uid"] = "wrong"
                elif defect == "id":
                    prior["owned_resources"][0]["id"] = "wrong"
                elif defect == "state":
                    state_module.save_json(
                        path.parent / "namespace.tfstate", {"resources": []}
                    )
                else:
                    state_module.save_json(
                        path.parent / "namespace-receipt.json",
                        {"path": "wrong", "uid": "wrong"},
                    )
                state_module.save_json(path, prior)
                before = path.read_bytes()
                with expect_error(state_module.Blocked):
                    recovery.fixture.ownership.recover_manifest()
                ensure_equal(path.read_bytes(), before)

    def test_readonly_inventory_never_writes_manifest(self):
        recovery = recovery_setup(self)
        fixture = recovery.fixture
        fixture.context.state.persistent, fixture.context.state.namespace_uid = (
            fixture.terraform.foundation_proof()
        )
        path = fixture.context.paths.state / "run-manifest.json"
        before = path.read_bytes()
        fixture.ownership.inventory(persist=False)
        ensure_equal(path.read_bytes(), before)
        with expect_error(state_module.Blocked, "existing run foundation incompatible"):
            fixture.ownership.inventory()
        ensure_equal(path.read_bytes(), before)

    def test_recovery_wrong_live_uid_never_writes(self):
        recovery = recovery_setup(self)
        recovery.xc.return_value["system_metadata"]["uid"] = "changed"
        path = recovery.fixture.context.paths.state / "run-manifest.json"
        before = path.read_bytes()
        with expect_error(state_module.Blocked, "UID identity mismatch"):
            recovery.fixture.ownership.recover_manifest()
        ensure_equal(path.read_bytes(), before)

    def test_deploy_and_rebuild_keep_corruption_guard(self):
        recovery = recovery_setup(self)
        for operation in ("deploy", "rebuild"):
            recovery.fixture.context.settings = replace(
                recovery.fixture.context.settings, operation=operation
            )
            with expect_error(
                state_module.Blocked, "existing run foundation incompatible"
            ):
                recovery.fixture.terraform.namespace_prepare()

    def test_inventory_retains_only_external_namespace(self):
        fixture = self.fixture
        base = "/subscriptions/" + TEST_SCOPE["subscription_id"] + "/resourceGroups/"
        fixture.context.state.persistent = {
            "namespace": "system/" + state_module.FIXED["namespace"]
        }
        fixture.context.state.namespace_uid = "uid-" + state_module.FIXED["namespace"]
        resources = [
            {
                "mode": "managed",
                "type": "azurerm_resource_group",
                "address": "rg.main",
                "values": {"id": base + "application", "name": "application"},
            },
            {
                "mode": "managed",
                "type": "xcsh_origin_pool",
                "address": "pool.main",
                "values": {
                    "id": "pool-id",
                    "name": "origin-pool",
                    "namespace": state_module.FIXED["namespace"],
                },
            },
        ]
        with (
            patch.object(fixture.terraform, "foundation_proof"),
            patch.object(
                fixture.terraform,
                "tf",
                return_value=(
                    json.dumps({"values": {"root_module": {"resources": resources}}}),
                    0,
                ),
            ),
            patch.object(
                fixture.runtime,
                "xc",
                side_effect=lambda path: {
                    "metadata": {"name": path.rsplit("/", 1)[-1]},
                    "system_metadata": {"uid": "uid-" + path.rsplit("/", 1)[-1]},
                },
            ),
            patch.object(
                fixture.ownership,
                "azure_api_versions",
                side_effect=lambda ids: dict.fromkeys(ids, "2024-01-01"),
            ),
        ):
            ensure_equal(
                fixture.ownership.inventory(),
                {"rg.main": base + "application", "pool.main": "pool-id"},
            )
        manifest = json.loads(
            (fixture.context.paths.state / "run-manifest.json").read_text()
        )
        ensure_equal(manifest["azure_preserved"], [])
        ensure_equal(
            manifest["persistent_resource_ids"], fixture.context.state.persistent
        )
        ensure_equal(
            manifest["xc_preserved"][0]["path"],
            "/api/web/namespaces/" + state_module.FIXED["namespace"],
        )
        ensure_equal(
            set(manifest["azure_api_versions"]),
            set(manifest["azure_owned"] + manifest["azure_preserved"]),
        )

    def test_fixture_preservation_checks_real_canonical_readback(self):
        fixture = self.fixture
        fixture.context.paths = replace(fixture.context.paths, root=ROOT)
        pinned = "/api/object_store/namespaces/webapp-api-protection/stored_objects/swagger/showcase/v1"
        receipt = {
            "api_url": state_module.FIXED["xc_url"],
            "namespace": state_module.FIXED["namespace"],
            "name": "showcase",
            "path": pinned,
            "version": "v1",
            "content": '{"openapi":"3.0.3"}',
        }
        state_module.save_json(
            fixture.context.paths.state / "swagger-receipt.json", receipt
        )
        state_module.save_json(
            fixture.context.paths.vars, {"api_definition_swagger_specs": [pinned]}
        )
        with patch.object(
            fixture.runtime,
            "xc",
            return_value={
                "metadata": {
                    "name": "showcase",
                    "namespace": state_module.FIXED["namespace"],
                    "version": "v1",
                },
                "string_value": receipt["content"],
            },
        ) as xc:
            fixture.ownership.verify_fixture()
            xc.assert_called_once_with(pinned)
            xc.return_value["string_value"] = "{}"
            with expect_error(state_module.Blocked, "content/version"):
                fixture.ownership.verify_fixture()

    def test_fixture_preservation_accepts_exact_deployed_name_and_rejects_mismatch(
        self,
    ):
        fixture = self.fixture
        fixture.context.paths = replace(fixture.context.paths, root=ROOT)
        pinned = "/api/object_store/namespaces/webapp-api-protection/stored_objects/swagger/synthetic-form/v2"
        receipt = {
            "api_url": state_module.FIXED["xc_url"],
            "namespace": state_module.FIXED["namespace"],
            "name": "synthetic-form",
            "path": pinned,
            "version": "v2",
            "content": '{"openapi":"3.0.3"}',
        }
        state_module.save_json(
            fixture.context.paths.state / "swagger-receipt.json", receipt
        )
        state_module.save_json(
            fixture.context.paths.vars, {"api_definition_swagger_specs": [pinned]}
        )
        with patch.object(
            fixture.runtime,
            "xc",
            return_value={
                "metadata": {
                    "name": "synthetic-form",
                    "namespace": state_module.FIXED["namespace"],
                    "version": "v2",
                },
                "string_value": receipt["content"],
            },
        ) as xc:
            fixture.ownership.verify_fixture()
            xc.assert_called_once_with(pinned)
            receipt["name"] = "different-object"
            state_module.save_json(
                fixture.context.paths.state / "swagger-receipt.json", receipt
            )
            with expect_error(state_module.Blocked, "path mismatch"):
                fixture.ownership.verify_fixture()

    def test_missing_fixture_receipt_never_uploads(self):
        with (
            patch.object(self.fixture.runtime, "xc") as xc,
            patch.object(self.fixture.runtime, "run") as run,
        ):
            with expect_error(state_module.Blocked, "receipt missing"):
                self.fixture.ownership.verify_fixture()
            xc.assert_not_called()
            run.assert_not_called()


class SignupRecoveryEnrollmentTests(unittest.TestCase):
    def test_fixture_enrollment_uses_owned_forced_command_destinations(self):
        fixture = make_fixture(self)
        fixture.context.state.outputs = {
            "origin": {"public_ip": "192.0.2.1"},
            "generator": {"public_ip": "192.0.2.2"},
        }
        fixture.context.state.resources = []
        state = fixture.context.paths.state
        (state / "signup-recovery-key").write_text("PRIVATE-SYNTHETIC-KEY")
        (state / "signup-recovery-key.pub").write_text("ssh-ed25519 " + "A" * 68)
        fixture.context.paths.known_hosts.write_text("synthetic known host")
        fixtures = {
            "fixture_type": "seeded-synthetic-origin-accounts",
            "crapi_tokens": ["one", "two"],
        }
        with (
            patch.object(
                fixture.ownership,
                "owned_guest",
                side_effect=lambda _r, _role, candidate: candidate,
            ),
            patch.object(fixture.ownership, "ssh_argv", return_value=["ssh", "owned"]),
            patch.object(
                fixture.runtime, "run", return_value=(json.dumps(fixtures), 0)
            ) as run,
        ):
            fixture.ownership.catalog_fixtures()
        commands = [list(call.args[0]) for call in run.call_args_list]
        ensure(any("/usr/local/bin/enroll-signup-recovery" in cmd for cmd in commands))
        saved = json.loads((state / "catalog-fixtures.json").read_text())
        ensure_equal(saved["signup_recovery"]["host"], "192.0.2.1")
        ensure_equal(
            saved["signup_recovery"]["key"],
            "/opt/traffic-generator/signup-recovery-key",
        )


class ReviewedOwnershipDefects(unittest.TestCase):
    def setUp(self):
        self.fixture = make_fixture(self)

    def test_partial_apply_destroy_uses_inventory_not_showcase_output(self):
        fixture = self.fixture
        fixture.context.settings = replace(
            fixture.context.settings, operation="destroy"
        )
        state_module.save_json(fixture.context.paths.vars, {})
        fixture.context.state.resources = [
            {
                "type": "azurerm_resource_group",
                "address": "group.main",
                "values": {"id": "owned"},
            }
        ]
        with (
            patch.object(fixture.terraform, "namespace_prepare"),
            patch.object(fixture.terraform, "namespace_tf_prepare"),
            patch.object(fixture.terraform, "app_init"),
            patch.object(
                fixture.terraform,
                "get_outputs",
                side_effect=state_module.Blocked("missing showcase"),
            ) as outputs,
            patch.object(
                fixture.ownership, "inventory", return_value={"group.main": "owned"}
            ),
            patch.object(fixture.ownership, "traffic"),
            patch.object(
                fixture.terraform,
                "plan",
                return_value=fixture.context.paths.state / "destroy.plan",
            ) as plan,
            patch.object(
                fixture.terraform,
                "tf",
                side_effect=[("", 0), ('{"values":{"root_module":{}}}', 0), ("", 0)],
            ),
            patch.object(fixture.ownership, "verify_phase") as verify,
            patch.object(fixture.ownership, "verify_fixture"),
        ):
            fixture.lifecycle.destroy()
            outputs.assert_not_called()
            plan.assert_called_once_with("destroy", "destroy", {"group.main": "owned"})
            verify.assert_called_once_with("absence")
            ensure(fixture.context.state.outputs is None)

    def test_unknown_generator_state_does_not_prove_absence(self):
        with expect_error(state_module.Blocked, "ownership state incomplete"):
            self.fixture.ownership.cleanup_access(
                [{"address": "module.traffic_generator.unknown", "values": {}}]
            )

    def test_generator_partial_access_fails_closed(self):
        resources, _ = guest_state("generator")
        with expect_error(state_module.Blocked, "public_ip unavailable"):
            self.fixture.ownership.cleanup_access(resources[:-1])
        ensure(self.fixture.context.state.outputs is None)

    def test_generator_cleanup_requires_live_state_owned_access(self):
        resources, guest = guest_state("generator")
        with patch.object(
            self.fixture.runtime, "az", return_value=live_vm(resources, guest)
        ) as az:
            self.fixture.ownership.cleanup_access(resources)
            with patch.object(self.fixture.runtime, "run", return_value=("", 0)) as run:
                self.fixture.ownership.traffic("stop")
                calls = [call.args[0] for call in run.call_args_list]
                ensure_equal(len(calls), 2)
                ensure("StrictHostKeyChecking=accept-new" in calls[0])
                ensure_equal(calls[0][-1], "true")
                ensure("StrictHostKeyChecking=yes" in calls[1])
                ensure("azureuser@192.0.2.1" in calls[1])
            az.return_value["id"] = "unowned"
            with expect_error(state_module.Blocked, "ownership/access mismatch"):
                self.fixture.ownership.cleanup_access(resources)

    def test_empty_application_state_never_proves_ownership(self):
        self.fixture.context.state.persistent = {
            "namespace": "system/" + state_module.FIXED["namespace"]
        }
        self.fixture.context.state.namespace_uid = "uid"
        with (
            patch.object(self.fixture.terraform, "foundation_proof"),
            patch.object(self.fixture.terraform, "tf", return_value=("{}", 0)),
            expect_error(state_module.Blocked, "missing application state"),
        ):
            self.fixture.ownership.inventory()


class SSHEnrollment(unittest.TestCase):
    def setUp(self):
        self.fixture = prepare_enrollment(self)

    def test_both_fresh_hosts_enrolled_before_strict_readiness(self):
        self.fixture.fixture.ownership.verify_phase("readiness")
        calls = [call.args[0] for call in self.fixture.run.call_args_list]
        ensure_equal(len(calls), 3)
        for role, argv in zip(("origin", "generator"), calls[:2], strict=True):
            ensure("StrictHostKeyChecking=accept-new" in argv)
            ensure(
                "UserKnownHostsFile="
                + str(self.fixture.fixture.context.paths.known_hosts)
                in argv
            )
            ensure_equal(
                argv[-2:],
                ["azureuser@" + self.fixture.outputs[role]["public_ip"], "true"],
            )
        ensure_equal(calls[2][0], "bash")
        ensure("--known-hosts" in calls[2])
        verifier = (ROOT / "scripts/demo_verify_client.py").read_text()
        ensure("StrictHostKeyChecking=yes" in verifier)

    def test_changed_key_and_dead_guest_never_reach_verifier(self):
        for failure in (
            state_module.Blocked("ssh changed host key exit 255"),
            subprocess.TimeoutExpired("ssh", 10),
        ):
            with self.subTest(failure=type(failure).__name__):
                enrollment = prepare_enrollment(self)
                enrollment.run.side_effect = failure
                with expect_error(type(failure)):
                    enrollment.fixture.ownership.verify_phase("readiness")
                ensure_equal(enrollment.run.call_count, 1)
                ensure(
                    "live-readiness"
                    not in [
                        phase["name"]
                        for phase in enrollment.fixture.context.state.receipt["phases"]
                    ]
                )

    def test_all_destinations_guarded_before_first_connection(self):
        for defect in (
            "output-ip",
            "output-id",
            "output-user",
            "subscription",
            "nic-join",
            "pip-join",
            "live-id",
            "live-ip",
            "live-user",
            "live-nic",
            "namespace",
        ):
            with self.subTest(defect=defect):
                enrollment = prepare_enrollment(self)
                guest = enrollment.outputs["generator"]
                if defect.startswith("output-"):
                    guest[
                        {
                            "output-ip": "public_ip",
                            "output-id": "id",
                            "output-user": "admin_username",
                        }[defect]
                    ] = "foreign"
                elif defect == "subscription":
                    enrollment.resources[-1]["values"]["id"] = enrollment.resources[-1][
                        "values"
                    ]["id"].replace(TEST_SCOPE["subscription_id"], "foreign")
                elif defect == "nic-join":
                    enrollment.resources[3]["values"]["network_interface_ids"] = [
                        "foreign"
                    ]
                elif defect == "pip-join":
                    enrollment.resources[4]["values"]["ip_configuration"][0][
                        "public_ip_address_id"
                    ] = "foreign"
                elif defect == "namespace":
                    enrollment.outputs["namespace"] = "foreign"
                else:
                    vm = enrollment.live[guest["id"]]
                    if defect == "live-id":
                        vm["id"] = "foreign"
                    elif defect == "live-ip":
                        vm["publicIps"] = "192.0.2.99"
                    elif defect == "live-user":
                        vm["osProfile"]["adminUsername"] = "foreign"
                    else:
                        vm["networkProfile"]["networkInterfaces"][0]["id"] = "foreign"
                with expect_error(state_module.Blocked):
                    enrollment.fixture.ownership.verify_phase("readiness")
                enrollment.run.assert_not_called()

    def test_enrollment_failure_cleanup_preserves_original_error(self):
        enrollment = self.fixture
        enrollment.run.side_effect = state_module.Blocked(
            "ssh changed host key exit 255"
        )
        with (
            patch.object(enrollment.fixture.lifecycle, "preflight"),
            patch.object(
                enrollment.fixture.lifecycle,
                "deploy",
                side_effect=lambda: enrollment.fixture.ownership.verify_phase(
                    "readiness"
                ),
            ),
            expect_error(state_module.Blocked, "changed host key"),
        ):
            enrollment.fixture.lifecycle.execute()
        receipt = enrollment.fixture.context.state.receipt
        ensure_equal(receipt["status"], "blocked")
        ensure_equal(receipt["error"], "ssh changed host key exit 255")
        ensure("original failure retained" in receipt["cleanup"])
        ensure(
            not any(call.args[0][0] == "bash" for call in enrollment.run.call_args_list)
        )

    def test_enrollment_deadline_is_bounded_and_restored_on_timeout(self):
        enrollment = self.fixture
        original = time.monotonic() + 1800
        enrollment.fixture.context.state.deadline = original

        def timeout(*_args: object):
            ensure(enrollment.fixture.runtime.remaining() <= 20)
            command = "ssh"
            raise subprocess.TimeoutExpired(command, 20)

        enrollment.run.side_effect = timeout
        with expect_error(subprocess.TimeoutExpired):
            enrollment.fixture.ownership.enroll_guests()
        ensure_equal(enrollment.fixture.context.state.deadline, original)

    def test_dead_guest_failure_survives_failed_stop(self):
        enrollment = self.fixture
        failure = subprocess.TimeoutExpired("ssh", 20)
        enrollment.run.side_effect = failure
        with (
            patch.object(enrollment.fixture.lifecycle, "preflight"),
            patch.object(
                enrollment.fixture.lifecycle,
                "deploy",
                side_effect=lambda: enrollment.fixture.ownership.verify_phase(
                    "readiness"
                ),
            ),
            expect_error(subprocess.TimeoutExpired) as caught,
        ):
            enrollment.fixture.lifecycle.execute()
        ensure(caught.exception is failure)
        ensure_equal(
            enrollment.fixture.context.state.receipt["error"], "TimeoutExpired"
        )
        ensure(
            "original failure retained"
            in enrollment.fixture.context.state.receipt["cleanup"]
        )

    def test_wrong_config_cannot_authorize_cleanup_ssh(self):
        self.fixture.fixture.context.settings.config["namespace"] = "foreign"
        with expect_error(state_module.Blocked, "configuration scope"):
            self.fixture.fixture.ownership.traffic("stop")
        self.fixture.run.assert_not_called()
