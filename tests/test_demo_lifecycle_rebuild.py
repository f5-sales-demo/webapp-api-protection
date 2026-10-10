"""Reviewed VM rebuild and SSH trust rotation regressions."""

from __future__ import annotations

import copy
import unittest
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest.mock import patch

from demo_lifecycle_fixtures import (
    guest_state,
    lifecycle,
    live_vm,
    make_fixture,
    state_module,
)
from demo_test_support import ensure_equal, expect_error
from test_demo_lifecycle import stub


class RebuildOrchestration(unittest.TestCase):
    """Exercise replacement orchestration through the actual lifecycle method."""

    def test_review_is_checked_before_stopping_or_applying(self):
        fixture = make_fixture(self)
        stub(self, fixture.terraform, "namespace_tf_prepare")
        stub(self, fixture.terraform, "app_init")
        stub(self, fixture.ownership, "inventory", return_value={"vm": "owned"})
        fixture.context.state.resources = []
        stub(
            self,
            fixture.terraform,
            "reviewed_rebuild",
            side_effect=lifecycle.Blocked("stale"),
        )
        stop = stub(self, fixture.ownership, "traffic")
        apply = stub(self, fixture.terraform, "apply")
        with expect_error(lifecycle.Blocked, "stale"):
            fixture.lifecycle.rebuild()
        stop.assert_not_called()
        apply.assert_not_called()

    def test_stale_review_failure_keeps_running_traffic(self):
        fixture = make_fixture(self)
        fixture.context.settings = replace(
            fixture.context.settings, operation="rebuild"
        )
        stub(self, fixture.lifecycle, "preflight")
        stub(self, fixture.lifecycle, "rebuild", side_effect=lifecycle.Blocked("stale"))
        cleanup = stub(self, lifecycle, "_cleanup_traffic")
        with expect_error(lifecycle.Blocked, "stale"):
            fixture.lifecycle.execute()
        cleanup.assert_not_called()

    def test_rebuild_preserves_services_and_refreshes_ownership_before_readiness(self):
        fixture = make_fixture(self)
        calls: list[str] = []
        resources: list[dict[str, Any]] = [{"address": "vm", "values": {"id": "owned"}}]
        fixture.context.state.resources = resources
        for owner, method in (
            (fixture.terraform, "namespace_tf_prepare"),
            (fixture.terraform, "app_init"),
            (fixture.ownership, "inventory"),
            (fixture.ownership, "cleanup_access"),
            (fixture.terraform, "get_outputs"),
            (fixture.ownership, "rotate_rebuilt_hosts"),
        ):
            stub(
                self,
                owner,
                method,
                side_effect=lambda *_a, method=method, **_k: calls.append(method),
            )
        stub(
            self,
            fixture.terraform,
            "reviewed_rebuild",
            return_value=Path("review.plan"),
        )
        stub(
            self,
            fixture.terraform,
            "apply",
            side_effect=lambda plan: calls.append("apply-" + str(plan)),
        )
        stub(self, fixture.terraform, "plan", side_effect=lambda name, *_a: Path(name))
        stub(
            self,
            fixture.ownership,
            "traffic",
            side_effect=lambda action: calls.append("traffic-" + action),
        )
        stub(self, fixture.ownership, "verify_phase", side_effect=calls.append)
        destroy = stub(self, fixture.lifecycle, "destroy")
        deploy = stub(self, fixture.lifecycle, "deploy")
        fixture.lifecycle.rebuild()
        ensure_equal(
            calls,
            [
                "namespace_tf_prepare",
                "app_init",
                "inventory",
                "cleanup_access",
                "traffic-stop",
                "apply-review.plan",
                "get_outputs",
                "inventory",
                "rotate_rebuilt_hosts",
                "readiness",
                "traffic-start",
                "acceptance",
                "apply-post-rebuild-drift",
            ],
        )
        destroy.assert_not_called()
        deploy.assert_not_called()


class RebuiltHostKeys(unittest.TestCase):
    """Require unique VM replacement proof before removing enrolled keys."""

    def prepare(self):
        fixture = make_fixture(self)
        previous = []
        current = []
        live = {}
        for role in ("origin", "generator"):
            resources, guest = guest_state(role)
            resources[0]["values"]["virtual_machine_id"] = "old-" + role
            previous.extend(copy.deepcopy(resources))
            resources[0]["values"]["virtual_machine_id"] = "new-" + role
            current.extend(resources)
            value = live_vm(resources, guest)
            value["vmId"] = "new-" + role
            live[guest["id"]] = value
        fixture.context.state.resources = current
        fixture.context.paths.known_hosts.write_text(
            "192.0.2.1 ssh-ed25519 AAAA\n192.0.2.99 ssh-ed25519 BBBB\n"
        )
        return fixture, previous, current, live

    def test_replacement_rotates_only_owned_ips_and_preserves_backup(self):
        fixture, previous, _current, live = self.prepare()
        snapshot = fixture.context.paths.known_hosts.read_bytes()
        with (
            patch.object(
                fixture.runtime, "az", side_effect=lambda *_a, live=live: live[_a[3]]
            ),
            patch.object(fixture.runtime, "run") as run,
        ):
            fixture.ownership.rotate_rebuilt_hosts(previous)
        ensure_equal(
            [c.args[0][2] for c in run.call_args_list], ["192.0.2.2", "192.0.2.1"]
        )
        backups = list(fixture.context.paths.state.glob("known_hosts.pre-rebuild-*"))
        ensure_equal(len(backups), 1)
        ensure_equal(backups[0].read_bytes(), snapshot)
        ensure_equal(backups[0].stat().st_mode & 0o777, 0o600)

    def test_unchanged_unique_ids_keep_all_keys(self):
        fixture, _previous, current, _live = self.prepare()
        with patch.object(fixture.runtime, "run") as run:
            fixture.ownership.rotate_rebuilt_hosts(copy.deepcopy(current))
        run.assert_not_called()

    def test_missing_or_mismatched_identity_never_removes_any_key(self):
        for defect in ("missing", "live", "resource", "ip"):
            with self.subTest(defect=defect):
                fixture, previous, current, live = self.prepare()
                if defect == "missing":
                    current[0]["values"].pop("virtual_machine_id")
                elif defect == "live":
                    live[current[0]["values"]["id"]]["vmId"] = "unrelated"
                elif defect == "resource":
                    previous[0]["values"]["id"] += "-other"
                else:
                    previous[2]["values"]["ip_address"] = "192.0.2.99"
                with (
                    patch.object(
                        fixture.runtime,
                        "az",
                        side_effect=lambda *_a, live=live: live[_a[3]],
                    ),
                    patch.object(fixture.runtime, "run") as run,
                    expect_error(state_module.Blocked),
                ):
                    fixture.ownership.rotate_rebuilt_hosts(previous)
                run.assert_not_called()
