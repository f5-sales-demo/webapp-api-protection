"""Catalog evidence calibration must finish before any supervised start."""

import json
import unittest
from unittest.mock import Mock, patch

from demo_catalog_start import await_catalog_start
from demo_lifecycle_fixtures import ROOT, make_fixture
from demo_lifecycle_state import Blocked
from demo_test_support import ensure, ensure_equal, expect_error
from demo_verify_types import EvidenceError
from test_demo_lifecycle import stub


class CatalogStart(unittest.TestCase):
    """Exercise real traffic and await methods with an ordered calibration failure."""

    def prepare(self):
        fixture = make_fixture(self)
        fixture.context.state.outputs = {"generator": {"id": "owned"}}
        fixture.context.state.resources = []
        coverage = fixture.context.paths.app / "coverage"
        coverage.mkdir()
        (coverage / "catalog.json").write_text(
            (ROOT / "terraform/coverage/catalog.json").read_text()
        )
        stub(self, fixture.ownership, "owned_guest", return_value={"id": "owned"})
        stub(self, fixture.ownership, "ssh_argv", return_value=["ssh", "owned"])
        stub(self, fixture.ownership, "enroll_guest")
        stub(self, fixture.ownership, "catalog_fixtures")
        self.enterContext(patch("demo_lifecycle_ownership.await_catalog_start"))
        return fixture

    def test_calibration_precedes_start_and_is_reused_for_pass_collection(self):
        fixture = self.prepare()
        calls = []
        client = Mock()
        client.clock_bounds = (-1, 1)
        passes = [
            {
                "passed": True,
                "scenario_count": 164,
                "catalog_complete": True,
                "catalog_accepted": True,
                "traffic": {"verified": True},
                "source_commit": "pinned",
                "artifact_sha256": "exact",
            }
        ] * 2
        status = {
            "service_active": True,
            "service_enabled": True,
            "failures": [],
            "catalog_passes": passes,
            "source_commit": "pinned",
            "artifact_sha256": "exact",
        }

        def run(argv, **_kwargs):
            calls.append(argv[-1])
            return json.dumps(status), 0

        def calibration(*_args):
            calls.append("calibrate")
            return client

        stub(self, fixture.runtime, "run", side_effect=run)
        with (
            patch(
                "demo_lifecycle_ownership.catalog_client",
                side_effect=calibration,
            ) as calibrate,
            patch(
                "demo_lifecycle_ownership.align_generator_clock",
                side_effect=lambda *_: calls.append("align"),
            ) as align,
            patch("demo_lifecycle_ownership.collect_pending") as collect,
            patch("demo_lifecycle_ownership.catalog_metrics", return_value=True),
        ):
            fixture.ownership.traffic("start")
            fixture.ownership.await_catalog()
        ensure_equal(calls, ["status", "calibrate", "align", "start", "status"])
        calibrate.assert_called_once()
        align.assert_called_once()
        ensure(collect.call_args.args[-1] is client)

    def test_failed_calibration_never_starts_traffic(self):
        fixture = self.prepare()
        run = stub(self, fixture.runtime, "run", return_value=("{}", 0))
        with (
            patch(
                "demo_lifecycle_ownership.catalog_client",
                side_effect=EvidenceError("clock unavailable"),
            ),
            expect_error(EvidenceError),
        ):
            fixture.ownership.traffic("start")
        run.assert_called_once()
        ensure_equal(run.call_args.args[0][-1], "status")

    def test_family_recovery_precedes_fixture_export_and_start(self):
        fixture = self.prepare()
        calls = []
        fixture.context.state.outputs["origin"] = {"id": "owned-origin"}
        fixture.ownership.catalog_fixtures.side_effect = lambda: calls.append(
            "fixtures"
        )
        stub(
            self,
            fixture.ownership,
            "recover_catalog_families",
            side_effect=lambda: calls.append("recover"),
        )

        def start(*_args, **_kwargs):
            calls.append(_args[0][-1])
            return "{}", 0

        stub(self, fixture.runtime, "run", side_effect=start)
        with (
            patch(
                "demo_lifecycle_ownership.catalog_client",
                side_effect=lambda *_: calls.append("calibrate"),
            ),
            patch("demo_lifecycle_ownership.align_generator_clock"),
        ):
            fixture.ownership.traffic("start")
        ensure_equal(calls, ["status", "recover", "fixtures", "calibrate", "start"])

    def test_recovery_preserves_journals_of_running_catalog(self):
        fixture = self.prepare()
        fixture.context.state.outputs["origin"] = {"id": "owned-origin"}
        run = stub(
            self,
            fixture.runtime,
            "run",
            return_value=(json.dumps({"service_active": True}), 0),
        )
        fixture.ownership.recover_catalog_families()
        run.assert_called_once()
        ensure_equal(run.call_args.args[0][-1], "status")

    def test_stop_does_not_require_calibration_or_api_evidence(self):
        fixture = self.prepare()
        run = stub(self, fixture.runtime, "run", return_value=("", 0))
        with patch("demo_lifecycle_ownership.catalog_client") as calibrate:
            fixture.ownership.traffic("stop")
        calibrate.assert_not_called()
        ensure_equal(run.call_args.args[0][-1], "stop")


class CatalogStartupJournal(unittest.TestCase):
    """A stopped pass may remain visible briefly after systemd starts the new service."""

    def test_stale_failed_status_waits_for_new_running_identity(self):
        fixture = make_fixture(self)
        old = {
            "run_started": 10,
            "service_active": False,
            "service_enabled": False,
            "status": "stopped",
            "failures": [{"id": "old", "outcome": "tool_failure"}],
        }
        stale = {**old, "service_active": True, "service_enabled": True}
        fresh = {**stale, "run_started": 20, "status": "running", "failures": []}
        run = stub(
            self,
            fixture.runtime,
            "run",
            side_effect=[(json.dumps(stale), 0), (json.dumps(fresh), 0)],
        )
        with patch("demo_catalog_start.time.sleep"):
            await_catalog_start(
                fixture.context,
                fixture.runtime,
                ["ssh", "owned"],
                old,
            )
        ensure_equal(run.call_count, 2)

    def test_new_run_failures_or_disabled_service_are_rejected(self):
        for defect in ("failure", "disabled", "inactive"):
            with self.subTest(defect=defect):
                fixture = make_fixture(self)
                status = {
                    "run_started": 20,
                    "service_active": True,
                    "service_enabled": True,
                    "status": "running",
                    "failures": [],
                }
                if defect == "failure":
                    status["failures"] = [{"id": "new", "outcome": "tool_failure"}]
                else:
                    status[
                        "service_enabled" if defect == "disabled" else "service_active"
                    ] = False
                stub(self, fixture.runtime, "run", return_value=(json.dumps(status), 0))
                with expect_error(Blocked, "fresh catalog startup"):
                    await_catalog_start(
                        fixture.context,
                        fixture.runtime,
                        ["ssh", "owned"],
                        {"run_started": 10, "service_active": False},
                    )

    def test_existing_active_run_remains_valid_without_new_identity(self):
        fixture = make_fixture(self)
        status = {
            "run_started": 10,
            "service_active": True,
            "service_enabled": True,
            "status": "running",
            "failures": [],
        }
        run = stub(self, fixture.runtime, "run", return_value=(json.dumps(status), 0))
        await_catalog_start(
            fixture.context,
            fixture.runtime,
            ["ssh", "owned"],
            status,
        )
        run.assert_called_once()

    def test_missing_fresh_journal_reaches_bounded_failure(self):
        fixture = make_fixture(self)
        stale = {
            "run_started": 10,
            "service_active": True,
            "service_enabled": True,
            "status": "stopped",
            "failures": [],
        }
        stub(self, fixture.runtime, "run", return_value=(json.dumps(stale), 0))
        with (
            patch("demo_catalog_start.time.monotonic", side_effect=[100, 161]),
            expect_error(Blocked, "fresh running journal"),
        ):
            await_catalog_start(
                fixture.context,
                fixture.runtime,
                ["ssh", "owned"],
                {"run_started": 10, "service_active": False},
            )
