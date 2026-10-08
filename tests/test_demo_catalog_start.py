"""Catalog evidence calibration must finish before any supervised start."""

import json
import unittest
from unittest.mock import Mock, patch

from demo_lifecycle_fixtures import ROOT, make_fixture
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
        ensure_equal(calls, ["calibrate", "align", "start", "status"])
        calibrate.assert_called_once()
        align.assert_called_once()
        ensure(collect.call_args.args[-1] is client)

    def test_failed_calibration_never_starts_traffic(self):
        fixture = self.prepare()
        run = stub(self, fixture.runtime, "run")
        with (
            patch(
                "demo_lifecycle_ownership.catalog_client",
                side_effect=EvidenceError("clock unavailable"),
            ),
            expect_error(EvidenceError),
        ):
            fixture.ownership.traffic("start")
        run.assert_not_called()

    def test_stop_does_not_require_calibration_or_api_evidence(self):
        fixture = self.prepare()
        run = stub(self, fixture.runtime, "run", return_value=("", 0))
        with patch("demo_lifecycle_ownership.catalog_client") as calibrate:
            fixture.ownership.traffic("stop")
        calibrate.assert_not_called()
        ensure_equal(run.call_args.args[0][-1], "stop")
