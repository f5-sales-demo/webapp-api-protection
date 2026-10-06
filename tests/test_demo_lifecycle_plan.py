"""Saved-plan substitution and drift rejection checks."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from demo_lifecycle_plan import require_current, seal
from demo_lifecycle_state import Blocked
from demo_test_support import ensure, ensure_equal, expect_error


class PlanBindingTests(unittest.TestCase):
    def test_rejects_changed_inputs_state_plan_and_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = root / "terraform"
            app.mkdir()
            for filename in (
                "application.tfvars.json",
                "application.tfstate",
                "namespace.tfstate",
            ):
                (root / filename).write_text("{}")
                (root / filename).chmod(0o600)
            (app / ".terraform.lock.hcl").write_text("lock")
            plan = root / "fresh.plan"
            plan.write_bytes(b"plan")
            context = SimpleNamespace(
                paths=SimpleNamespace(
                    root=root,
                    app=app,
                    state=root,
                    vars=root / "application.tfvars.json",
                ),
                settings=SimpleNamespace(scope={"namespace": "demo"}),
            )
            with patch("demo_lifecycle_plan.source_digest", return_value="source"):
                for target in (
                    context.paths.vars,
                    root / "application.tfstate",
                    root / "namespace.tfstate",
                    app / ".terraform.lock.hcl",
                    plan,
                ):
                    original = target.read_bytes()
                    seal(context, plan, {"resource_changes": [], "output_changes": {}})
                    require_current(context, plan)
                    target.write_bytes(original + b"changed")
                    with expect_error(Blocked):
                        require_current(context, plan)
                    target.write_bytes(original)
                seal(context, plan, {})
            with (
                patch("demo_lifecycle_plan.source_digest", return_value="other"),
                expect_error(Blocked),
            ):
                require_current(context, plan)

    def test_summary_includes_output_actions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = root / "terraform"
            app.mkdir()
            plan = root / "fresh.plan"
            plan.write_bytes(b"plan")
            context = SimpleNamespace(
                paths=SimpleNamespace(
                    root=root, app=app, state=root, vars=root / "vars.json"
                ),
                settings=SimpleNamespace(scope={}),
            )
            with patch("demo_lifecycle_plan.source_digest", return_value="source"):
                seal(
                    context,
                    plan,
                    {"output_changes": {"use_cases": {"actions": ["update"]}}},
                )
            summary = json.loads(plan.with_suffix(".summary.json").read_text())
            ensure(summary["zero_actions"] is False)
            ensure_equal(summary["outputs"], {"use_cases": ["update"]})
