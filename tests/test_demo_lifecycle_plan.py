"""Saved-plan substitution and drift rejection checks."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from demo_lifecycle_plan import binding, require_current, seal
from demo_lifecycle_state import Blocked, Paths
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
                    namespace_root=app / "namespace",
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
                    root=root,
                    app=app,
                    namespace_root=app / "namespace",
                    state=root,
                    vars=root / "vars.json",
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


@pytest.fixture
def artifacts(tmp_path):
    root = tmp_path / "source"
    state = tmp_path / "private"
    state.mkdir()
    (root / "terraform/namespace").mkdir(parents=True)
    paths = Paths(
        root=root, state=state, key=state / "key", known_hosts=state / "known_hosts"
    )
    for path in [
        paths.vars,
        paths.app / ".terraform.lock.hcl",
        paths.namespace_root / ".terraform.lock.hcl",
        state / "application.tfstate",
        state / "namespace.tfstate",
        state / "reviewed.plan",
    ]:
        path.write_text("synthetic original " + path.name)
    return SimpleNamespace(
        paths=paths, settings=SimpleNamespace(scope="synthetic")
    ), state / "reviewed.plan"


def test_saved_plan_records_both_exact_provider_lock_hashes(artifacts):
    context, plan = artifacts
    with patch("demo_lifecycle_plan.source_digest", return_value="fixed-source"):
        receipt = binding(context, plan)
    assert receipt["schema_version"] == 2
    assert set(receipt["provider_locks"]) == {"application", "namespace"}
    assert all(len(value) == 64 for value in receipt["provider_locks"].values())


@pytest.mark.parametrize("owner", ["application", "namespace"])
def test_changed_provider_lock_rejects_saved_plan_even_with_fixed_source(
    artifacts, owner
):
    context, plan = artifacts
    directory = (
        context.paths.app if owner == "application" else context.paths.namespace_root
    )
    with patch("demo_lifecycle_plan.source_digest", return_value="fixed-source"):
        seal(context, plan, {})
        require_current(context, plan)
        (directory / ".terraform.lock.hcl").write_text("synthetic changed lock")
        with pytest.raises(Blocked, match="stale"):
            require_current(context, plan)
