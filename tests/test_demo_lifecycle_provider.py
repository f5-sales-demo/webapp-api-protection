"""Latest released provider pins and locks must converge before deployment."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from demo_lifecycle_provider import require_latest_provider
from demo_lifecycle_state import Blocked
from demo_test_support import ensure_equal, expect_error


class LatestProvider(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        self.context = SimpleNamespace(
            paths=SimpleNamespace(app=self.root, state=self.root)
        )
        self.release = {
            "tag_name": "v99.1.2",
            "draft": False,
            "prerelease": False,
            "immutable": True,
            "published_at": "2026-01-01T00:00:00Z",
        }
        self.runtime = Mock()
        self.runtime.run.return_value = (json.dumps(self.release), 0)
        for name in [
            "versions.tf",
            "namespace/main.tf",
            "modules/http-lb/versions.tf",
            "modules/comparison/versions.tf",
        ]:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('version = "= 99.1.2"')
        for name in [".terraform.lock.hcl", "namespace/.terraform.lock.hcl"]:
            (self.root / name).write_text(
                'provider "registry.terraform.io/f5-sales-demo/xcsh" {\n version = "99.1.2"\n}'
            )

    def test_latest_release_and_both_locks_pass(self):
        require_latest_provider(self.context, self.runtime)
        receipt = json.loads((self.root / "latest-provider-release.json").read_text())
        ensure_equal(receipt["tag"], self.release["tag_name"])
        self.runtime.phase.assert_called_once_with("latest-immutable-provider-release")

    def test_new_release_rejects_old_pins(self):
        self.release["tag_name"] = "v99.1.3"
        self.runtime.run.return_value = (json.dumps(self.release), 0)
        with expect_error(Blocked, "pin must match latest published release v99.1.3"):
            require_latest_provider(self.context, self.runtime)
        self.runtime.phase.assert_not_called()

    def test_stale_namespace_lock_rejects(self):
        path = self.root / "namespace/.terraform.lock.hcl"
        path.write_text(path.read_text().replace("99.1.2", "99.1.1"))
        with expect_error(Blocked, "lock must match latest published release"):
            require_latest_provider(self.context, self.runtime)

    def test_unsealed_or_prerelease_rejects(self):
        for field, value in [
            ("immutable", False),
            ("draft", True),
            ("prerelease", True),
        ]:
            with self.subTest(field=field):
                release = {**self.release, field: value}
                self.runtime.run.return_value = (json.dumps(release), 0)
                with expect_error(Blocked, "not immutable"):
                    require_latest_provider(self.context, self.runtime)
