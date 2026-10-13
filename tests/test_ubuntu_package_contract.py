"""Bootstrap package selection must stay inside the declared signed snapshot."""

import json
from pathlib import Path
from unittest.mock import Mock

import pytest
import yaml
from demo_lifecycle_state import Blocked
from demo_package_pins import verify_package_pins

ROOT = Path(__file__).resolve().parents[1]


def test_each_guest_uses_exact_packages_from_snapshot_before_installation():
    manifest = json.loads((ROOT / "terraform/ubuntu-packages.json").read_text())
    artifacts = {
        (item["package"], item["version"]): item for item in manifest["packages"]
    }
    for role, declared in manifest["roles"].items():
        template = (ROOT / "terraform/cloud-init" / (role + ".yaml")).read_text()
        value = yaml.safe_load(template)
        assert value.get("package_upgrade", False) is False
        assert value["packages"] == [
            [item["package"], item["version"]] for item in declared
        ]
        bootstrap = "\n".join(value["bootcmd"])
        assert (
            "https://snapshot.ubuntu.com/ubuntu/" + manifest["snapshot"] + "/"
            in bootstrap
        )
        assert "Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg" in bootstrap
        assert "archive.ubuntu.com" not in bootstrap
        assert "security.ubuntu.com" not in bootstrap
        for item in declared:
            artifact = artifacts[item["package"], item["version"]]
            assert len(artifact["sha256"]) == 64
            assert artifact["url"].startswith(
                "https://snapshot.ubuntu.com/ubuntu/" + manifest["snapshot"] + "/"
            )


def test_package_readback_rejects_drift_missing_results_and_incomplete_count(tmp_path):
    manifest = {"roles": {"origin-server": [{"package": "curl", "version": "1.0"}]}}
    (tmp_path / "ubuntu-packages.json").write_text(json.dumps(manifest))
    runtime = Mock()
    runtime.run.return_value = (json.dumps({"verified": True, "checked": 1}), "")
    verify_package_pins(runtime, ["ssh", "owned-host"], tmp_path, "origin")
    assert (
        json.loads(runtime.run.call_args.kwargs["input_text"])
        == manifest["roles"]["origin-server"]
    )
    for result in (
        {"verified": False, "checked": 1},
        {"verified": True, "checked": 0},
        {},
    ):
        runtime.run.return_value = (json.dumps(result), "")
        with pytest.raises(Blocked, match="system packages differ"):
            verify_package_pins(runtime, ["ssh", "owned-host"], tmp_path, "origin")
