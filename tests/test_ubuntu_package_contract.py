"""Bootstrap package selection must stay inside the declared signed snapshot."""

import io
import json
import runpy
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest
import yaml
from demo_lifecycle_state import Blocked
from demo_package_pins import PACKAGE_CHECK, package_records, verify_package_pins

ROOT = Path(__file__).resolve().parents[1]


def test_each_guest_uses_exact_packages_from_snapshot_before_installation():
    """Require exact snapshot artifacts before cloud-init package installation."""
    manifest = json.loads((ROOT / "terraform/ubuntu-packages.json").read_text())
    artifacts = {
        (item["package"], item["version"]): item for item in manifest["packages"]
    }
    for role in manifest["dependency_roles"]:
        closure = package_records(manifest, role)
        declared = [item for item in closure if "snapshot.ubuntu.com" in item["url"]]
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
    """Reject incomplete or failed remote verification receipts."""
    manifest: dict = {
        "schema_version": 2,
        "packages": [{"package": "curl", "version": "1.0", "sha256": "a" * 64}],
        "dependency_roles": {"origin-server": ["a" * 64]},
    }
    (tmp_path / "ubuntu-packages.json").write_text(json.dumps(manifest))
    runtime = Mock()
    runtime.run.return_value = (json.dumps({"verified": True, "checked": 1}), "")
    verify_package_pins(runtime, ["ssh", "owned-host"], tmp_path, "origin")
    assert json.loads(runtime.run.call_args.kwargs["input_text"]) == package_records(
        manifest, "origin-server"
    )
    for result in (
        {"verified": False, "checked": 1},
        {"verified": True, "checked": 0},
        {},
    ):
        runtime.run.return_value = (json.dumps(result), "")
        with pytest.raises(Blocked, match="system packages differ"):
            verify_package_pins(runtime, ["ssh", "owned-host"], tmp_path, "origin")


@pytest.mark.parametrize(
    "case",
    [
        ("1.0\tamd64\tinstall ok installed", 0, True),
        ("1.0\tarm64\tinstall ok installed", 0, False),
        ("1.0\tamd64\tdeinstall ok config-files", 0, False),
        ("1.0\tamd64\tinstall ok unpacked", 0, False),
        ("1.1\tamd64\tinstall ok installed", 0, False),
        ("1.0", 0, False),
        ("", 1, False),
    ],
)
def test_native_package_checker_requires_complete_installed_identity(
    monkeypatch, capsys, tmp_path, case
):
    """Run the remote checker against native dpkg identity responses."""
    readback, returncode, accepted = case
    records = [{"package": "curl", "version": "1.0", "architecture": "amd64"}]
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(records)))
    commands = []

    def query(argv, **_kwargs):
        commands.append(argv)
        return subprocess.CompletedProcess(argv, returncode, readback, "")

    monkeypatch.setattr(subprocess, "run", query)
    checker = tmp_path / "package_check.py"
    checker.write_text(PACKAGE_CHECK)
    runpy.run_path(str(checker))
    result = json.loads(capsys.readouterr().out)
    assert result["verified"] is accepted
    assert result["checked"] == 1
    assert result["failures"] == ([] if accepted else ["curl"])
    assert commands == [
        [
            "/usr/bin/dpkg-query",
            "-W",
            "-f=${Version}\t${Architecture}\t${Status}",
            "curl",
        ]
    ]


def test_generator_readback_includes_later_jre_installation(tmp_path):
    """Include the declared runtime JRE alongside bootstrap packages."""
    manifest = json.loads((ROOT / "terraform/ubuntu-packages.json").read_text())
    supplemental = manifest.get("supplemental_roles", {}).get("traffic-generator", [])
    assert [item["package"] for item in supplemental] == ["default-jre-headless"]
    template = (ROOT / "terraform/cloud-init/traffic-generator.yaml").read_text()
    for item in supplemental:
        assert item["package"] + "=" + item["version"] in template
    (tmp_path / "ubuntu-packages.json").write_text(json.dumps(manifest))
    records = package_records(manifest, "traffic-generator")
    runtime = Mock()
    runtime.run.return_value = (
        json.dumps({"verified": True, "checked": len(records)}),
        "",
    )
    verify_package_pins(runtime, ["ssh", "owned-host"], tmp_path, "generator")
    assert json.loads(runtime.run.call_args.kwargs["input_text"]) == records


def test_dependency_closure_is_declared_installed_and_verified(tmp_path):
    """Require each role dependency, including Docker, in runtime readback."""
    manifest = json.loads((ROOT / "terraform/ubuntu-packages.json").read_text())
    assert set(manifest["dependency_roles"]) == set(manifest["roles"])
    for role in manifest["dependency_roles"]:
        entries = package_records(manifest, role)
        assert len(entries) > len(manifest["roles"][role])
        template = yaml.safe_load(
            (ROOT / "terraform/cloud-init" / (role + ".yaml")).read_text()
        )
        ubuntu = [item for item in entries if "snapshot.ubuntu.com" in item["url"]]
        assert template["packages"] == [
            [item["package"], item["version"]] for item in ubuntu
        ]
        (tmp_path / "ubuntu-packages.json").write_text(json.dumps(manifest))
        runtime = Mock()
        runtime.run.return_value = (
            json.dumps({"verified": True, "checked": len(entries)}),
            "",
        )
        verify_package_pins(
            runtime,
            ["ssh", "owned-host"],
            tmp_path,
            "origin" if role == "origin-server" else "generator",
        )
        assert json.loads(runtime.run.call_args.kwargs["input_text"]) == entries


def test_browser_modules_use_integrity_locked_npm_ci():
    """Require locked transitive browser modules before native browser install."""
    template = (ROOT / "terraform/cloud-init/traffic-generator.yaml").read_text()
    value = yaml.safe_load(template)
    files = {item["path"]: item for item in value["write_files"]}
    lock = json.loads(
        files["/opt/traffic-generator/browser-runtime/package-lock.json"]["content"]
    )
    assert len(lock["packages"]) > 4
    assert all(
        item["integrity"].startswith("sha512-")
        for path, item in lock["packages"].items()
        if path
    )
    assert "npm install -g" not in template
    assert "npm ci --no-audit --no-fund" in template
    assert "PUPPETEER_SKIP_DOWNLOAD" not in template


def test_playwright_system_dependencies_are_in_immutable_role_lock():
    """Install Chromium tools and fonts through the exact system package closure."""
    manifest = json.loads((ROOT / "terraform/ubuntu-packages.json").read_text())
    names = {item["package"] for item in package_records(manifest, "traffic-generator")}
    assert {
        "fonts-unifont",
        "xfonts-cyrillic",
        "xfonts-scalable",
        "fonts-ipafont-gothic",
        "fonts-wqy-zenhei",
        "fonts-tlwg-loma-otf",
        "fonts-freefont-ttf",
        "xvfb",
    } <= names
    template = (ROOT / "terraform/cloud-init/traffic-generator.yaml").read_text()
    assert "playwright install-deps" not in template


@pytest.mark.parametrize(
    "defect", ["unknown", "duplicate", "catalog_duplicate", "empty", "conflict"]
)
def test_canonical_role_references_reject_ambiguous_ownership(defect):
    """Fail before remote readback when role ownership is incomplete or ambiguous."""
    first = {"package": "curl", "sha256": "a" * 64}
    manifest: dict = {
        "schema_version": 2,
        "packages": [first],
        "dependency_roles": {"origin-server": [first["sha256"]]},
    }
    references = manifest["dependency_roles"]["origin-server"]
    if defect == "unknown":
        references.append("b" * 64)
    elif defect == "duplicate":
        references.append(first["sha256"])
    elif defect == "catalog_duplicate":
        manifest["packages"].append(first.copy())
    elif defect == "empty":
        references.clear()
    else:
        manifest["packages"].append({"package": "curl", "sha256": "b" * 64})
        references.append("b" * 64)
    with pytest.raises(Blocked, match="canonical system package ownership"):
        package_records(manifest, "origin-server")
