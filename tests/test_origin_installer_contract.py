"""The origin installer pin must replace independent application provisioning."""

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class InstallerContractTests(unittest.TestCase):
    def test_cloud_init_uses_immutable_shared_installer(self):
        template = (ROOT / "terraform/cloud-init/origin-server.yaml").read_text()
        assert "docker-compose.yml" not in template
        assert "origin_commit" in template
        assert "sha256sum --check" in template

    def test_retention_overrides_are_installed_after_shared_bootstrap(self):
        template = (ROOT / "terraform/cloud-init/origin-server.yaml").read_text()
        bootstrap = template.index("  - [bash, /usr/local/bin/bootstrap-origin]")
        cleanup = template.index(
            "  - [install, -m, '0755', /usr/local/lib/demo-dvwa-session-cleanup.py"
        )
        timer = template.index(
            "  - [install, -m, '0644', /usr/local/lib/demo-dvwa-session-cleanup.timer"
        )
        enabled = template.index(
            "  - [systemctl, enable, --now, demo-dvwa-session-cleanup.timer]"
        )
        assert bootstrap < cleanup < timer < enabled

    def test_all_nine_url_outputs_derive_from_manifest(self):
        output = (ROOT / "terraform/outputs.tf").read_text()
        assert "local.origin_applications" in output
        manifest = json.loads((ROOT / "terraform/origin-applications.json").read_text())
        assert len(manifest["applications"]) == 9


if __name__ == "__main__":
    unittest.main()
