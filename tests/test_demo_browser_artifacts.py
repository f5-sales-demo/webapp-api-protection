"""Exact browser bytes and installed content must pass before guest acceptance."""

import base64
import hashlib
import io
import json
import stat
import zipfile

import pytest
from demo_browser_artifacts import prepare, verify
from demo_traffic_fixtures import ROOT, rendered_cloud_config


def fixture(tmp_path):
    """Provide one exact executable browser fixture and its immutable archive."""
    payload = b"native browser fixture"
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        entry = zipfile.ZipInfo("browser/chrome")
        entry.external_attr = (stat.S_IFREG | 0o755) << 16
        archive.writestr(entry, payload)
    body = data.getvalue()
    installed = tmp_path / "cache/browser/chrome"
    installed.parent.mkdir(parents=True)
    installed.write_bytes(payload)
    installed.chmod(0o755)
    record = {
        "sha256": hashlib.sha256(body).hexdigest(),
        "bytes": len(body),
        "url": "https://example.invalid/exact.zip",
        "cache_path": str(tmp_path / "cache"),
    }
    return record, body, installed


def test_download_and_installed_content_reject_corruption(tmp_path, monkeypatch):
    """Preserve exact archive ownership and reject managed content and mode drift."""
    record, body, installed = fixture(tmp_path)
    monkeypatch.setattr(
        "urllib.request.urlopen", lambda *_args, **_kwargs: io.BytesIO(body)
    )
    archive = prepare(record, tmp_path / "archives")
    assert verify(record, archive) == 1
    installed.write_bytes(b"changed")
    with pytest.raises(ValueError, match="installed browser content"):
        verify(record, archive)
    installed.write_bytes(b"native browser fixture")
    installed.chmod(0o644)
    with pytest.raises(ValueError, match="installed browser content"):
        verify(record, archive)
    archive.write_bytes(b"corrupt")
    with pytest.raises(ValueError, match="retained browser artifact"):
        prepare(record, tmp_path / "archives")


def test_wrong_download_never_publishes_owned_archive(tmp_path, monkeypatch):
    """Reject downloaded bytes without publishing them under the declared hash."""
    record, _body, _installed = fixture(tmp_path)
    monkeypatch.setattr(
        "urllib.request.urlopen", lambda *_args, **_kwargs: io.BytesIO(b"wrong")
    )
    with pytest.raises(ValueError, match="browser artifact bytes"):
        prepare(record, tmp_path / "archives")
    assert not (tmp_path / "archives" / (record["sha256"] + ".zip")).exists()


def test_rendered_browser_inputs_and_full_readback_match_declared_artifacts():
    """Bind Terraform embedding to canonical npm and archive locks plus readback."""
    _template, cloud = rendered_cloud_config()
    files = {item["path"]: item for item in cloud["write_files"]}
    for name in ("package.json", "package-lock.json", "artifacts.json"):
        path = "/opt/traffic-generator/browser-runtime/" + name
        assert (
            base64.b64decode(files[path]["content"])
            == (ROOT / "terraform/browser-runtime" / name).read_bytes()
        )
    lock = json.loads((ROOT / "terraform/browser-runtime/artifacts.json").read_text())
    manifest = json.loads((ROOT / "terraform/guest-files.json").read_text())[
        "generator"
    ]
    assert len(lock["artifacts"]) == 5
    assert (
        sum(
            path.startswith("/opt/traffic-generator/browser-cache/")
            for path in manifest
        )
        == 1180
    )
    run = "\n".join(item for item in cloud["runcmd"] if isinstance(item, str))
    assert run.index("demo-browser-artifacts.py prepare") < run.index("npm ci")
    assert run.index("playwright install chromium") < run.index(
        "demo-browser-artifacts.py verify"
    )
    assert "PUPPETEER_SKIP_DOWNLOAD" not in run
