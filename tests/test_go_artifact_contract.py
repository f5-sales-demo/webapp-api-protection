"""Require exact proxy bytes and tagged native tool identity in the Go lock."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_complete_go_proxy_artifact_contract():
    """Freeze graph metadata and module bytes rather than resolving tags live."""
    lock = json.loads((ROOT / "terraform/go-runtime/artifacts.json").read_text())
    artifacts = lock["artifacts"]
    paths = {row["path"] for row in artifacts}
    assert len(paths) == len(artifacts) == 236
    assert lock["toolchain_version"] == "1.26.8"
    assert lock["build_environment"] == {
        "CGO_ENABLED": "0",
        "GOOS": "linux",
        "GOARCH": "amd64",
        "GOAMD64": "v1",
        "GOTOOLCHAIN": "local",
        "GOSUMDB": "off",
    }
    for row in artifacts:
        assert not Path(row["path"]).is_absolute()
        assert ".." not in Path(row["path"]).parts
        assert len(row["sha256"]) == 64
        assert row["bytes"] > 0
        if row["path"].endswith("/list"):
            body = ("\n".join(row["versions"]) + "\n").encode()
            assert hashlib.sha256(body).hexdigest() == row["sha256"]
            assert len(body) == row["bytes"]
        elif row["path"].endswith(".info"):
            body = row["metadata_json"].encode("utf-8")
            assert hashlib.sha256(body).hexdigest() == row["sha256"]
            assert len(body) == row["bytes"]
            assert json.loads(body)["Version"] == Path(row["path"]).name.removesuffix(
                ".info"
            )
        else:
            assert row["url"] == "https://proxy.golang.org/" + row["path"]
    for module in (
        "github.com/rakyll/hey/@v/v0.1.5",
        "github.com/wallarm/gotestwaf/@v/v0.5.9",
    ):
        assert {module + suffix for suffix in (".zip", ".mod", ".info")} <= paths
    assert {row["name"] for row in lock["tools"]} == {"hey", "gotestwaf"}
    assert all(row["native_tagged_binary_identical"] for row in lock["tools"])
