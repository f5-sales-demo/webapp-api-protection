"""Reject corrupted or ambiguous proxy inputs before native tools are installed."""

import copy
import hashlib
import io
import json
import tarfile
from pathlib import Path

import demo_go_artifacts as go_artifacts
import pytest

ROOT = Path(__file__).resolve().parents[1]


def small_manifest():
    data = b"v1.2.3\n"
    return {
        "artifacts": [
            {
                "path": "example.com/tool/@v/list",
                "versions": ["v1.2.3"],
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
            }
        ]
    }


def test_frozen_proxy_preparation_and_readback(tmp_path):
    manifest = small_manifest()
    proxy = tmp_path / "proxy"
    assert go_artifacts.prepare(manifest, proxy) == 1
    assert go_artifacts.prepare(manifest, proxy) == 1
    (proxy / manifest["artifacts"][0]["path"]).write_bytes(b"v9.9.9\n")
    with pytest.raises(ValueError, match="bytes differ"):
        go_artifacts.prepare(manifest, proxy)


def test_corrupt_download_never_publishes_proxy(tmp_path, monkeypatch):
    manifest = small_manifest()
    row = manifest["artifacts"][0]
    row["path"] = "example.com/tool/@v/v1.2.3.mod"
    row["url"] = "https://proxy.golang.org/" + row["path"]

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def read(self, _size):
            return b"corrupt"

    monkeypatch.setattr(
        go_artifacts.urllib.request, "urlopen", lambda *_a, **_k: Response()
    )
    proxy = tmp_path / "proxy"
    with pytest.raises(ValueError, match="bytes differ"):
        go_artifacts.prepare(manifest, proxy)
    assert not proxy.exists()
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize(
    "mutation", ["duplicate", "traversal", "url", "latest", "environment"]
)
def test_invalid_lock_rejected_before_io(tmp_path, mutation):
    manifest = json.loads((ROOT / "terraform/go-runtime/artifacts.json").read_text())
    if mutation == "duplicate":
        manifest["artifacts"].append(copy.deepcopy(manifest["artifacts"][0]))
    elif mutation == "traversal":
        manifest["artifacts"][0]["path"] = "../escape/@v/list"
    elif mutation == "url":
        next(row for row in manifest["artifacts"] if row["path"].endswith(".mod"))[
            "url"
        ] = "https://example.com/unowned"
    elif mutation == "latest":
        manifest["tools"][0]["module"] = "github.com/rakyll/hey@latest"
    else:
        manifest["build_environment"]["GOTOOLCHAIN"] = "auto"
    path = tmp_path / "lock.json"
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match=r"invalid|differs|unsupported"):
        go_artifacts.validated_lock(path)


def test_proxy_rejects_extra_files_and_symlinks(tmp_path):
    manifest = small_manifest()
    proxy = tmp_path / "proxy"
    go_artifacts.prepare(manifest, proxy)
    extra = proxy / "extra"
    extra.write_text("unknown")
    with pytest.raises(ValueError, match="coverage differs"):
        go_artifacts.verify_proxy(manifest, proxy)
    extra.unlink()
    extra.symlink_to(tmp_path)
    with pytest.raises(ValueError, match="symbolic link"):
        go_artifacts.verify_proxy(manifest, proxy)


def test_native_binary_hash_and_mode_readback(tmp_path):
    binary = tmp_path / "hey"
    binary.write_bytes(b"exact native binary")
    binary.chmod(0o755)
    manifest = {
        "tools": [
            {
                "name": "hey",
                "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            }
        ]
    }
    assert go_artifacts.verify_binaries(manifest, tmp_path) == 1
    binary.chmod(0o644)
    with pytest.raises(ValueError, match="native binary differs"):
        go_artifacts.verify_binaries(manifest, tmp_path)
    binary.chmod(0o755)
    binary.write_bytes(b"different")
    with pytest.raises(ValueError, match="native binary differs"):
        go_artifacts.verify_binaries(manifest, tmp_path)


@pytest.mark.parametrize("fail", [False, True])
def test_tagged_build_uses_closed_proxy_isolated_caches_and_propagates_failure(
    tmp_path, monkeypatch, fail
):
    manifest = small_manifest()
    manifest["toolchain_version"] = "1.26.8"
    manifest["build_environment"] = {
        "CGO_ENABLED": "0",
        "GOOS": "linux",
        "GOARCH": "amd64",
        "GOAMD64": "v1",
        "GOTOOLCHAIN": "local",
        "GOSUMDB": "off",
    }
    data = b"exact tagged tool"
    manifest["tools"] = [
        {
            "name": "hey",
            "module": "github.com/rakyll/hey@v0.1.5",
            "binary_sha256": hashlib.sha256(data).hexdigest(),
        }
    ]
    proxy = tmp_path / "proxy"
    go_artifacts.prepare(manifest, proxy)
    workspace = tmp_path / "build"
    compiler = tmp_path / "compiler/go"
    monkeypatch.setattr(
        go_artifacts.subprocess,
        "check_output",
        lambda *_a, **_k: "go version go1.26.8 linux/amd64",
    )
    calls = []

    def install(argv, **kwargs):
        calls.append(argv)
        assert argv == [
            str(compiler),
            "install",
            "-trimpath",
            "github.com/rakyll/hey@v0.1.5",
        ]
        environment = kwargs["env"]
        assert environment["GOPROXY"] == proxy.as_uri()
        assert environment["GOTOOLCHAIN"] == "local"
        assert environment["GOVCS"] == "*:off"
        assert environment["GOENV"] == "off"
        assert environment["GOFLAGS"] == ""
        assert kwargs["check"] is True
        assert kwargs["cwd"] == workspace
        for key in ("HOME", "GOPATH", "GOMODCACHE", "GOCACHE", "GOBIN"):
            assert Path(environment[key]).is_relative_to(workspace)
        if fail:
            raise go_artifacts.subprocess.CalledProcessError(1, argv)
        output = Path(environment["GOBIN"]) / "hey"
        output.parent.mkdir()
        output.write_bytes(data)
        output.chmod(0o755)

    monkeypatch.setattr(go_artifacts.subprocess, "run", install)
    if fail:
        with pytest.raises(go_artifacts.subprocess.CalledProcessError):
            go_artifacts.build(manifest, proxy, compiler, workspace)
    else:
        assert go_artifacts.build(manifest, proxy, compiler, workspace) == 1
    assert len(calls) == 1


def test_compiler_archive_readback_rejects_drift_and_extra_content(tmp_path):
    archive = tmp_path / "compiler.tar.gz"
    data = b"declared compiler"
    with tarfile.open(archive, "w:gz") as output:
        item = tarfile.TarInfo("go/bin/go")
        item.mode = 0o755
        item.size = len(data)
        output.addfile(item, io.BytesIO(data))
    directory = tmp_path / "toolchain"
    binary = directory / "go/bin/go"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(data)
    binary.chmod(0o755)
    manifest = {"toolchain_sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}
    assert go_artifacts.verify_toolchain(manifest, archive, directory) == 1
    extra = directory / "unowned"
    extra.write_text("unknown")
    with pytest.raises(ValueError, match="coverage differs"):
        go_artifacts.verify_toolchain(manifest, archive, directory)
    extra.unlink()
    binary.write_bytes(b"drift")
    with pytest.raises(ValueError, match="file differs"):
        go_artifacts.verify_toolchain(manifest, archive, directory)
