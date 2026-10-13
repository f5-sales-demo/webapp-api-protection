"""Prepare immutable Go proxy artifacts and reproduce exact tagged native tools."""

import argparse
import base64
import hashlib
import json
import re
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path

EXECUTABLE_MODE = 0o755


def validated_lock(lock: Path) -> dict:
    """Reject ambiguous paths, mutable resolution, or undeclared build identity."""
    manifest = json.loads(lock.read_text())
    if manifest.get("schema_version") != 1:
        message = "unsupported Go artifact schema"
        raise ValueError(message)
    seen = set()
    for row in manifest["artifacts"]:
        path = row["path"]
        if (
            not isinstance(path, str)
            or not re.fullmatch(r"[A-Za-z0-9!._/@+-]+", path)
            or any(part in ("", ".", "..") for part in path.split("/"))
            or "/@v/" not in path
            or path in seen
        ):
            message = "invalid Go proxy artifact identity"
            raise ValueError(message)
        if (
            not re.fullmatch(r"[a-f0-9]{64}", row["sha256"])
            or not isinstance(row["bytes"], int)
            or isinstance(row["bytes"], bool)
            or row["bytes"] <= 0
        ):
            message = "invalid Go proxy artifact identity"
            raise ValueError(message)
        seen.add(path)
        if path.endswith("/list"):
            versions = row["versions"]
            if (
                not versions
                or len(set(versions)) != len(versions)
                or any(not re.fullmatch(r"v[0-9][A-Za-z0-9.+-]*", v) for v in versions)
            ):
                message = "invalid frozen Go version list"
                raise ValueError(message)
            verify_bytes(row, ("\n".join(versions) + "\n").encode())
        elif path.endswith(".info"):
            data = base64.b64decode(row["metadata_base64"], validate=True)
            verify_bytes(row, data)
            metadata = json.loads(data)
            if metadata.get("Version") != Path(path).name.removesuffix(
                ".info"
            ) or not metadata.get("Time"):
                message = "frozen Go metadata version differs from declared path"
                raise ValueError(message)
        elif row.get("url") != "https://proxy.golang.org/" + path:
            message = "Go proxy URL differs from declared path"
            raise ValueError(message)
    if not seen:
        message = "empty Go proxy artifact lock"
        raise ValueError(message)
    if manifest["build_environment"] != {
        "CGO_ENABLED": "0",
        "GOOS": "linux",
        "GOARCH": "amd64",
        "GOAMD64": "v1",
        "GOTOOLCHAIN": "local",
        "GOSUMDB": "off",
    }:
        message = "unsupported Go native build environment"
        raise ValueError(message)
    names = set()
    for tool in manifest["tools"]:
        if (
            not re.fullmatch(r"[a-z][a-z0-9]*", tool["name"])
            or tool["name"] in names
            or not re.fullmatch(
                r"[A-Za-z0-9._/+-]+@v[0-9][A-Za-z0-9.+-]*", tool["module"]
            )
            or not re.fullmatch(r"[a-f0-9]{64}", tool["binary_sha256"])
            or tool.get("native_tagged_binary_identical") is not True
        ):
            message = "invalid tagged Go tool identity"
            raise ValueError(message)
        names.add(tool["name"])
    if not names:
        message = "empty Go native tool lock"
        raise ValueError(message)
    return manifest


def verify_bytes(row: dict, data: bytes) -> None:
    """Reject any content that differs from the declared byte identity."""
    if len(data) != row["bytes"] or hashlib.sha256(data).hexdigest() != row["sha256"]:
        message = "Go artifact bytes differ from declared ownership"
        raise ValueError(message)


def verify_proxy(manifest: dict, directory: Path) -> int:
    """Verify the complete local proxy and reject extra or symbolic-link objects."""
    expected = {row["path"] for row in manifest["artifacts"]}
    actual = set()
    if directory.is_symlink():
        message = "Go proxy must not be a symbolic link"
        raise ValueError(message)
    for item in directory.rglob("*"):
        if item.is_symlink():
            message = "Go proxy contains a symbolic link"
            raise ValueError(message)
        if item.is_file():
            actual.add(item.relative_to(directory).as_posix())
    if actual != expected:
        message = "Go proxy artifact coverage differs from lock"
        raise ValueError(message)
    for row in manifest["artifacts"]:
        verify_bytes(row, (directory / row["path"]).read_bytes())
    return len(expected)


def prepare(manifest: dict, directory: Path) -> int:
    """Publish a complete verified proxy atomically; never replace unknown content."""
    if directory.exists() or directory.is_symlink():
        return verify_proxy(manifest, directory)
    directory.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".go-proxy-", dir=directory.parent
    ) as stage:
        staged = Path(stage) / "proxy"
        staged.mkdir()
        for row in manifest["artifacts"]:
            if row["path"].endswith("/list"):
                data = ("\n".join(row["versions"]) + "\n").encode()
            elif row["path"].endswith(".info"):
                data = base64.b64decode(row["metadata_base64"], validate=True)
            else:
                with urllib.request.urlopen(  # noqa: S310 -- validated exact HTTPS URL
                    row["url"], timeout=180
                ) as response:
                    data = response.read(row["bytes"] + 1)
            verify_bytes(row, data)
            output = staged / row["path"]
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(data)
            output.chmod(0o644)
        checked = verify_proxy(manifest, staged)
        staged.rename(directory)
    return checked


def verify_binaries(manifest: dict, directory: Path) -> int:
    """Require native binary hashes before installation and during readback."""
    for tool in manifest["tools"]:
        path = directory / tool["name"]
        if (
            path.is_symlink()
            or not path.is_file()
            or hashlib.sha256(path.read_bytes()).hexdigest() != tool["binary_sha256"]
            or path.stat().st_mode & 0o777 != EXECUTABLE_MODE
        ):
            message = "Go native binary differs from declared artifact"
            raise ValueError(message)
    return len(manifest["tools"])


def verify_toolchain(manifest: dict, archive: Path, directory: Path) -> int:
    """Verify every compiler file and mode against the exact distribution archive."""
    if (
        archive.is_symlink()
        or hashlib.sha256(archive.read_bytes()).hexdigest()
        != manifest["toolchain_sha256"]
    ):
        message = "Go compiler archive differs from declared ownership"
        raise ValueError(message)
    expected = set()
    with tarfile.open(archive) as source:
        for item in source:
            relative = Path(item.name)
            if (
                relative.is_absolute()
                or ".." in relative.parts
                or item.issym()
                or item.islnk()
            ):
                message = "Go compiler archive contains an invalid object"
                raise ValueError(message)
            if not item.isfile():
                continue
            stream = source.extractfile(item)
            installed = directory / relative
            if (
                stream is None
                or installed.is_symlink()
                or not installed.is_file()
                or hashlib.sha256(installed.read_bytes()).digest()
                != hashlib.sha256(stream.read()).digest()
                or installed.stat().st_mode & 0o777 != item.mode & 0o777
            ):
                message = "Go compiler file differs from declared artifact"
                raise ValueError(message)
            expected.add(relative.as_posix())
    actual = set()
    for installed_item in directory.rglob("*"):
        if installed_item.is_symlink():
            message = "Go compiler contains a symbolic link"
            raise ValueError(message)
        if installed_item.is_file():
            actual.add(installed_item.relative_to(directory).as_posix())
    if actual != expected:
        message = "Go compiler file coverage differs from archive"
        raise ValueError(message)
    return len(expected)


def build(manifest: dict, proxy: Path, go: Path, workspace: Path) -> int:
    """Preserve native tagged installs using a closed proxy and isolated caches."""
    verify_proxy(manifest, proxy)
    expected = f"go version go{manifest['toolchain_version']} linux/amd64"
    observed = subprocess.check_output([str(go), "version"], text=True).strip()  # noqa: S603
    if observed != expected:
        message = "Go compiler version differs from artifact lock"
        raise ValueError(message)
    workspace.mkdir(parents=True, exist_ok=False)
    environment = {
        "PATH": str(go.parent) + ":/usr/bin:/bin",
        "HOME": str(workspace),
        "GOPATH": str(workspace / "gopath"),
        "GOMODCACHE": str(workspace / "modules"),
        "GOCACHE": str(workspace / "cache"),
        "GOBIN": str(workspace / "bin"),
        "GOPROXY": proxy.resolve().as_uri(),
        "GOVCS": "*:off",
        "GOENV": "off",
        "GOFLAGS": "",
        **manifest["build_environment"],
    }
    for tool in manifest["tools"]:
        subprocess.run(  # noqa: S603 -- validated locked native module argv
            [str(go), "install", "-trimpath", tool["module"]],
            cwd=workspace,
            env=environment,
            check=True,
        )
    return verify_binaries(manifest, workspace / "bin")


def main() -> None:
    """Prepare, build, or verify exact declared tool artifacts."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "operation", choices=("prepare", "build", "verify", "toolchain")
    )
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--proxy", type=Path, required=True)
    parser.add_argument("--go", type=Path)
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--binaries", type=Path)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--toolchain", type=Path)
    args = parser.parse_args()
    manifest = validated_lock(args.lock)
    if args.operation == "toolchain":
        if args.archive is None or args.toolchain is None:
            parser.error("toolchain requires --archive and --toolchain")
        checked = verify_toolchain(manifest, args.archive, args.toolchain)
    elif args.operation == "prepare":
        checked = prepare(manifest, args.proxy)
    elif args.operation == "build":
        if args.go is None or args.workspace is None:
            parser.error("build requires --go and a fresh --workspace")
        checked = build(manifest, args.proxy, args.go, args.workspace)
    else:
        if args.binaries is None:
            parser.error("verify requires --binaries")
        verify_proxy(manifest, args.proxy)
        checked = verify_binaries(manifest, args.binaries)
    print(
        json.dumps({"operation": args.operation, "verified": True, "checked": checked})
    )


if __name__ == "__main__":
    main()
