"""Synthetic traffic and local installer fixtures; never live acceptance."""

from __future__ import annotations

import base64
import gzip
import hashlib
import importlib.util
import io
import json
import shlex
import subprocess
import sys
import tarfile
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from tests.demo_test_support import ensure

ROOT = Path(__file__).resolve().parents[1]
DOMAINS = ["www.f5-sales-demo.com", "api.f5-sales-demo.com"]
VEGETA_VERSION = (
    "Version: v12.12.0\n"
    "Commit: 03ca49e9b419c106db29d687827c4c823d8b8ece\n"
    "Runtime: go1.22.5 linux/amd64\n"
    "Date: 2024-07-29T17:35:40Z+0000\n"
)
SPEC = importlib.util.spec_from_file_location(
    "traffic_test_runtime", ROOT / "scripts/demo_traffic.py"
)
if SPEC is None or SPEC.loader is None:
    MESSAGE = "traffic module loader unavailable"
    raise RuntimeError(MESSAGE)
traffic = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = traffic
SPEC.loader.exec_module(traffic)


def configuration() -> dict[str, Any]:
    return {
        "target_domains": DOMAINS.copy(),
        "target_origin_ip": "192.0.2.1",
        "tool_tier": "standard",
        "mud_bad_traffic": True,
    }


def rendered_cloud_config(tier: str = "standard") -> tuple[str, dict[str, Any]]:
    template = (ROOT / "terraform/cloud-init/traffic-generator.yaml").read_text()
    script = (ROOT / "scripts/demo_traffic.py").read_text()
    substitutions = {
        "target_domains": json.dumps(DOMAINS, separators=(",", ":")),
        "target_origin_ip": "192.0.2.1",
        "tool_tier": tier,
        "mud_bad_traffic": "true",
        "generator_commit": "22db98b9bf2e7aed9d76a4015d990bff1e76a2ef",
        "generator_sha256": "6408ae5e274eeb5a285d79acb1f4fd6d38f7b3f1fae09017add7d85157372cf2",
        "installer_sha256": "a" * 64,
        "traffic_script": script.replace("\n", "\n      "),
    }
    for key, value in substitutions.items():
        template = template.replace("${" + key + "}", value)
    template = template.replace("$${", "${").replace("%%{", "%{")
    return template, yaml.safe_load(template)


def azure_custom_data(raw: bytes, *, compressed: bool = True) -> str:
    """Encode Azure custom-data and enforce its decoded binary payload limit."""
    payload = gzip.compress(raw, mtime=0) if compressed else raw
    encoded = base64.b64encode(payload).decode("ascii")
    wire_bytes = len(base64.b64decode(encoded, validate=True))
    ensure(
        wire_bytes <= 65535,
        f"Azure decoded custom-data: {wire_bytes} bytes exceeds 65535-byte limit",
    )
    return encoded


def phase(data: dict[str, Any], marker: str) -> str:
    return next(
        item for item in data["runcmd"] if isinstance(item, str) and marker in item
    )


def content(data: dict[str, Any], suffix: str) -> str:
    return next(
        item["content"] for item in data["write_files"] if item["path"].endswith(suffix)
    )


def captured_echo(target: dict[str, Any]) -> str:
    """Use the sanitized origin echo shape with synthetic request identities."""
    url = urllib.parse.urlsplit(target["url"])
    body = {
        "method": target["method"],
        "url": urllib.parse.urlunsplit(
            url._replace(path=url.path.removeprefix("/httpbin"))
        ),
        "headers": {
            "Host": url.hostname,
            "X-Mud-User": target["header"]["X-MUD-User"][0],
        },
    }
    return base64.b64encode(json.dumps(body).encode()).decode()


def report() -> dict[str, Any]:
    return {
        "requests": 1500,
        "rate": 50,
        "duration": 30_000_000_000,
        "latencies": {
            "min": 1,
            "mean": 5,
            "50th": 5,
            "90th": 6,
            "95th": 7,
            "99th": 8,
            "max": 10,
        },
        "errors": [],
    }


def records() -> list[dict[str, Any]]:
    result = []
    for target in traffic.targets(DOMAINS, "fresh-run", 0):
        url = urllib.parse.urlsplit(target["url"])
        category = urllib.parse.parse_qs(url.query)["demo_class"][0]
        result.append(
            {
                "domain": url.hostname,
                "class": category,
                "code": 200
                if category == "benign"
                else 429
                if category == "rate-limit"
                else 403,
                "error": "",
                "url": target["url"],
                "method": target["method"],
                "body": captured_echo(target),
            }
        )
    return result


def authorize(root: Path) -> None:
    traffic.atomic(
        root / "authorization.json",
        {"config_sha256": traffic.fingerprint(configuration())},
    )


def status(root: Path) -> dict[str, Any]:
    return json.loads((root / "status.json").read_text())


def decoded_row(target: dict[str, Any], index: int, case: str) -> dict[str, Any]:
    category = target["header"]["X-Demo-Class"][0]
    refill = case in ("rate_refill", "missing_body", "blocking_page", "wrong_identity")
    code = (
        200
        if category == "benign" or (category == "rate-limit" and refill)
        else 429
        if category == "rate-limit"
        else 403
    )
    if category == "rate-limit" and case == "rate_403":
        code = 403
    error = "" if code == 200 else f"{code} {traffic.responses[code]}"
    if index == 50 and case in ("network", "business"):
        code, error = (
            (0, "read timeout")
            if case == "network"
            else (500, "500 Internal Server Error")
        )
    body: str | None = captured_echo(target)
    if category == "rate-limit":
        if case == "missing_body":
            body = None
        elif case == "blocking_page":
            body = base64.b64encode(b"Forbidden").decode()
        elif case == "wrong_identity":
            echo = json.loads(base64.b64decode(captured_echo(target)))
            echo["headers"]["X-Mud-User"] = "different-synthetic-user"
            body = base64.b64encode(json.dumps(echo).encode()).decode()
    return {
        "url": target["url"],
        "code": code,
        "error": error,
        "method": target["method"],
        "body": body,
        "timestamp": "2026-10-01T09:22:45Z",
        "latency": 5,
    }


@dataclass
class FakeTool:
    """Write controlled native-tool JSON to the runtime's real output streams."""

    count: int = 1500
    case: str = "fresh_rate"

    def __call__(
        self, argv: list[str], **kwargs: Any
    ) -> subprocess.CompletedProcess[str]:
        if argv[1] == "report":
            errors = ["403 Forbidden"]
            if self.case not in (
                "rate_refill",
                "missing_body",
                "blocking_page",
                "wrong_identity",
                "rate_403",
            ):
                errors.append("429 Too Many Requests")
            extra = {
                "network": "read timeout",
                "business": "500 Internal Server Error",
                "aggregate_extra": "unrelated aggregate error",
            }.get(self.case)
            if extra:
                errors.append(extra)
            json.dump(
                {
                    **report(),
                    "requests": self.count,
                    "rate": self.count / 30,
                    "errors": errors,
                },
                kwargs["stdout"],
            )
        elif argv[1] == "encode":
            folder = Path(argv[-1]).parent
            targets = [
                json.loads(line)
                for line in (folder / "targets.jsonl").read_text().splitlines()
            ]
            for index in range(self.count):
                kwargs["stdout"].write(
                    json.dumps(decoded_row(targets[index % 1500], index, self.case))
                    + "\n"
                )
        return subprocess.CompletedProcess(argv, 0)


def shell(
    source: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    """Run only caller-constructed repository installer snippets in local fixtures."""
    return subprocess.run(  # noqa: S603 -- trusted local fixture shell, no external input
        ["/bin/sh", "-c", source],
        env=env,
        # Lifecycle tests set the parent umask; installer guests are independent.
        umask=0o022,
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )


def archive_fixture(path: Path, member: str, binary: bytes) -> str:
    with tarfile.open(path, "w:gz") as output:
        entry = tarfile.TarInfo(member)
        entry.mode = 0o755
        entry.size = len(binary)
        output.addfile(entry, io.BytesIO(binary))
    return hashlib.sha256(path.read_bytes()).hexdigest()


GO_PROBE = b"""#!/bin/sh
set -eu
[ "${HOME:-}" = "$EXPECTED_HOME" ] || exit 31
[ "${XDG_CACHE_HOME:-}" = "$HOME/.cache" ] || exit 32
[ "${GOCACHE:-}" = "$HOME/.cache/go-build" ] || exit 33
[ "${GOPATH:-}" = "$EXPECTED_GOPATH" ] || exit 34
[ "${GOMODCACHE:-}" = "$GOPATH/pkg/mod" ] || exit 35
[ "${GOTOOLCHAIN:-}" = local ] || exit 36
for directory in "$GOCACHE" "$GOPATH" "$GOMODCACHE"; do
    [ -d "$directory" ] && [ -w "$directory" ] || exit 37
done
if [ "$1" = version ]; then
    printf 'go version %s linux/amd64\\n' "${PROBE_VERSION:-go1.26.8}"
    exit 0
fi
printf '%s\\n' "$*" >> "$CALLS"
[ "$2" != "${FAIL_PACKAGE:-}" ] || exit 41
case "$2" in
github.com/rakyll/hey@v0.1.5) touch "$GOPATH/bin/hey" ;;
github.com/wallarm/gotestwaf/cmd/gotestwaf@v0.5.9)
    touch "$GOPATH/bin/gotestwaf"
    mkdir -p "$GOMODCACHE/github.com/wallarm/gotestwaf@v0.5.9/testcases"
    touch "$GOMODCACHE/github.com/wallarm/gotestwaf@v0.5.9/config.yaml" ;;
*) exit 42 ;;
esac
"""


@dataclass
class GoFixture:
    """Own all disposable paths and the checksum-substituted installer."""

    root: Path
    initialization: str
    stubs: str
    installer: str
    digest: str
    pinned_digest: str
    environment: dict[str, str]

    def source(self, *, valid_hash: bool = True, initialize: bool = True) -> str:
        installer = (
            self.installer.replace(self.pinned_digest, self.digest)
            if valid_hash
            else self.installer
        )
        return (self.initialization if initialize else "") + self.stubs + installer


def go_fixture(root: Path, data: dict[str, Any]) -> GoFixture:
    source = phase(data, "installing load testing tools")
    source = source[: source.index('echo "Installing checksum-pinned Vegeta')]
    pinned = "d0f743b33e8d8945e6b1f432edd15785c70507121d6e2a723b21285eddf8b57b"
    ensure("https://go.dev/dl/go1.26.8.linux-amd64.tar.gz" in source)
    ensure(pinned in source)
    ensure("export GOTOOLCHAIN=local" in data["runcmd"][0])
    ensure("@latest" not in source and "golang-go" not in source)
    archive = root / "fixture.tar.gz"
    digest = archive_fixture(archive, "go/bin/go", GO_PROBE)
    (root / "bin").mkdir()
    initialization = (
        data["runcmd"][0]
        .replace("/root", str(root / "home"))
        .replace("/opt/go", str(root / "gopath"))
    )
    installer = source.replace(". /usr/local/lib/cloud-init-helpers.sh", "")
    for original, destination in (
        ("/opt/traffic-generator-toolchain", "toolchain"),
        ("/opt/gotestwaf", "gotestwaf"),
        ("/opt/go", "gopath"),
        ("/usr/local/bin", "bin"),
        ("/tmp/go.tar.gz", "download.tar.gz"),  # noqa: S108 -- replace guest path with owned temporary fixture
    ):
        installer = installer.replace(original, str(root / destination))
    stubs = (
        content(data, "cloud-init-helpers.sh")
        + '\ndpkg() { echo amd64; };\nlog_phase() { :; }; sleep() { :; }; chown() { :; };\nfetch_url() { printf "fetch:%s\\n" "$1"; cp '
        + shlex.quote(str(archive))
        + ' "$2"; };\n'
    )
    environment = {
        "PATH": "/usr/bin:/bin",
        "EXPECTED_HOME": str(root / "home"),
        "EXPECTED_GOPATH": str(root / "gopath"),
        "CALLS": str(root / "calls"),
    }
    return GoFixture(
        root, initialization, stubs, installer, digest, pinned, environment
    )
