"""Local cloud-init installer checks with disposable artifacts and no live targets."""

import base64
import gzip
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

from tests.demo_test_support import ensure, ensure_equal, expect_error
from tests.demo_traffic_fixtures import (
    ROOT,
    archive_fixture,
    azure_custom_data,
    content,
    go_fixture,
    phase,
    rendered_cloud_config,
    shell,
)


class CloudInitTests(unittest.TestCase):
    def test_apt_retry_configuration_precedes_package_installation(self):
        _, data = rendered_cloud_config()
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "apt.conf"
            source = data["bootcmd"][0].replace(
                "/etc/apt/apt.conf.d/80-demo-acquire", str(config)
            )
            for _ in range(2):
                ensure_equal(shell(source).returncode, 0)
                ensure_equal(
                    config.read_text().splitlines(),
                    [
                        'Acquire::Retries "5";',
                        'Acquire::http::Timeout "60";',
                        'Acquire::https::Timeout "60";',
                    ],
                )

    def test_node_package_checks_content_metadata_and_installed_version(self):
        _, data = rendered_cloud_config()
        pin = json.loads((ROOT / "terraform/tool-pins.json").read_text())
        asset = pin["release_assets"]["nodejs_24.21.0-1nodesource1_amd64.deb"]
        source = phase(data, "installing Node.js 24").replace(
            ". /usr/local/lib/cloud-init-helpers.sh", ""
        )
        ensure(asset["url"] in source and asset["sha256"] in source)
        ensure("setup_24.x" not in source)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "fixture.deb"
            archive.write_bytes(b"declared-node-package")
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            installer = source.replace(
                "/tmp/nodejs-pinned.deb",  # noqa: S108 -- owned local fixture replaces guest path
                str(root / "download.deb"),
            ).replace("dpkg-deb", "deb_metadata")
            stubs = (
                "set -eu\nlog_phase() { :; };\n"
                "dpkg() { echo amd64; };\n"
                'deb_metadata() { case "$3" in Package) echo "$PACKAGE" ;; '
                'Version) echo "$VERSION" ;; Architecture) echo "$ARCH" ;; esac; };\n'
                'node() { echo "$RUNTIME"; };\n'
                'install_packages() { echo installed >> "$CALLS"; };\n'
                "fetch_url() { cp " + shlex.quote(str(archive)) + ' "$2"; };\n'
            )
            environment = {
                **os.environ,
                "CALLS": str(root / "calls"),
                "PACKAGE": "nodejs",
                "VERSION": pin["nodejs_deb_version"],
                "ARCH": "amd64",
                "RUNTIME": "v24.21.0",
            }
            bad_hash = shell(stubs + installer, environment)
            ensure(bad_hash.returncode != 0)
            ensure(not (root / "calls").exists())
            installer = installer.replace(asset["sha256"], digest)
            for field, wrong in (
                ("PACKAGE", "other"),
                ("VERSION", "24.20.0"),
                ("ARCH", "arm64"),
            ):
                with self.subTest(field=field):
                    result = shell(stubs + installer, {**environment, field: wrong})
                    ensure(result.returncode != 0)
                    ensure(not (root / "calls").exists())
            result = shell(stubs + installer, {**environment, "RUNTIME": "v24.20.0"})
            ensure(result.returncode != 0)
            ensure((root / "download.deb").exists(), result.stdout + result.stderr)
            (root / "calls").unlink()
            result = shell(stubs + installer, environment)
            ensure_equal(result.returncode, 0)
            ensure_equal((root / "calls").read_text(), "installed\n")
            ensure(not (root / "download.deb").exists())

    def test_posix_clone_helper_validates_pin_before_git(self):
        _, data = rendered_cloud_config()
        helper = content(data, "/usr/local/lib/cloud-init-helpers.sh")
        ensure("[[" not in helper)
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "helper.sh"
            script.write_text(helper)
            result = subprocess.run(  # noqa: S603 - declared helper under POSIX shell
                [
                    "/bin/sh",
                    "-c",
                    ' . "$1"; clone_repo https://example.test/repo /unused invalid',
                    "sh",
                    str(script),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
        ensure_equal(result.returncode, 1)

    def test_embedded_shell_syntax_and_wire_limit(self):
        template, data = rendered_cloud_config()
        encoded = azure_custom_data(template.encode())
        ensure_equal(gzip.decompress(base64.b64decode(encoded)), template.encode())
        embedded = content(data, "/usr/local/lib/demo_traffic.py")
        ensure_equal(
            embedded.strip(), (ROOT / "scripts/demo_traffic.py").read_text().strip()
        )
        compile(embedded, "embedded-demo-traffic", "exec")
        scripts = [
            item.get("content", "")
            for item in data["write_files"]
            if item.get("content", "").startswith(("#!/bin/bash", "#!/bin/sh"))
        ]
        scripts.extend(
            command for command in data["runcmd"] if isinstance(command, str)
        )
        for source in scripts:
            subprocess.run(
                ["/bin/bash", "-n"], input=source, text=True, check=True, timeout=30
            )
        ensure(len(scripts) > 10)
        ensure(not any(item["path"].endswith(".timer") for item in data["write_files"]))
        ensure("tgen-continuous.service" in template)
        ensure("--commit" in template and "--sha256" in template)
        binding = (ROOT / "terraform/main.tf").read_text()
        ensure(
            'custom_data = base64gzip(templatefile("${path.module}/cloud-init/traffic-generator.yaml"'
            in binding
        )

    def test_custom_data_compression_is_deterministic(self):
        template, _ = rendered_cloud_config()
        raw = template.encode()
        ensure_equal(azure_custom_data(raw), azure_custom_data(raw))
        ensure_equal(gzip.decompress(base64.b64decode(azure_custom_data(raw))), raw)

    def test_custom_data_limit_rejects_oversized_wire_payload(self):
        template, _ = rendered_cloud_config()
        with expect_error(AssertionError, "exceeds 65535-byte limit"):
            azure_custom_data(template.encode(), compressed=False)
        with expect_error(AssertionError, "exceeds 65535-byte limit"):
            azure_custom_data(os.urandom(65536))

    def test_rendered_boot_phase_leaves_traffic_stopped(self):
        _, data = rendered_cloud_config()
        source = phase(data, "disable --now tgen-continuous.service")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = (
                'systemctl() { printf "%s\\n" "$*" >> "$CALLS"; };\n'
                + source.replace(
                    "/opt/traffic-generator/status.json", str(root / "status.json")
                )
            )
            result = shell(source, {**os.environ, "CALLS": str(root / "calls")})
            ensure_equal(result.returncode, 0)
            ensure_equal(
                json.loads((root / "status.json").read_text())["status"], "stopped"
            )
            ensure_equal(
                (root / "calls").read_text().splitlines(),
                [
                    "daemon-reload",
                    "disable --now tgen-continuous.service",
                    "stop tgen-continuous.service",
                ],
            )

    def test_required_installation_failure_stops_cloudinit(self):
        _, data = rendered_cloud_config()
        source = "\n".join(
            item if isinstance(item, str) else shlex.join(item)
            for item in data["runcmd"]
        )
        result = shell("sysctl() { return 17; };\n" + source)
        ensure_equal(result.returncode, 17)
        ensure("provisioning failed (17)" in result.stderr)
        ensure("traffic-generator provisioned" not in result.stdout)

    def test_security_install_failure_cannot_be_masked_by_completion(self):
        _, data = rendered_cloud_config()
        source = phase(data, "installing security binaries").replace(
            ". /usr/local/lib/cloud-init-helpers.sh", ""
        )
        stubs = 'log_phase() { :; }; dpkg() { echo amd64; }; ghlatest() { echo 1.2.3; }; fetch_url() { echo "fetch:$1"; }; sha256sum() { cat >/dev/null; }; unzip() { return 18; };\n'
        result = shell(data["runcmd"][0] + stubs + source)
        ensure_equal(result.returncode, 18)
        ensure("Phase 3 complete" not in result.stdout)

    def test_versioned_downloads_expand_in_parent_shell(self):
        _, data = rendered_cloud_config()
        source = phase(data, "installing security binaries")
        source = source[
            source.index('echo "Installing ffuf') : source.index(
                'echo "Installing feroxbuster'
            )
        ]
        stubs = 'set -eu\nDPKG_ARCH=amd64\nghlatest() { echo 1.2.3; }; uname() { echo x86_64; }; fetch_url() { echo "fetch:$1"; }; tar() { :; }; sha256sum() { cat >/dev/null; };\n'
        result = shell(stubs + source)
        ensure_equal(result.returncode, 0)
        ensure("/v2.3.0/ffuf_2.3.0_linux_amd64.tar.gz" in result.stdout)
        ensure("/v3.8.2/gobuster_Linux_x86_64.tar.gz" in result.stdout)

    def test_every_catalog_requires_zap_and_java(self):
        stubs = 'set -eu\nlog_phase() { :; }; command() { case "$2" in zap|msfconsole|java) return 1 ;; *) return 0 ;; esac; };\n'
        for tier in ("standard", "full"):
            _, data = rendered_cloud_config(tier)
            smoke = phase(data, "running smoke test").replace(
                ". /usr/local/lib/cloud-init-helpers.sh", ""
            )
            with self.subTest(tier=tier), tempfile.TemporaryDirectory() as directory:
                smoke = smoke.replace(
                    "/opt/traffic-generator/status.json",
                    str(Path(directory) / "status.json"),
                )
                result = shell(stubs + smoke)
                ensure_equal(result.returncode, 1)
                ensure_equal(
                    json.loads((Path(directory) / "status.json").read_text())[
                        "tools_fail"
                    ],
                    2,
                )


class ArchiveInstallerTests(unittest.TestCase):
    def test_go_install_children_inherit_clean_cloudinit_environment(self):
        _, data = rendered_cloud_config()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = go_fixture(root, data)
            missing = shell(fixture.source(initialize=False), fixture.environment)
            ensure(missing.returncode != 0 and "XDG_CACHE_HOME" in missing.stderr)
            bad_hash = shell(fixture.source(valid_hash=False), fixture.environment)
            ensure(bad_hash.returncode != 0 and "FAILED" in bad_hash.stdout)
            ensure(not (root / "toolchain/go/bin/go").exists())
            good = shell(fixture.source(), fixture.environment)
            ensure_equal(good.returncode, 0)
            ensure_equal(
                (root / "calls").read_text().splitlines(),
                [
                    "install github.com/rakyll/hey@v0.1.5",
                    "install github.com/wallarm/gotestwaf/cmd/gotestwaf@v0.5.9",
                ],
            )
            ensure_equal((root / "gopath").stat().st_mode & 0o777, 0o700)
            ensure_equal((root / "toolchain/go/bin/go").stat().st_mode & 0o777, 0o755)
            missing_home = shell(
                shlex.quote(str(root / "toolchain/go/bin/go"))
                + " install github.com/rakyll/hey@v0.1.5",
                fixture.environment,
            )
            ensure_equal(missing_home.returncode, 31)
            for package in (
                "github.com/rakyll/hey@v0.1.5",
                "github.com/wallarm/gotestwaf/cmd/gotestwaf@v0.5.9",
            ):
                failed = shell(
                    fixture.source(), {**fixture.environment, "FAIL_PACKAGE": package}
                )
                ensure_equal(failed.returncode, 1)
                ensure("provisioning failed (1)" in failed.stderr)
                ensure_equal(
                    (root / "calls").read_text().splitlines()[-3:],
                    ["install " + package] * 3,
                )
            wrong = shell(
                fixture.source(), {**fixture.environment, "PROBE_VERSION": "go1.22.0"}
            )
            ensure(wrong.returncode != 0 and "Unexpected Go version" in wrong.stderr)

    def test_dalfox_pinned_archive_layout_and_fail_closed_install(self):
        _, data = rendered_cloud_config()
        source = phase(data, "installing security binaries")
        source = source[
            source.index('echo "Installing dalfox') : source.index(
                'echo "Installing amass'
            )
        ]
        digest = "3b059b6bb55e686b5f240852ea6a6750aa5e35a3b404e4027ffe505e2b60a470"
        ensure("DALFOX_VER=3.2.3" in source and digest in source)
        ensure("ghlatest" not in source and "dalfox-linux-" not in source)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "fixture.tar.gz"
            binary = b'#!/bin/sh\nprintf "dalfox 3.2.3\\n"\n'
            fixture_digest = archive_fixture(
                archive, "dalfox-v3.2.3-linux-x86_64/dalfox", binary
            )
            (root / "bin").mkdir()
            installer = source.replace(
                "/tmp/dalfox.tar.gz",  # noqa: S108 -- substitute guest literal with owned temporary fixture
                str(root / "download.tar.gz"),
            ).replace("/usr/local/bin", str(root / "bin"))
            stubs = (
                'set -eu\nDPKG_ARCH=amd64\nfetch_url() { printf "fetch:%s\\n" "$1"; cp '
                + shlex.quote(str(archive))
                + ' "$2"; };\n'
            )
            bad = shell(stubs + installer)
            ensure(bad.returncode != 0 and "FAILED" in bad.stdout)
            ensure(not (root / "bin/dalfox").exists())
            good = shell(stubs + installer.replace(digest, fixture_digest))
            ensure_equal(good.returncode, 0)
            ensure("/v3.2.3/dalfox-v3.2.3-linux-x86_64.tar.gz" in good.stdout)
            ensure_equal((root / "bin/dalfox").read_bytes(), binary)
            ensure_equal((root / "bin/dalfox").stat().st_mode & 0o777, 0o755)
            ensure(not (root / "download.tar.gz").exists())
            ensure_equal(
                shell(stubs + "fetch_url() { return 23; };\n" + installer).returncode,
                23,
            )
            unsupported = shell(stubs + "DPKG_ARCH=arm64\n" + installer)
            ensure(unsupported.returncode != 0 and "fetch:" not in unsupported.stdout)

    def test_zap_is_full_tier_pinned_and_checksum_failure_is_fatal(self):
        stubs = 'log_phase() { :; }; install_packages() { :; }; fetch_url() { echo "fetch:$1"; }; tar() { echo extracted; }; mv() { :; }; ln() { :; }; chmod() { :; }; timeout() { echo "timeout:$*"; };\n'
        for tier in ("standard", "full"):
            _, data = rendered_cloud_config(tier)
            source = phase(data, "installing required full-catalog tools").replace(
                ". /usr/local/lib/cloud-init-helpers.sh", ""
            )
            for checksum_status in (0, 19):
                with (
                    self.subTest(tier=tier, checksum_status=checksum_status),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    installer = source.replace(
                        "/usr/local/bin/zap", str(Path(directory) / "zap")
                    )
                    checker = (
                        "sha256sum() { cat; return " + str(checksum_status) + "; };\n"
                    )
                    result = shell(data["runcmd"][0] + stubs + checker + installer)
                    ensure_equal(result.returncode, checksum_status)
                    ensure("/v2.17.0/ZAP_2.17.0_Linux.tar.gz" in result.stdout)
                    ensure(
                        "efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a"
                        in result.stdout
                    )
                    ensure_equal("extracted" in result.stdout, checksum_status == 0)
                    ensure_equal(
                        "timeout:60 zap -version" in result.stdout,
                        checksum_status == 0,
                    )

    def test_real_checksum_rejects_corrupted_zap_before_extracting(self):
        _, data = rendered_cloud_config("full")
        source = phase(data, "installing required full-catalog tools").replace(
            ". /usr/local/lib/cloud-init-helpers.sh", ""
        )
        stubs = 'log_phase() { :; }; install_packages() { :; }; fetch_url() { printf corrupted > "$2"; }; tar() { echo MUST_NOT_EXTRACT; return 90; };\n'
        with tempfile.TemporaryDirectory() as directory:
            source = source.replace(
                "/tmp/zap.tar.gz",  # noqa: S108 -- substitute guest literal with owned temporary fixture
                str(Path(directory) / "zap.tar.gz"),
            ).replace("/usr/local/bin/zap", str(Path(directory) / "zap"))
            result = shell(data["runcmd"][0] + stubs + source)
        ensure(result.returncode != 0 and "FAILED" in result.stdout)
        ensure("MUST_NOT_EXTRACT" not in result.stdout)


class PythonInstallerTests(unittest.TestCase):
    def test_python_tool_install_is_hash_locked_and_never_global(self):
        _, data = rendered_cloud_config()
        source = phase(data, "installing isolated Python")
        ensure("/usr/bin/python3 -m venv /opt/traffic-generator/venv" in source)
        ensure("sys.prefix != sys.base_prefix" in source)
        ensure(
            "timeout 900 /opt/traffic-generator/venv/bin/python -m pip --isolated install"
            in source
        )
        ensure("--require-hashes" in source)
        for flag in (
            "--system-site-packages",
            "--break-system-packages",
            "--ignore-installed",
        ):
            ensure(flag not in source)
        lines = content(data, "python-tools.lock").strip().splitlines()
        ensure(len(lines) > 80)
        for line in lines:
            ensure(
                re.fullmatch(r"\S+==\S+ --hash=sha256:[a-f0-9]{64}", line) is not None
            )
        for pin in (
            "pip==26.2.1",
            "blinker==1.9.0",
            "Flask==3.1.3",
            "mitmproxy==12.2.3",
        ):
            ensure(any(line.startswith(pin + " ") for line in lines))
        for removed in ("wfuzz", "pycurl", "chardet", "setuptools"):
            ensure(not any(line.lower().startswith(removed + "==") for line in lines))
        ensure("wfuzz" not in source)
        smoke = phase(data, "running smoke test")
        ensure("wfuzz" not in smoke and " ffuf " in smoke)

    def test_real_venv_hides_distro_blinker_without_network(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            venv = root / "venv"
            subprocess.run(  # noqa: S603 -- fixed interpreter and owned temporary venv destination
                ["/usr/bin/python3", "-m", "venv", str(venv)], check=True, timeout=60
            )
            python = str(venv / "bin/python")
            check = 'import sys, importlib.util; sys.exit(0 if sys.prefix != sys.base_prefix and importlib.util.find_spec("blinker") is None else 1)'
            subprocess.run([python, "-I", "-c", check], check=True, timeout=30)  # noqa: S603 -- owned temporary venv interpreter
            wheel = root / "blinker-1.9.0-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("blinker/__init__.py", '__version__ = "1.9.0"\n')
                archive.writestr(
                    "blinker-1.9.0.dist-info/METADATA",
                    "Metadata-Version: 2.1\nName: blinker\nVersion: 1.9.0\n",
                )
                archive.writestr(
                    "blinker-1.9.0.dist-info/WHEEL",
                    "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
                )
                archive.writestr("blinker-1.9.0.dist-info/RECORD", "")
            result = subprocess.run(  # noqa: S603 -- owned interpreter, offline fixture wheel
                [
                    python,
                    "-m",
                    "pip",
                    "--isolated",
                    "install",
                    "--no-index",
                    "--no-deps",
                    str(wheel),
                ],
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            ensure_equal(result.returncode, 0)
            ensure("Uninstalling" not in result.stdout)
            subprocess.run(  # noqa: S603 -- owned temporary venv interpreter
                [
                    python,
                    "-I",
                    "-c",
                    "import blinker, sys; sys.exit(0 if blinker.__file__.startswith(sys.prefix) else 1)",
                ],
                check=True,
                timeout=30,
            )

    def test_python_phase_failure_stops_provisioning(self):
        _, data = rendered_cloud_config()
        source = phase(data, "installing isolated Python").replace(
            ". /usr/local/lib/cloud-init-helpers.sh", ""
        )
        for failure in ("install", "startup"):
            with (
                self.subTest(failure=failure),
                tempfile.TemporaryDirectory() as directory,
            ):
                installer = source.replace("/opt/traffic-generator", directory)
                stubs = "set -eu\nlog_phase() { :; };\n"
                stubs += (
                    "retry_cmd() { return 31; };\n"
                    if failure == "install"
                    else "retry_cmd() { :; }; timeout() { return 43; };\n"
                )
                result = shell(stubs + installer + "\necho unexpected-completion")
                ensure_equal(result.returncode, 31 if failure == "install" else 43)
                ensure("unexpected-completion" not in result.stdout)

    def test_python_tools_share_canonical_path_and_missing_mitmdump_blocks_ready(self):
        _, data = rendered_cloud_config()
        files = {item["path"]: item["content"] for item in data["write_files"]}
        path = "/opt/traffic-generator/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        for name in (
            "/etc/environment",
            "/etc/profile.d/traffic-generator.sh",
            "/usr/local/bin/tgen-control",
        ):
            ensure(path in files[name])
        ensure("exec /usr/bin/python3" in files["/usr/local/bin/tgen-control"])
        ensure(
            "exec sudo -n /usr/local/bin/tgen-control"
            in files["/usr/local/bin/tgen-control"]
        )
        smoke = phase(data, "running smoke test").replace(
            ". /usr/local/lib/cloud-init-helpers.sh", ""
        )
        ensure(path in smoke)
        stubs = 'set -eu\nlog_phase() { :; }; command() { [ "$2" != mitmdump ]; };\n'
        with tempfile.TemporaryDirectory() as directory:
            smoke = smoke.replace(
                "/opt/traffic-generator/status.json",
                str(Path(directory) / "status.json"),
            )
            result = shell(stubs + smoke)
            ensure_equal(result.returncode, 1)
            ensure("MISSING: mitmdump" in result.stdout)
            observed = json.loads((Path(directory) / "status.json").read_text())
            ensure_equal(observed["status"], "degraded")
            ensure_equal(observed["tools_fail"], 1)

    @unittest.skipUnless(
        os.environ.get("VALIDATE_PYTHON_TOOL_LOCK") == "1",
        "Explicit network dependency validation only",
    )
    def test_published_python_lock_installs_on_ubuntu_python312(self):
        _, data = rendered_cloud_config()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            venv = root / "venv"
            subprocess.run(  # noqa: S603 -- fixed interpreter and owned temporary venv destination
                ["/usr/bin/python3", "-m", "venv", str(venv)], check=True, timeout=60
            )
            python = str(venv / "bin/python")
            subprocess.run(  # noqa: S603 -- owned temporary venv interpreter
                [
                    python,
                    "-I",
                    "-c",
                    "import sys; sys.exit(0 if sys.version_info[:2] == (3, 12) else 1)",
                ],
                check=True,
                timeout=30,
            )
            requirements = root / "python-tools.lock"
            requirements.write_text(content(data, "python-tools.lock"))
            argv = [
                python,
                "-m",
                "pip",
                "--isolated",
                "install",
                "--require-hashes",
                "-r",
                str(requirements),
            ]
            subprocess.run([*argv, "--dry-run"], check=True, timeout=900)  # noqa: S603 -- explicit opt-in, hash-locked isolated installer
            source = (
                phase(data, "installing isolated Python")
                .replace(". /usr/local/lib/cloud-init-helpers.sh", "")
                .replace("/opt/traffic-generator", str(root))
            )
            helpers = 'set -eu\nlog_phase() { :; }; retry_cmd() { shift 2; "$@"; };\n'
            subprocess.run(  # noqa: S603 -- repository installer snippet redirected entirely into owned venv
                ["/bin/sh", "-c", helpers + source], check=True, timeout=1100
            )
            for tool in (
                "scapy",
                "arjun",
                "hashid",
                "pwn",
                "mitmproxy",
                "mitmdump",
                "mitmweb",
                "sslyze",
                "smbclient.py",
            ):
                executable = str(venv / "bin" / tool)
                ensure_equal(shutil.which(tool, path=str(venv / "bin")), executable)
                flag = (
                    "--version"
                    if tool in ("mitmproxy", "mitmdump", "mitmweb")
                    else "-h"
                )
                subprocess.run(  # noqa: S603 -- owned hash-validated temporary tool executable
                    [executable, flag],
                    check=True,
                    timeout=30,
                    stdout=subprocess.DEVNULL,
                )
            subprocess.run(  # noqa: S603 -- owned temporary venv interpreter
                [
                    python,
                    "-I",
                    "-c",
                    'import blinker, sys, importlib.util; sys.exit(0 if blinker.__file__.startswith(sys.prefix) and importlib.util.find_spec("wfuzz") is None else 1)',
                ],
                check=True,
                timeout=30,
            )


if __name__ == "__main__":
    unittest.main()
