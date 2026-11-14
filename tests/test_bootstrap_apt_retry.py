"""Exercise the declared bootstrap wrapper without changing installed packages."""

import hashlib
import json
import os
import shlex
import sys
from pathlib import Path

import pytest
import yaml

from tests.demo_traffic_fixtures import shell

ROOT = Path(__file__).resolve().parents[1]


def declared_wrapper():
    """Read the exact executable written by Terraform's cloud-init template."""
    config = yaml.safe_load(
        (ROOT / "terraform/cloud-init/traffic-generator.yaml").read_text()
    )
    command = next(item for item in config["bootcmd"] if "DEMO_APT_RETRY" in item)
    script = (
        command.split("<<'DEMO_APT_RETRY'\n", 1)[1].split("\nDEMO_APT_RETRY", 1)[0]
        + "\n"
    )
    return config, script


def test_bootstrap_wrapper_and_acquire_settings_have_declared_owners():
    config, script = declared_wrapper()
    files = json.loads((ROOT / "terraform/guest-files.json").read_text())["generator"]
    assert files["/usr/local/bin/demo-apt-retry"] == {
        "sha256": hashlib.sha256(script.encode()).hexdigest(),
        "mode": "0755",
    }
    acquire = (
        'Acquire::Retries "0";\nAcquire::http::Timeout "60";\n'
        'Acquire::https::Timeout "60";\n'
    )
    assert files["/etc/apt/apt.conf.d/80-demo-acquire"] == {
        "sha256": hashlib.sha256(acquire.encode()).hexdigest(),
        "mode": "0644",
    }
    assert config["apt_get_wrapper"] == {
        "enabled": True,
        "command": ["/usr/local/bin/demo-apt-retry"],
    }
    assert 'Acquire::Retries "0";' in config["bootcmd"][0]
    assert config["output"]["all"] == ">> /var/log/cloud-init-output.log"


@pytest.mark.parametrize(
    ("exits", "expected", "attempts", "sleep_status"),
    [
        ([100, 0], 0, 2, 0),
        ([100] * 5, 100, 5, 0),
        ([42], 42, 1, 0),
        ([143], 143, 1, 0),
        ([100], 143, 1, 143),
    ],
)
def test_retry_preserves_arguments_failure_and_interruption(
    tmp_path, exits, expected, attempts, sleep_status
):
    _, script = declared_wrapper()
    wrapper = tmp_path / "demo-apt-retry"
    wrapper.write_text(script)
    wrapper.chmod(0o755)
    calls, sleeps = tmp_path / "calls.jsonl", tmp_path / "sleeps.jsonl"
    executable = tmp_path / "apt-get"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import json,os,sys\nfrom pathlib import Path\n"
        "p=Path(os.environ['APT_CALLS'])\n"
        "count=len(p.read_text().splitlines()) if p.exists() else 0\n"
        "with p.open('a') as f:f.write(json.dumps(sys.argv[1:])+chr(10))\n"
        "raise SystemExit(json.loads(os.environ['APT_EXITS'])[count])\n"
    )
    executable.chmod(0o755)
    sleeper = tmp_path / "sleep"
    sleeper.write_text(
        f"#!{sys.executable}\nimport json,os,sys\n"
        "with open(os.environ['APT_SLEEPS'],'a') as f:"
        "f.write(json.dumps(sys.argv[1:])+chr(10))\n"
        "raise SystemExit(int(os.environ['APT_SLEEP_EXIT']))\n"
    )
    sleeper.chmod(0o755)
    env = dict(os.environ, PATH=str(tmp_path) + os.pathsep + os.environ["PATH"])
    env.update(
        APT_CALLS=str(calls),
        APT_EXITS=json.dumps(exits),
        APT_SLEEPS=str(sleeps),
        APT_SLEEP_EXIT=str(sleep_status),
    )
    argv = ["--assume-yes", "install", "example=1.2+$literal", "space in argument"]
    result = shell(shlex.join([str(wrapper), str(executable), *argv]), env)
    assert result.returncode == expected
    assert [json.loads(line) for line in calls.read_text().splitlines()] == [
        argv
    ] * attempts
    delays = (
        [json.loads(line) for line in sleeps.read_text().splitlines()]
        if sleeps.exists()
        else []
    )
    assert delays == [
        [str(attempt * 5)] for attempt in range(1, attempts + bool(sleep_status))
    ]


def test_missing_command_is_a_failure(tmp_path):
    _, script = declared_wrapper()
    wrapper = tmp_path / "demo-apt-retry"
    wrapper.write_text(script)
    wrapper.chmod(0o755)
    assert shell(shlex.quote(str(wrapper))).returncode == 64
