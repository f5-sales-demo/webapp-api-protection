"""Continuous display traffic preserves scope, payload, origin identity and failures."""

import base64
import copy
import hashlib
import io
import json
import threading
import urllib.error
import urllib.parse
from email.message import Message
from http.client import IncompleteRead
from unittest.mock import Mock, patch

import demo_ai_traffic as traffic
import pytest
from demo_traffic_fixtures import ROOT, azure_custom_data, rendered_cloud_config


def inputs(tmp_path):
    raw = (ROOT / "terraform/fixtures/ai-waf-traffic.json").read_bytes()
    fixture = tmp_path / "fixture.json"
    fixture.write_bytes(raw)
    config = {
        "schema_version": 1,
        "hosts": traffic.HOSTS.copy(),
        "aggregate_rps": 2,
        "fixture_sha256": hashlib.sha256(raw).hexdigest(),
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config))
    return path, fixture, config, json.loads(raw)


@pytest.mark.parametrize(
    "mutation", ["host", "rate", "hash", "path", "partial", "duplicate", "label"]
)
def test_substitution_fails_before_network_access(tmp_path, mutation):
    config_path, fixture_path, config, fixture = inputs(tmp_path)
    if mutation == "host":
        config["hosts"]["before"] = "www.f5-sales-demo.com"
    elif mutation == "rate":
        config["aggregate_rps"] = 200
    elif mutation == "hash":
        config["fixture_sha256"] = "0" * 64
    else:
        if mutation == "path":
            fixture["path"] = "//foreign.example.test/"
        elif mutation == "partial":
            fixture["requests"].pop()
        elif mutation == "duplicate":
            fixture["requests"][-1] = copy.deepcopy(fixture["requests"][0])
        else:
            fixture["requests"][0]["label"] = "../outside"
        fixture_path.write_text(json.dumps(fixture))
        config["fixture_sha256"] = hashlib.sha256(fixture_path.read_bytes()).hexdigest()
    config_path.write_text(json.dumps(config))
    with (
        patch("demo_ai_traffic.urllib.request.build_opener") as network,
        pytest.raises(ValueError, match="AI traffic"),
    ):
        traffic.load(config_path, fixture_path)
    network.assert_not_called()


class NativeResponse(io.BytesIO):
    def __init__(self, raw, code):
        super().__init__(raw)
        self.code = code


def response(raw, code=200):
    return NativeResponse(raw, code)


def echo(req):
    url = urllib.parse.urlsplit(req.full_url)
    return {
        "method": "GET",
        "args": {"input": urllib.parse.parse_qs(url.query)["input"][0]},
        "url": urllib.parse.urlunsplit(
            url._replace(path=url.path.removeprefix("/httpbin"))
        ),
        "headers": {"Host": url.hostname, "X-Mud-User": req.get_header("X-mud-user")},
    }


def test_all_native_payloads_preserved_on_both_hosts_and_false_positive_contrast(
    tmp_path,
):
    config_path, fixture_path, _, fixture = inputs(tmp_path)
    traffic.load(config_path, fixture_path)
    identities = set()
    for item in fixture["requests"]:
        for phase, host in traffic.HOSTS.items():
            http = Mock()

            def native(req, timeout, item=item, phase=phase):
                assert timeout == 20
                assert urllib.parse.parse_qs(
                    urllib.parse.urlsplit(req.full_url).query
                ) == {"input": [item["input"]]}
                identities.add(req.get_header("X-mud-user"))
                code = item["expected_status"][phase]
                if code == 403:
                    raise urllib.error.HTTPError(
                        req.full_url, 403, "blocked", Message(), io.BytesIO(b"blocked")
                    )
                return response(json.dumps(echo(req)).encode())

            http.open.side_effect = native
            result = traffic.request(http, host, phase, item, fixture["path"], "a" * 32)
            assert result["expected_response"] is True
            assert result["transport_failure"] is False
            assert result["response_sha256"]
            assert result["request_target"] == fixture[
                "path"
            ] + "?" + urllib.parse.urlencode({"input": item["input"]})
    assert len(identities) == 36


@pytest.mark.parametrize("mutation", ["host", "user", "path", "input", "method"])
def test_http_200_with_wrong_response_identity_fails(tmp_path, mutation):
    _, _, _, fixture = inputs(tmp_path)
    item = next(row for row in fixture["requests"] if row["kind"] == "benign")
    http = Mock()

    def native(req, **_kwargs):
        body = echo(req)
        if mutation == "host":
            body["headers"]["Host"] = "other.example.test"
        elif mutation == "user":
            body["headers"]["X-Mud-User"] = "other"
        elif mutation == "path":
            body["url"] = body["url"].replace("/anything/ai-waf", "/other")
        elif mutation == "input":
            body["args"]["input"] = "other"
        else:
            body["method"] = "POST"
        return response(json.dumps(body).encode())

    http.open.side_effect = native
    record = traffic.request(
        http, traffic.HOSTS["before"], "before", item, fixture["path"], "b" * 32
    )
    assert record["status"] == 200
    assert record["expected_response"] is False


def test_transport_timeout_and_redirect_are_never_success(tmp_path):
    _, _, _, fixture = inputs(tmp_path)
    item = fixture["requests"][0]
    http = Mock()
    http.open.side_effect = TimeoutError()
    record = traffic.request(
        http, traffic.HOSTS["after"], "after", item, fixture["path"], "c" * 32
    )
    assert record["transport_failure"] is True
    assert record["expected_response"] is False
    assert traffic.NoRedirect().redirect_request(None) is None


def test_stop_retains_real_counters_and_bounded_journal(tmp_path):
    _, _, config, fixture = inputs(tmp_path)
    stopping = threading.Event()

    def observed(_http, host, phase, item, path, rotation):
        stopping.set()
        return {
            "phase": phase,
            "label": item["label"],
            "status": 0,
            "transport_failure": True,
            "expected_response": False,
            "received_at": 1,
            "rotation": rotation,
            "host": host,
            "request_target": path,
        }

    with patch("demo_ai_traffic.request", side_effect=observed):
        traffic.run(config, fixture, tmp_path / "state", stopping)
    status = json.loads((tmp_path / "state/status.json").read_text())
    assert status["running"] is False
    assert status["requests"] == status["transport_failures"] == 1
    assert status["catalog_acceptance"] is False
    assert status["ai_attribution_accepted"] is False
    assert status["rotations"] == 0
    assert (tmp_path / "state/requests.jsonl").stat().st_mode & 0o777 == 0o600


def test_cloud_init_declares_exact_artifacts_provisions_stopped_and_fits_azure():
    template, data = rendered_cloud_config()
    azure_custom_data(template.encode())
    files = {row["path"]: row for row in data["write_files"]}
    for destination, source in {
        "/usr/local/lib/demo-ai-traffic.py": "scripts/demo_ai_traffic.py",
        "/etc/demo-ai-traffic/fixture.json": "terraform/fixtures/ai-waf-traffic.json",
    }.items():
        assert (
            base64.b64decode(files[destination]["content"])
            == (ROOT / source).read_bytes()
        )
    service = files["/etc/systemd/system/demo-ai-traffic.service"]["content"]
    assert "ExecStartPre=" in service
    assert "--check" in service
    assert "StateDirectory=demo-ai-traffic" in service
    assert "TimeoutStopSec=30" in service
    assert "systemctl disable --now demo-ai-traffic.service" in template
    assert "systemctl enable --now demo-ai-traffic.service" not in template


def test_incomplete_http_body_is_a_transport_failure(tmp_path):
    _, _, _, fixture = inputs(tmp_path)
    http = Mock()
    http.open.side_effect = IncompleteRead(b"partial", 20)
    item = fixture["requests"][0]
    record = traffic.request(
        http, traffic.HOSTS["after"], "after", item, fixture["path"], "d" * 32
    )
    assert record["transport_failure"] is True
    assert record["expected_response"] is False
    assert record["error_type"] == "IncompleteRead"


def test_guest_manifest_binds_all_four_ai_artifacts():
    _, data = rendered_cloud_config()
    files = {row["path"]: row for row in data["write_files"]}
    manifest = json.loads((ROOT / "terraform/guest-files.json").read_text())[
        "generator"
    ]
    for destination in (
        "/usr/local/lib/demo-ai-traffic.py",
        "/etc/demo-ai-traffic/fixture.json",
        "/etc/demo-ai-traffic/config.json",
        "/etc/systemd/system/demo-ai-traffic.service",
    ):
        row = files[destination]
        raw = (
            base64.b64decode(row["content"])
            if row.get("encoding") == "b64"
            else row["content"].encode()
        )
        assert manifest[destination] == {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "mode": row["permissions"],
        }
