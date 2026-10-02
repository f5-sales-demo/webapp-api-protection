"""Fresh synthetic fixtures shared by owner-specific verifier suites."""

from __future__ import annotations

import copy
import json
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
import demo_verify_client as transport
import demo_verify_evidence as evaluation
import demo_verify_types as contracts

USER = "showcase-" + "a" * 32 + "-waf"
DOMAINS = ["www.example.test", "api.example.test"]


def probe(control: str = "waf") -> contracts.Probe:
    return {
        "host": DOMAINS[0],
        "path": "/httpbin/get",
        "method": "GET",
        "user": USER,
        "sent_at": 100,
        "control": control,
    }


def event() -> dict[str, Any]:
    return {
        "namespace": "demo",
        "vh_name": evaluation.virtual_host("demo-lb"),
        "domain": DOMAINS[0],
        "req_path": "/httpbin/get",
        "method": "GET",
        "user": evaluation.identified_user(USER),
        "time": "1970-01-01T00:01:41Z",
        "sec_event_type": "waf_sec_event",
        "sec_event_name": "WAF",
        "app_firewall_name": "demo-lb-waf",
        "action": "block",
        "signatures": [{"id": "200002883", "state": "Enabled"}],
    }


def runs() -> tuple[dict[str, Any], float]:
    start = time.time() - 400
    run: dict[str, Any] = {
        "run_id": "a" * 32,
        "sequence": 0,
        "trigger": "scheduled",
        "status": "verified",
        "failures": [],
        "started_epoch": start,
        "started_at": datetime.fromtimestamp(start, UTC).isoformat(),
        "completed_at": datetime.fromtimestamp(start + 30, UTC).isoformat(),
        "domains": DOMAINS,
        "count": 1500,
        "rate": 50,
        "duration_seconds": 30,
        "transport_errors": 0,
        "benign_success": 1,
        "latencies": {
            "min": 1_000_000,
            "mean": 6_000_000,
            "50th": 5_000_000,
            "90th": 9_000_000,
            "95th": 10_000_000,
            "99th": 20_000_000,
            "max": 25_000_000,
        },
        "class_counts": {
            "benign": 1350,
            "waf": 30,
            "schema": 30,
            "endpoint-denial": 30,
            "rate-limit": 30,
            "mud": 30,
        },
        "security_evidence_scope": "measurement only; fresh control attribution required",
        "rate_outcomes": {
            domain: {
                "status_counts": {"200": 15},
                "429_count": 0,
                "rate_denial_observed": False,
            }
            for domain in DOMAINS
        },
    }
    later = copy.deepcopy(run)
    later.update(
        run_id="b" * 32,
        sequence=1,
        started_epoch=start + 300,
        started_at=datetime.fromtimestamp(start + 300, UTC).isoformat(),
        completed_at=datetime.fromtimestamp(start + 330, UTC).isoformat(),
    )
    return {**later, "timer_active": True, "history": [run, later]}, start - 1


def client():
    with patch.dict(
        os.environ,
        {
            "XCSH_API_URL": "https://console.example.test",
            "XCSH_API_TOKEN": "SECRET",
        },
    ):
        return transport.Client(time.monotonic() + 2)


def mud_fixture() -> dict[str, Any]:
    return json.loads(
        (Path(__file__).parent / "fixtures/demo_mud_detection.json").read_text()
    )


def mud_evidence() -> tuple[Any, contracts.Probe, dict[str, Any]]:
    fixture = mud_fixture()
    request = probe("mud")
    request.update(user="showcase-" + "a" * 32 + "-d0-mud", attack_started_at=100)
    record = dict(event(), user=evaluation.identified_user(request["user"]))
    return fixture["logs"][0], request, record


def continuous_status(status):
    """Translate synthetic legacy timings into complete continuous catalog fixture evidence."""
    history = status.get("history", [])
    if len(history) < 2:
        return {**status, "catalog_passes": []}
    now = time.time()
    start = (
        history[0]["started_epoch"]
        if isinstance(history[0].get("started_epoch"), (float, int))
        else now - 60
    )
    return {
        **status,
        "service_active": True,
        "service_enabled": True,
        "heartbeat": now,
        "catalog_passes": [
            {
                "id": "pass-fixture-a",
                "complete": True,
                "passed": True,
                "started": start,
            },
            {
                "id": "pass-fixture-b",
                "complete": True,
                "passed": True,
                "started": now - 1,
            },
        ],
        "rates": {
            "elapsed": 30,
            "benign_requests": 5400,
            "benign_success": 5400,
            "attack_requests": 600,
            "benign_transport_failures": 0,
            "attack_transport_failures": 0,
            "benign_per_domain": dict.fromkeys(DOMAINS, 2700),
        },
        "failures": [],
    }


def readiness_client(cloud_status="done", returned_host=None, returned_path="/get"):
    client = Mock()
    client.ssh.side_effect = [
        json.dumps({"status": cloud_status, "errors": [], "recoverable_errors": {}}),
        "Result=success\nExecMainStatus=0\n",
        json.dumps({"status": "done", "errors": [], "recoverable_errors": {}}),
        "Result=success\nExecMainStatus=0\n",
        json.dumps(
            {
                "schema_version": 1,
                "ready": True,
                "checks": [{"name": "httpbin-1", "ready": True}],
            }
        ),
    ]
    client.request.side_effect = [
        (200, {"url": "http://" + (returned_host or domain) + returned_path})
        for domain in DOMAINS
    ]
    return client


def azure_retry_status() -> dict[str, Any]:
    # Sanitized current origin capture: one retained warning per stage.
    warning = (
        "Polling IMDS failed attempt 1 with exception: UrlError('404 Client Error: "
        "Not Found for url: http://169.254.169.254/metadata/reprovisiondata?"
        "api-version=2019-06-01')"
    )
    report: dict[str, Any] = {
        "datasource": "azure",
        "status": "done",
        "extended_status": "degraded done",
        "stage": None,
        "errors": [],
        "recoverable_errors": {"WARNING": [warning] * 4},
    }
    for name, start, finish in (
        ("init", 1886.32, 1890.04),
        ("init-local", 7.11, 1883.94),
        ("modules-config", 1890.69, 1891.2),
        ("modules-final", 1892.26, 2979.35),
    ):
        report[name] = {
            "errors": [],
            "start": start,
            "finished": finish,
            "recoverable_errors": {"WARNING": [warning]},
        }
    return report


def effective_fixture(challenge="enable_challenge"):
    # Allowlisted shape observed on the rebuilt LB, not provider HCL nesting.
    def ref(name):
        return {"tenant": "demo-tenant", "namespace": "demo", "name": name}

    spec = {
        "domains": DOMAINS,
        "enable_api_discovery": {"default_api_auth_discovery": {}},
        "enable_malicious_user_detection": {},
        challenge: {"malicious_user_mitigation": ref("demo-mud")},
        "user_identification": ref("demo-userid"),
        "app_firewall": ref("demo-waf"),
        "api_specification": {
            "api_definition": ref("demo-api"),
            "validation_all_spec_endpoints": {
                "validation_mode": {
                    "validation_mode_active": {
                        "enforcement_block": {},
                        "request_validation_properties": [
                            "PROPERTY_HTTP_BODY",
                            "PROPERTY_CONTENT_TYPE",
                        ],
                    },
                    "skip_response_validation": {},
                }
            },
        },
        "api_rate_limit": {
            "no_ip_allowed_list": {},
            "server_url_rules": [],
            "api_endpoint_rules": [
                {
                    "any_domain": {},
                    "base_path": "",
                    "api_endpoint_path": "/httpbin/anything/rate-limit",
                    "api_endpoint_method": {
                        "methods": ["GET"],
                        "invert_matcher": False,
                    },
                    "request_matcher": None,
                    "client_matcher": None,
                    "inline_rate_limiter": {
                        "threshold": 20,
                        "unit": "MINUTE",
                        "use_http_lb_user_id": {},
                    },
                }
            ],
        },
    }
    responses = [
        (200, {"metadata": {"name": "demo-lb", "namespace": "demo"}, "spec": spec}),
        (
            200,
            {
                "spec": {
                    "blocking": {},
                    "blocking_page": {
                        "response_code": "Forbidden",
                        "blocking_page": "string:///PCFkb2N0eXBlIGh0bWw+PGh0bWw+PGJvZHk+"
                        "UmVxdWVzdCBSZWplY3RlZDwvYm9keT48L2h0bWw+",
                    },
                }
            },
        ),
        (200, {"spec": {"rules": [{"http_header_name": "X-MUD-User"}]}}),
        (
            200,
            {
                "spec": {
                    "mitigation_type": {
                        "rules": [
                            {
                                "threat_level": {level: {}},
                                "mitigation_action": {"block_temporarily": {}},
                            }
                            for level in ("low", "medium", "high")
                        ]
                    }
                }
            },
        ),
    ]
    client = Mock()
    client.api.side_effect = responses
    out = {"namespace": "demo", "loadbalancer_name": "demo-lb", "domains": DOMAINS}
    return client, out, spec, responses


def rate_event(probe):
    policy_set = "ves-io-http-loadbalancer-rate-limiting-demo-lb"
    return dict(
        event(),
        req_path=probe["path"],
        user=evaluation.identified_user(probe["user"]),
        sec_event_type="api_sec_event",
        sec_event_name="API Rate Limiting",
        rsp_code="429",
        policy_hits={
            "policy_hits": [
                {
                    "rate_limiter_action": "fail",
                    "rate_limiter_user_id": evaluation.identified_user(probe["user"]),
                    "result": "rate_limiter_drop",
                    "policy_namespace": "demo",
                    "policy_set": policy_set,
                    "policy": policy_set + "-api-endpoint",
                    "policy_rule": policy_set + "-api-endpoint-rule-0",
                }
            ]
        },
    )


def rate_client(statuses):
    client = Mock(deadline=time.monotonic() + 100)
    codes = iter(statuses)

    def respond(host, path, method, user):
        code = next(codes)
        return code, {
            "url": "http://" + host + path.removeprefix("/httpbin"),
            "headers": {"X-Mud-User": user},
        } if code == 200 else None

    client.request.side_effect = respond
    return client
