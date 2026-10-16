#!/usr/bin/env python3
"""Configuration-read-only AI WAF comparison using canonical Terraform outputs."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import signal
import time
import urllib.parse
import uuid
from pathlib import Path

from demo_catalog_clock import calibrate_clock
from demo_lifecycle import Lifecycle, _canonical_state
from demo_lifecycle_state import Blocked, secure_artifact
from demo_verify_client import Client
from demo_verify_types import EvidenceError
from showcase_ai_waf_evidence import (
    SUCCESS,
    evaluate_phase,
    pair_configuration,
    require,
    require_control_difference,
)
from showcase_walkthrough import interrupted, send
from showcase_walkthrough_config import save
from showcase_walkthrough_evidence import access_pages, matched

MIN_TIMEOUT, MAX_TIMEOUT = 60, 1800


def configuration(client: Client, pair: dict) -> dict:
    """Read exact endpoint objects; no configuration API writes are supported."""
    result = {}
    for phase, endpoint in pair.items():
        expected = "ai-waf-" + phase
        require(
            endpoint["domain"] == expected + ".f5-sales-demo.com"
            and endpoint["loadbalancer_name"] == expected,
            "AI Terraform endpoint identity mismatch",
        )
        objects = {}
        for kind, collection, name in (
            ("listener", "http_loadbalancers", endpoint["loadbalancer_name"]),
            ("firewall", "app_firewalls", endpoint["app_firewall_name"]),
            ("identity", "user_identifications", endpoint["user_identification_name"]),
        ):
            code, obj = client.api(
                "/api/config/namespaces/"
                + endpoint["namespace"]
                + "/"
                + collection
                + "/"
                + name
            )
            require(
                code == SUCCESS
                and isinstance(obj, dict)
                and obj.get("metadata", {}).get("name") == name
                and obj.get("metadata", {}).get("namespace") == endpoint["namespace"],
                "AI configuration readback identity mismatch",
            )
            objects[kind] = obj
        result[phase] = {**objects, "names": endpoint}
    pair_configuration(result)
    return result


def probes(client: Client, endpoint: dict, fixture: dict, prefix: str) -> list[dict]:
    """Preserve each fixture with a unique synthetic identity and exact input echo."""
    result = []
    for item in fixture["requests"]:
        path = fixture["path"] + "?" + urllib.parse.urlencode({"input": item["input"]})
        probe = send(
            client,
            endpoint["domain"],
            path,
            "GET",
            prefix + "-" + item["label"],
            control="ai-waf",
            label=item["label"],
        )
        result.append({**probe, "input": item["input"], "kind": item["kind"]})
    return result


def telemetry(
    client: Client, endpoint: dict, requests: list[dict]
) -> tuple[list[dict], list[dict]]:
    """Wait for exact read-only telemetry without replaying workload requests."""
    start = min(p["sent_at"] + p.get("clock_offset_min", 0) for p in requests)
    end = max(p["received_at"] + p.get("clock_offset_max", 0) for p in requests) + 60
    while True:
        access = access_pages(
            client, endpoint["namespace"], endpoint["loadbalancer_name"], start, end
        )
        events = [
            event
            for p in requests
            for event in client.pages(
                endpoint["namespace"],
                endpoint["loadbalancer_name"],
                start,
                end,
                user=p["user"],
            )
        ]
        save(
            client.walkthrough_directory
            / (endpoint["loadbalancer_name"] + "-access.json"),
            access,
        )
        save(
            client.walkthrough_directory
            / (endpoint["loadbalancer_name"] + "-events.json"),
            events,
        )
        if all(
            matched(access, p, endpoint["namespace"], endpoint["loadbalancer_name"])
            is not None
            for p in requests
        ) and all(
            any(event.get("user", "").endswith(p["user"]) for event in events)
            for p in requests
            if p["kind"] == "attack"
        ):
            return access, events
        time.sleep(min(5, client.remaining()))


def run(lifecycle: Lifecycle, timeout: int) -> int:
    """Keep failed receipts and verify immutable configuration after every run."""
    lifecycle.preflight(False)
    client = Client(time.monotonic() + timeout)
    pair = (
        json.loads((lifecycle.context.paths.state / "outputs.json").read_text())
        .get("use_cases", {})
        .get("value", {})
        .get("ai-waf")
    )
    require(
        isinstance(pair, dict) and set(pair) == {"before", "after"},
        "AI Terraform comparison outputs missing",
    )
    fixture_path = (
        lifecycle.context.paths.root / "terraform/fixtures/ai-waf-requests.json"
    )
    fixture_bytes = fixture_path.read_bytes()
    fixture = json.loads(fixture_bytes)
    require(
        fixture.get("schema_version") == 1
        and fixture.get("path") == "/httpbin/anything/ai-waf",
        "immutable AI fixture identity mismatch",
    )
    run_id = uuid.uuid4().hex
    directory = lifecycle.context.paths.state / ("ai-waf-walkthrough-" + run_id)
    directory.mkdir(mode=0o700)
    client.walkthrough_directory = directory
    original = None
    report = {
        "complete": False,
        "restored": False,
        "configuration_read_only": True,
        "fixture_sha256": hashlib.sha256(fixture_bytes).hexdigest(),
        "source_revision": client.command(["git", "rev-parse", "HEAD"]).strip(),
        "receipt_id": run_id,
    }
    try:
        code, addon = client.api(
            "/api/web/namespaces/system/addon_services/f5xc-waap-standard/activation-status"
        )
        require(
            code == SUCCESS and addon.get("state") == "AS_SUBSCRIBED",
            "current WAAP subscription unavailable",
        )
        report["waap_subscription"] = addon["state"]
        original = configuration(client, pair)
        save(directory / "configuration-before.json", original)
        for phase in ("before", "after"):
            endpoint = pair[phase]
            client.walkthrough_outputs = {**endpoint, "domains": [endpoint["domain"]]}
            calibrate_clock(
                client,
                client.walkthrough_outputs,
                "showcase-" + run_id + "-ai-waf-" + phase,
            )
            requests = probes(
                client, endpoint, fixture, "showcase-" + run_id + "-ai-waf-" + phase
            )
            save(directory / (phase + "-requests.json"), requests)
            access, events = telemetry(client, endpoint, requests)
            report[phase] = evaluate_phase(
                access, events, requests, endpoint, phase == "after"
            )
        require_control_difference(report["before"], report["after"])
        report["complete"] = True
    except (EvidenceError, OSError, ValueError, KeyError, TypeError, IndexError) as exc:
        report["error"] = (
            str(exc) if isinstance(exc, EvidenceError) else "private execution failure"
        )
    finally:
        client.deadline = time.monotonic() + 90
        try:
            final = configuration(client, pair)
            save(directory / "configuration-after.json", final)
            report["restored"] = (
                original is not None
                and final == original
                and fixture_path.read_bytes() == fixture_bytes
            )
        except (EvidenceError, OSError, ValueError, KeyError, TypeError, IndexError):
            report["restored"] = False
        report["complete"] = report["complete"] and report["restored"]
        save(directory / "receipt.json", report)
    return 0 if report["complete"] else 2


def main() -> int:
    """Honor the canonical shared deployment lock before reading or probing."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    args = parser.parse_args()
    if not MIN_TIMEOUT <= args.timeout_seconds <= MAX_TIMEOUT:
        parser.error("timeout must be 60-1800 seconds")
    args.operation = "verify"
    os.umask(0o077)
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupted)
    lifecycle = None
    try:
        lifecycle = Lifecycle(args)
        _canonical_state(lifecycle)
        lock_path = lifecycle.context.paths.state / "lifecycle.lock"
        secure_artifact(lock_path)
        with lock_path.open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return run(lifecycle, args.timeout_seconds)
    except (
        EvidenceError,
        Blocked,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        IndexError,
    ) as exc:
        if lifecycle is not None:
            directory = lifecycle.context.paths.state / (
                "ai-waf-preflight-failed-" + uuid.uuid4().hex
            )
            directory.mkdir(mode=0o700)
            save(
                directory / "receipt.json",
                {
                    "complete": False,
                    "configuration_read_only": True,
                    "error_type": type(exc).__name__,
                },
            )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
