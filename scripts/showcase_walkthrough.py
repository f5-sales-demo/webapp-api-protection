#!/usr/bin/env python3
"""Sequential API-first showcase walkthrough; raw receipts are always private."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import math
import os
import signal
import time
import uuid
from pathlib import Path
from typing import cast

import showcase_walkthrough_dvwa as dvwa
from demo_lifecycle import Lifecycle, _canonical_state
from demo_lifecycle_state import Blocked, secure_artifact
from demo_verify import readiness
from demo_verify_client import Client
from demo_verify_evidence import (
    detection_ready,
    identified_user,
    rate_origin,
    stamp,
    virtual_host,
)
from demo_verify_scope import effective, outputs
from demo_verify_types import EvidenceError
from showcase_walkthrough_config import Configuration, fail, save
from showcase_walkthrough_evidence import (
    LOG_INGESTION_MARGIN,
    access_pages,
    blocked,
    collect,
    matched,
    schema_report,
)

SUCCESS, FORBIDDEN, RATE_DENIAL = 200, 403, 429
MIN_TIMEOUT, MAX_TIMEOUT = 60, 1800
MAX_CLOCK_OFFSET = 5
RATE_BURST_REQUESTS = 90
RATE_BURST_SPACING = 2
CATEGORIES = ("waf", "schema", "endpoint-denial", "rate-limit", "mud")


def interrupted(_number: int, _frame: object) -> None:
    """Signals raise through the restoration path."""
    fail("walkthrough interrupted")


def send(  # pylint: disable=too-many-arguments
    client: Client,
    host: str,
    path: str,
    method: str,
    user: str,
    body: dict | None = None,
    *,
    control: str = "",
    label: str = "",
) -> dict:
    """Record actual request timestamps, payload digest and application JSON."""
    start = time.time()
    code, response = client.request(host, path, method, user, body)
    record = {
        "host": host,
        "path": path.split("?", 1)[0],
        "request_target": path,
        "method": method,
        "user": user,
        "sent_at": start,
        "received_at": time.time(),
        "status": code,
        "body": response,
        "payload_sha256": hashlib.sha256(
            json.dumps(body, sort_keys=True).encode()
        ).hexdigest(),
        "control": control,
        "label": label,
    }
    if hasattr(client, "clock_bounds"):
        record["clock_offset_min"], record["clock_offset_max"] = client.clock_bounds
    if hasattr(client, "walkthrough_directory"):
        journal = client.walkthrough_directory / "requests.jsonl"
        with journal.open("a") as stream:
            stream.write(json.dumps(record) + "\n")
        journal.chmod(0o600)
    return record


# Request loops retain one timestamp and identity for each dispatch.
def requests(  # pylint: disable=too-many-branches
    client: Client, host: str, category: str, prefix: str, enabled: bool
) -> list[dict]:
    """Use independent request identities, with one shared identity per rate burst."""
    result = []
    if category == "schema":
        for label, body in [
            ("valid", {"demo_id": "synthetic-walkthrough"}),
            ("missing", {}),
            ("type", {"demo_id": 7}),
        ]:
            result.append(
                send(
                    client,
                    host,
                    "/httpbin/post",
                    "POST",
                    prefix + "-" + label,
                    cast("dict", body),
                    control="schema" if label != "valid" else "",
                    label=label,
                )
            )
    elif category == "endpoint-denial":
        for method in ("POST", "DELETE"):
            result.append(  # noqa: PERF401 - retain dispatch order and partial receipts
                send(
                    client,
                    host,
                    "/httpbin/anything/admin",
                    method,
                    prefix + "-" + method.lower(),
                    {"demo_id": "synthetic-walkthrough"},
                    control="endpoint-denial",
                    label=method,
                )
            )
        result.append(
            send(
                client,
                host,
                "/httpbin/anything/admin",
                "GET",
                prefix + "-admin-get",
                label="admin-get",
            )
        )
    elif category == "rate-limit":
        for _ in range(RATE_BURST_REQUESTS):
            result.append(
                send(
                    client,
                    host,
                    "/httpbin/anything/rate-limit",
                    "GET",
                    prefix + "-burst",
                    control="rate-limit",
                    label="burst",
                )
            )
            time.sleep(RATE_BURST_SPACING)
        result.append(
            send(
                client,
                host,
                "/httpbin/anything/rate-limit",
                "GET",
                prefix + "-independent",
                label="independent",
            )
        )
    elif category == "mud":
        started = time.time()
        for index in range(20):
            result.append(  # noqa: PERF401 - retain dispatch order and partial receipts
                send(
                    client,
                    host,
                    "/httpbin/get?demo=%27%20OR%201%3D1--",
                    "GET",
                    prefix + "-sequence",
                    control="waf",
                    label="sequence-" + str(index),
                )
            )
        if any(probe["status"] != FORBIDDEN for probe in result):
            fail("MUD sequence requires explicit WAF enforcement responses")
        if enabled:
            # Detection evidence must precede the later benign mitigation request.
            out = client.walkthrough_outputs
            attack = {**result[0], "control": "mud", "attack_started_at": started}
            while True:
                end = time.time()
                events = client.pages(
                    out["namespace"],
                    out["loadbalancer_name"],
                    started,
                    end,
                    user=prefix + "-sequence",
                )
                logs = client.pages(
                    out["namespace"],
                    out["loadbalancer_name"],
                    started,
                    end,
                    suspicious=True,
                    user=prefix + "-sequence",
                )
                if detection_ready(
                    logs,
                    [attack],
                    events,
                    out["namespace"],
                    out["loadbalancer_name"],
                    end,
                ):
                    save(
                        client.walkthrough_directory / "detection.json",
                        {"logs": logs, "events": events, "detected_at": end},
                    )
                    break
                client.remaining()
                time.sleep(min(5, client.remaining()))
        probe = send(
            client,
            host,
            "/httpbin/get",
            "GET",
            prefix + "-sequence",
            control="mud",
            label="later-benign",
        )
        probe["attack_started_at"] = started
        result.append(probe)
        result.append(
            send(
                client,
                host,
                "/httpbin/get",
                "GET",
                prefix + "-independent",
                label="independent",
            )
        )
    else:
        fail(
            "DVWA walkthrough requires authenticated native runner; no substitute accepted"
        )
    result.append(
        send(
            client,
            host,
            "/httpbin/get",
            "GET",
            prefix + "-legitimate",
            label="legitimate",
        )
    )
    if category == "rate-limit" and enabled:
        for probe in result:
            if probe["status"] == SUCCESS:
                rate_origin(
                    probe["status"],
                    probe["body"],
                    host,
                    probe["request_target"],
                    probe["user"],
                )
            elif probe["label"] == "burst" and probe["status"] != RATE_DENIAL:
                fail("unexpected rate burst response")
    for probe in result:
        should_allow = (
            not enabled
            or not probe["control"]
            or (category == "mud" and probe["label"] == "later-benign" and not enabled)
        )
        if should_allow and not (
            category == "mud" and probe["label"].startswith("sequence-")
        ):
            if (
                category == "schema"
                and probe["status"] == SUCCESS
                and probe["path"] == "/httpbin/post"
                and (
                    not isinstance(probe["body"], dict)
                    or probe["body"].get("json")
                    != (
                        {"demo_id": "synthetic-walkthrough"}
                        if probe["label"] == "valid"
                        else {}
                        if probe["label"] == "missing"
                        else {"demo_id": 7}
                    )
                )
            ):
                fail("HTTPBin body echo mismatch")
            rate_origin(
                probe["status"],
                probe["body"],
                host,
                probe["request_target"],
                probe["user"],
            )
    return result


def evaluate(
    client: Client,
    out: dict,
    probes: list[dict],
    category: str,
    enabled: bool,
    directory: Path,
) -> dict:
    """Keep native success, report-only events and enforcement independent."""
    records, events = collect(
        client, out["namespace"], out["loadbalancer_name"], probes
    )
    save(
        directory / ("after-evidence.json" if enabled else "before-evidence.json"),
        {"access_logs": records, "security_events": events},
    )
    required = [
        p
        for p in probes
        if p["control"] and (category != "rate-limit" or p["status"] == RATE_DENIAL)
    ]
    if (
        category == "mud"
        and not enabled
        and not all(
            blocked(
                events,
                matched(records, p, out["namespace"], out["loadbalancer_name"]),
                p,
                out["namespace"],
                out["loadbalancer_name"],
            )
            for p in required
            if p["control"] == "waf"
        )
    ):
        fail("disabled-phase WAF activity attribution missing")
    if enabled:
        if any(p["status"] not in (FORBIDDEN, RATE_DENIAL) for p in required):
            fail("expected enforcement response missing")
        if not required or any(
            not blocked(
                events,
                matched(records, p, out["namespace"], out["loadbalancer_name"]),
                p,
                out["namespace"],
                out["loadbalancer_name"],
            )
            for p in required
        ):
            fail("fresh request-bound control attribution missing")
    elif category == "schema":
        if any(
            not schema_report(
                events,
                matched(records, p, out["namespace"], out["loadbalancer_name"]),
                p["label"],
            )
            for p in required
        ):
            fail("schema-specific report evidence missing")
    if category == "schema" and enabled:
        for probe in required:
            request_id = matched(
                records, probe, out["namespace"], out["loadbalancer_name"]
            )["req_id"]
            event = [e for e in events if e.get("req_id") == request_id]
            # Reuse the schema report validator after removing only the action comparison.
            if not schema_report(
                [{**e, "action": "report"} for e in event],
                {"req_id": request_id},
                probe["label"],
            ):
                fail("specific required-field or type violation missing")
    if category == "mud" and enabled:
        mud = [p for p in probes if p["control"] == "mud"]
        logs = client.pages(
            out["namespace"],
            out["loadbalancer_name"],
            probes[0]["sent_at"],
            time.time(),
            suspicious=True,
            user=mud[0]["user"],
        )
        if not detection_ready(
            logs, mud, events, out["namespace"], out["loadbalancer_name"], time.time()
        ):
            fail("fresh suspicious-user detection missing")
    return {"access_logs": records, "security_events": events}


def calibrate_clock(client: Client, out: dict, prefix: str) -> None:
    """Measure bounded server-log offset using three fresh benign identities."""
    probes = [
        send(
            client,
            out["domains"][0],
            "/httpbin/get",
            "GET",
            prefix + "-clock-" + str(i),
        )
        for i in range(3)
    ]
    for probe in probes:
        rate_origin(
            probe["status"], probe["body"], probe["host"], probe["path"], probe["user"]
        )
    while True:
        records = access_pages(
            client,
            out["namespace"],
            out["loadbalancer_name"],
            probes[0]["sent_at"] - 5,
            probes[-1]["received_at"] + LOG_INGESTION_MARGIN,
        )
        clocks = []
        for probe in probes:
            hits = [
                r
                for r in records
                if r.get("user") == identified_user(probe["user"])
                and r.get("domain") == probe["host"]
                and r.get("req_path") == probe["path"]
                and r.get("namespace") == out["namespace"]
                and r.get("vh_name") == virtual_host(out["loadbalancer_name"])
                and r.get("method") == "GET"
                and r.get("rsp_code") == "200"
            ]
            if len(hits) == 1:
                moment = stamp(hits[0]["time"])
                clocks.append(
                    (moment - probe["received_at"], moment - probe["sent_at"])
                )
        if len(clocks) == len(probes):
            low, high = (
                math.floor(min(c[0] for c in clocks)) - 1,
                math.ceil(max(c[1] for c in clocks)) + 1,
            )
            if not -MAX_CLOCK_OFFSET <= low <= high <= MAX_CLOCK_OFFSET:
                fail("log clock calibration exceeds five-second bound")
            client.clock_bounds = (low, high)
            save(
                client.walkthrough_directory / "clock-calibration.json",
                {
                    "probes": probes,
                    "access_logs": records,
                    "offset_min": low,
                    "offset_max": high,
                },
            )
            return
        client.remaining()
        time.sleep(min(5, client.remaining()))


def prepare_category(
    client: Client,
    args: argparse.Namespace,
    out: dict,
    configuration: Configuration,
    base: str,
    lb: str,
) -> tuple[dict | None, str]:
    """Validate private fixtures and snapshot the resources before stopping traffic."""
    session = None
    if args.category == "waf":
        # Reuse the installed generator's authenticated synthetic session exporter.
        native = client.ssh(
            out["generator"],
            args,
            "sudo -n find /opt/traffic-generator -maxdepth 1 -name fixtures.json",
        )
        if native.strip() != "/opt/traffic-generator/fixtures.json":
            fail("installed private DVWA fixture unavailable")
        fixtures = json.loads(
            client.ssh(
                out["generator"],
                args,
                "sudo -n cat /opt/traffic-generator/fixtures.json",
            )
        )
        session = fixtures.get("dvwa_sessions", {})
        client.command(["node", "-e", "require('playwright')"])
    configuration.capture(lb)
    firewall = base + "app_firewalls/" + out["loadbalancer_name"] + "-waf"
    if args.category == "waf":
        configuration.capture(firewall)
    return session, firewall


def run(args: argparse.Namespace) -> int:  # pylint: disable=too-many-locals,too-many-statements
    # Sequential restoration states remain explicit for recovery review.
    """Verify ownership and effective controls before stopping the owned service."""
    lifecycle = Lifecycle(args)
    lifecycle.preflight(False)
    lifecycle.ownership.inventory(persist=False)
    lifecycle.ownership.verify_fixture()
    out = outputs(lifecycle.context.paths.state / "outputs.json")
    lifecycle.context.state.outputs = out
    showcase_out = out.copy()
    args.ssh_key = str(lifecycle.context.paths.key)
    args.known_hosts = str(lifecycle.context.paths.known_hosts)
    args.poll_seconds = 5
    client = Client(time.monotonic() + args.timeout_seconds)
    effective(client, out)
    ready = readiness(client, out, args)
    raw = json.loads((lifecycle.context.paths.state / "outputs.json").read_text())
    category_key = {"endpoint-denial": "endpoint", "rate-limit": "rate"}.get(
        args.category, args.category
    )
    pairs = raw.get("use_cases", {}).get("value", {}).get(category_key)
    if not isinstance(pairs, dict) or set(pairs) != {"before", "after"}:
        fail("Terraform comparison outputs missing")
    installed = {}
    for role, path in [
        ("origin", "/opt/origin-server/install-receipt.json"),
        ("generator", "/opt/traffic-generator/source-receipt.json"),
    ]:
        installed[role] = json.loads(client.ssh(out[role], args, "sudo -n cat " + path))
        if not installed[role].get("source_commit"):
            fail("installed revision evidence missing")
    run_id = uuid.uuid4().hex
    directory = lifecycle.context.paths.state / ("walkthrough-" + run_id)
    directory.mkdir(mode=0o700)
    client.walkthrough_outputs = out
    client.walkthrough_directory = directory
    configuration = Configuration(client, directory)
    base = "/api/config/namespaces/" + out["namespace"] + "/"
    lb = base + "http_loadbalancers/" + out["loadbalancer_name"]
    report = {
        "receipt_id": run_id,
        "category": args.category,
        "started": time.time(),
        "complete": False,
        "restored": False,
        "installed": installed,
        "readiness_before": ready,
        "source_revision": client.command(["git", "rev-parse", "HEAD"]).strip(),
    }
    stopped = False
    try:
        session, firewall = prepare_category(client, args, out, configuration, base, lb)
        stopped = True
        lifecycle.ownership.traffic("stop")
        status = json.loads(
            client.ssh(out["generator"], args, "sudo -n tgen-control status")
        )
        if status.get("service_active") is not False:
            fail("continuous traffic did not stop")
        calibrate_clock(client, out, "showcase-" + run_id)
        for enabled in (False, True):
            phase = "after" if enabled else "before"
            endpoint = pairs[phase]
            out = {**out, **endpoint, "domains": [endpoint["domain"]]}
            client.walkthrough_outputs = out
            lb = base + "http_loadbalancers/" + out["loadbalancer_name"]
            firewall = base + "app_firewalls/" + out["app_firewall_name"]
            configuration.capture(lb)
            configuration.capture(firewall)
            save(directory / (phase + "-configuration.json"), configuration.current)
            calibrate_clock(client, out, "showcase-" + run_id + "-" + phase)
            prefix = "showcase-" + run_id + "-" + phase
            if args.category == "waf":
                probes = dvwa.requests(
                    client,
                    out["domains"][0],
                    prefix,
                    session.get(out["domains"][0], "")
                    if isinstance(session, dict)
                    else "",
                    enabled,
                )
                marker = next(p for p in probes if p["label"] == "xss")
                save(
                    directory / (phase + "-browser.json"),
                    dvwa.browser_marker(client, marker["body"], enabled, directory),
                )
            else:
                probes = requests(
                    client, out["domains"][0], args.category, prefix, enabled
                )
            save(directory / (phase + "-requests.json"), probes)
            evidence = evaluate(client, out, probes, args.category, enabled, directory)
            save(directory / (phase + "-evidence.json"), evidence)
            report[phase] = {
                "requests": len(probes),
                "status_counts": {
                    str(code): sum(p["status"] == code for p in probes)
                    for code in sorted({p["status"] for p in probes})
                },
            }
        report["complete"] = True
    except (EvidenceError, OSError, ValueError, KeyError) as exc:
        report["error"] = (
            str(exc) if isinstance(exc, EvidenceError) else "private execution failure"
        )
    finally:
        client.deadline = time.monotonic() + 90
        report["restored"] = configuration.restore() if configuration.original else True
        report["finished"] = time.time()
        report["duration_seconds"] = report["finished"] - report["started"]
        report["complete"] = report["complete"] and report["restored"]
        if stopped and report["restored"]:
            client.deadline = time.monotonic() + 120
            try:
                effective(client, showcase_out)
                for host in out["domains"]:
                    probe = send(
                        client,
                        host,
                        "/httpbin/get",
                        "GET",
                        "showcase-" + run_id + "-restored",
                    )
                    rate_origin(
                        probe["status"],
                        probe["body"],
                        host,
                        probe["path"],
                        probe["user"],
                    )
                lifecycle.context.state.deadline = time.monotonic() + 600
                lifecycle.ownership.verify_phase("readiness")
                lifecycle.ownership.traffic("start")
                report["traffic_restarted"] = True
            except (EvidenceError, Blocked, OSError, ValueError, KeyError):
                report["traffic_restarted"] = False
                report["complete"] = False
        save(directory / "receipt.json", report)
    return 0 if report["complete"] else 2


def main() -> int:
    """Parse help before accessing private state or credentials."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("category", choices=CATEGORIES)
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
    try:
        lifecycle = Lifecycle(args)
        _canonical_state(lifecycle)
        lock_path = lifecycle.context.paths.state / "lifecycle.lock"
        secure_artifact(lock_path)
        with lock_path.open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return run(args)
    except (EvidenceError, Blocked, OSError, ValueError, KeyError):
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
