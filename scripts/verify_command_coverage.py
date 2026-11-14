#!/usr/bin/env python3
"""Join native command behavior and attributed published WAF blocks."""

import argparse
import hashlib
import json
from pathlib import Path

from demo_verify_evidence import identified_user

REPLICA_PORTS = {8101, 8102, 8103, 8104}
PAYLOAD_COUNT = 9
DOMAIN_COUNT = 2
HTTP_OK = 200
HTTP_FORBIDDEN = 403


def verify(native: dict, control: dict, source: dict) -> dict:
    """Reject missing replica payloads, stale source, and generic blocked responses."""
    rows = native.get("checks", [])
    observed = {(row.get("port"), row.get("payload_index")) for row in rows}
    expected = {
        (port, index) for port in REPLICA_PORTS for index in range(PAYLOAD_COUNT)
    }
    requests = control.get("requests", [])
    events = [
        event
        for event in control.get("events", [])
        if event.get("sec_event_type") == "waf_sec_event"
    ]
    domains = {request.get("domain") for request in requests}
    checks = {
        "native_exact_inventory": len(rows) == len(expected) and observed == expected,
        "native_identity_and_outcomes": bool(rows)
        and all(
            row.get("identity") is True
            and row.get("pattern_matches") is True
            and row.get("output_present") is True
            and row.get("status") == HTTP_OK
            for row in rows
        ),
        "immutable_source": native.get("origin_commit") == source["origin_commit"]
        and control.get("source_commit") == source["traffic_commit"]
        and control.get("origin_commit") == source["origin_commit"],
        "published_inventory": len(domains) == DOMAIN_COUNT
        and len(requests) == DOMAIN_COUNT * PAYLOAD_COUNT
        and all(
            sum(request.get("domain") == domain for request in requests)
            == PAYLOAD_COUNT
            for domain in domains
        ),
        "published_blocks": all(
            request.get("status") == HTTP_FORBIDDEN
            and request.get("path") == "/dvwa/vulnerabilities/exec/"
            for request in requests
        ),
        "attributed_request_inventory": len(events) == DOMAIN_COUNT * PAYLOAD_COUNT
        and len({event.get("req_id") for event in events}) == len(events)
        and all(
            event.get("req_id")
            and event.get("action") == "block"
            and event.get("req_path") == "/dvwa/vulnerabilities/exec/"
            and event.get("method") == "POST"
            and str(event.get("rsp_code")) == "403"
            and event.get("user") == identified_user(control["actor"])
            for event in events
        ),
        "both_domains_attributed": all(
            sum(event.get("domain") == domain for event in events) == PAYLOAD_COUNT
            for domain in domains
        ),
    }
    return {
        "passed": all(checks.values()),
        "checks": checks,
        "claim": "native command behavior qualified; published requests blocked by attributed WAF",
        "source": source,
        "catalog_accepted": False,
    }


def main() -> int:
    """Validate private evidence files without live credentials or fabricated responses."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--traffic-commit", required=True)
    parser.add_argument("--origin-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = {
        "traffic_commit": args.traffic_commit,
        "origin_commit": args.origin_commit,
    }
    result = verify(
        json.loads(args.native.read_text()),
        json.loads(args.control.read_text()),
        source,
    )
    result["evidence_sha256"] = {
        "native": hashlib.sha256(args.native.read_bytes()).hexdigest(),
        "control": hashlib.sha256(args.control.read_bytes()).hexdigest(),
    }
    args.output.write_text(json.dumps(result, indent=2))
    args.output.chmod(0o600)
    print(json.dumps({"passed": result["passed"], "checks": result["checks"]}))
    return int(not result["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
