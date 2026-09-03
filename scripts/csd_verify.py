#!/usr/bin/env python3
# ruff: noqa: D101,D102,D103,D107,EM101,PLR0911,PLR2004,S310,TC003,TRY003
"""Read-only, fail-closed verification of the CSD demo lifecycle."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

VERIFIED = 0
CONFIG_FAILURE = 2
PENDING = 3


@dataclass(frozen=True)
class Evaluation:
    exit_code: int
    reason: str
    evidence: dict[str, Any]


def _normalized_domain(value: Any) -> str:
    text = str(value or "").strip().lower().rstrip(".")
    if "://" in text:
        return (urllib.parse.urlparse(text).hostname or "").rstrip(".")
    return text.split("/", 1)[0].split(":", 1)[0].rstrip(".")


def _timestamp(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        if number > 10_000_000_000:
            number /= 1000
        return int(number)
    text = str(value).strip()
    if text.isdigit():
        return _timestamp(int(text))
    try:
        return int(datetime.fromisoformat(text).timestamp())
    except ValueError:
        return None


def _records(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _records(child)
    elif isinstance(value, list):
        for child in value:
            yield from _records(child)


def _first(record: dict[str, Any], names: set[str]) -> Any:
    for key, value in record.items():
        if key.replace("_", "").lower() in names:
            return value
    return None


def _domain_records(payload: Any, expected: str) -> list[dict[str, Any]]:
    matches = []
    for record in _records(payload):
        candidate = _first(
            record, {"domain", "hostname", "host", "url", "scripturl", "src", "name"}
        )
        if _normalized_domain(candidate) == expected:
            matches.append(record)
    return matches


def _fresh(record: dict[str, Any], since_epoch: int) -> bool:
    value = _first(
        record,
        {
            "lastseen",
            "lastupdated",
            "detectedat",
            "updatedat",
            "timestamp",
            "eventtime",
            "lastobserved",
        },
    )
    parsed = _timestamp(value)
    return parsed is not None and parsed >= since_epoch


def _risk_is_high(record: dict[str, Any]) -> bool:
    value = _first(
        record, {"risk", "risklevel", "classification", "riskclassification"}
    )
    return (
        str(value or "").strip().lower().replace("_", " ").replace("-", " ")
        == "high risk"
    )


def _affected_users(record: dict[str, Any]) -> int:
    value = _first(record, {"affectedusers", "affecteduserscount", "usercount"})
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _counter(payload: Any, name: str) -> int:
    normalized = name.replace("_", "").lower()
    for record in _records(payload):
        value = _first(record, {normalized})
        if value is not None:
            try:
                return int(value)
            except (TypeError, ValueError):
                return 0
    return 0


# This is an ordered evidence decision table; each return preserves the exact
# pending reason that operators need while polling aggregation.
# pylint: disable-next=too-many-return-statements
def evaluate(
    snapshot: dict[str, Any], expected_domain: str, phase: str, since_epoch: int
) -> Evaluation:
    if phase not in {"detection", "mitigation"}:
        raise ValueError("VERIFY_PHASE must be detection or mitigation")
    expected = _normalized_domain(expected_domain)
    if not expected:
        raise ValueError("EXPECTED_DOMAIN must be a hostname")
    config = snapshot.get("config") or {}
    status = snapshot.get("status") or {}
    spec = config.get("spec") if isinstance(config, dict) else None
    configured = isinstance(spec, dict) and spec.get("client_side_defense") is not None
    enabled = (
        isinstance(status, dict)
        and status.get("isConfigured") is True
        and status.get("isEnabled") is True
    )
    if not configured or not enabled:
        return Evaluation(
            CONFIG_FAILURE, "CSD configuration or dataplane status is not enabled", {}
        )
    domain_hits = _domain_records(snapshot.get("detected_domains"), expected)
    script_hits = _domain_records(snapshot.get("scripts"), expected)
    if not domain_hits or not script_hits:
        return Evaluation(
            PENDING,
            "exact expected domain has not appeared in both domain and script telemetry",
            {},
        )
    fresh_scripts = [record for record in script_hits if _fresh(record, since_epoch)]
    if not fresh_scripts:
        return Evaluation(
            PENDING,
            "expected-domain script telemetry is stale or lacks a detection timestamp",
            {},
        )
    high_risk = [record for record in fresh_scripts if _risk_is_high(record)]
    if not high_risk:
        return Evaluation(
            PENDING, "fresh expected-domain script is not classified High Risk", {}
        )
    affected = max((_affected_users(record) for record in high_risk), default=0)
    if affected < 1:
        return Evaluation(
            PENDING, "fresh High Risk script has no affected-user evidence", {}
        )
    evidence = {"expected_domain": expected, "affected_users": affected, "phase": phase}
    if phase == "detection":
        return Evaluation(
            VERIFIED, "fresh High Risk detection has affected-user evidence", evidence
        )
    mitigated = _domain_records(snapshot.get("mitigated_domains"), expected)
    blocked = _counter(snapshot.get("summary"), "blocked_scripts")
    script_blocked = any(
        record.get("blocked") is True
        or str(record.get("action", "")).lower() in {"block", "blocked"}
        for record in high_risk
    )
    if not mitigated or (blocked < 1 and not script_blocked):
        return Evaluation(
            PENDING,
            "mitigation or expected-domain blocking statistics are still pending",
            evidence,
        )
    evidence["blocked_scripts"] = blocked
    return Evaluation(
        VERIFIED,
        "fresh High Risk detection and mitigation blocking are verified",
        evidence,
    )


class ApiClient:
    def __init__(
        self, base_url: str, token: str, namespace: str, load_balancer: str
    ) -> None:
        self.base = base_url.rstrip("/")
        self.token = token
        self.namespace = namespace
        self.load_balancer = load_balancer
        self.csd = (
            f"{self.base}/api/shape/csd/namespaces/{urllib.parse.quote(namespace)}"
        )

    def request(
        self, url: str, *, method: str = "GET", body: dict[str, Any] | None = None
    ) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "Authorization": f"APIToken {self.token}",
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)

    def snapshot(self, since_epoch: int) -> dict[str, Any]:
        now = int(time.time())
        ns = urllib.parse.quote(self.namespace)
        lb = urllib.parse.quote(self.load_balancer)
        return {
            "config": self.request(
                f"{self.base}/api/config/namespaces/{ns}/http_loadbalancers/{lb}?response_format=GET_RSP_FORMAT_DEFAULT"
            ),
            "status": self.request(f"{self.csd}/status"),
            "detected_domains": self.request(f"{self.csd}/detected_domains"),
            "scripts": self.request(
                f"{self.csd}/scripts",
                method="POST",
                body={"startTime": str(since_epoch), "endTime": str(now)},
            ),
            "summary": self.request(f"{self.csd}/summary"),
            "mitigated_domains": self.request(f"{self.csd}/mitigated_domains"),
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-domain", default=os.environ.get("EXPECTED_DOMAIN"))
    parser.add_argument("--phase", default=os.environ.get("VERIFY_PHASE", "detection"))
    parser.add_argument(
        "--since-epoch", type=int, default=os.environ.get("SINCE_EPOCH")
    )
    parser.add_argument(
        "--poll-min", type=int, default=int(os.environ.get("POLL_MIN", "15"))
    )
    parser.add_argument(
        "--namespace", default=os.environ.get("NS", "webapp-api-protection")
    )
    parser.add_argument(
        "--load-balancer", default=os.environ.get("LB", "webapp-api-protection")
    )
    args = parser.parse_args()
    if not args.expected_domain or args.since_epoch is None:
        parser.error("EXPECTED_DOMAIN and SINCE_EPOCH are required")
    if args.poll_min < 0:
        parser.error("POLL_MIN cannot be negative")
    base_url, token = os.environ.get("XCSH_API_URL"), os.environ.get("XCSH_API_TOKEN")
    if not base_url or not token:
        print(
            "CSD verification failed: XCSH_API_URL and XCSH_API_TOKEN are required",
            file=sys.stderr,
        )
        return CONFIG_FAILURE
    client = ApiClient(base_url, token, args.namespace, args.load_balancer)
    deadline = time.monotonic() + args.poll_min * 60
    while True:
        try:
            result = evaluate(
                client.snapshot(args.since_epoch),
                args.expected_domain,
                args.phase,
                args.since_epoch,
            )
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            print(
                f"CSD verification failed: API/authentication/dataplane error ({type(error).__name__})",
                file=sys.stderr,
            )
            return CONFIG_FAILURE
        except ValueError as error:
            print(f"CSD verification failed: {error}", file=sys.stderr)
            return CONFIG_FAILURE
        print(
            json.dumps(
                {
                    "exit_code": result.exit_code,
                    "reason": result.reason,
                    **result.evidence,
                },
                sort_keys=True,
            )
        )
        if result.exit_code != PENDING or time.monotonic() >= deadline:
            return result.exit_code
        time.sleep(60)


if __name__ == "__main__":
    raise SystemExit(main())
