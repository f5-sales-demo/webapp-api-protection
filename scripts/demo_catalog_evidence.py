"""Collect scoped XC evidence on the private Ubuntu operator, never on demo guests."""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING, Any

from demo_verify_client import Client, _page_batch
from demo_verify_evidence import decode_event, identified_user, virtual_host
from demo_verify_types import EvidenceError
from showcase_walkthrough_evidence import bind_ordered_requests, matched

if TYPE_CHECKING:
    from collections.abc import Sequence


OK = 200
PAGE_LIMIT = 500
MAX_PAGES = 20
INGESTION_MARGIN = 60


def access_by_user(
    client: Client, namespace: str, lb: str, user: str, start: float, end: float
) -> list[dict]:
    """Require complete access pagination for one exact synthetic identity."""
    path = "/api/data/namespaces/" + namespace + "/access_logs"
    payload = {
        "namespace": namespace,
        "query": "{vh_name="
        + json.dumps(virtual_host(lb))
        + ",user="
        + json.dumps(identified_user(user))
        + "}",
        "start_time": str(int(start)),
        "end_time": str(int(end) + 1),
        "limit": PAGE_LIMIT,
        "scroll": True,
    }
    code, page = client.api(path, payload)
    records: list[dict] = []
    total = None
    for _ in range(MAX_PAGES):
        batch, count, token = _page_batch(code, page, "logs")
        if total is not None and count != total:
            message = "catalog access pagination changed"
            raise EvidenceError(message)
        total = count
        records.extend(decode_event(item) for item in batch)
        if len(records) == total:
            return records
        if len(records) > total or not token or not batch:
            message = "catalog access pagination incomplete"
            raise EvidenceError(message)
        code, page = client.api(
            path + "/scroll", {"namespace": namespace, "scroll_id": token}
        )
    message = "catalog access pagination exceeded bound"
    raise EvidenceError(message)


def request_checks(
    records: list[dict],
    events: list[dict],
    rows: list[dict],
    namespace: str,
    lb: str,
    bounds: Sequence[float],
) -> list[dict] | None:
    """Require one exact access join and its security records for every request."""
    low, high = bounds
    probes = [
        {
            "host": row["domain"],
            "path": row["path"],
            "method": row["method"],
            "user": row["synthetic_identity"],
            "status": row["status"],
            "sent_at": row["sent_at"],
            "received_at": row["received_at"],
            "clock_offset_min": low,
            "clock_offset_max": high,
        }
        for row in rows
    ]
    bind_ordered_requests(records, probes, namespace, lb)
    checks = []
    for row, probe in zip(rows, probes, strict=True):
        record = matched(records, probe, namespace, lb)
        if record is None:
            return None
        hits = [event for event in events if event.get("req_id") == record["req_id"]]
        if not hits:
            return None
        checks.append({"response": row, "access": record, "events": hits})
    return checks


def evidence_bundle(
    client: Client, pending: dict, out: dict, bounds: Sequence[float]
) -> dict | None:
    """Join actual request times, host, method, user and status to server request IDs."""
    request = pending["request"]
    rows = request["requests"]
    namespace, lb = out["namespace"], out["loadbalancer_name"]
    if not rows or any(
        row.get("domain") not in out["domains"]
        or row.get("scenario") != request["scenario"]
        for row in rows
    ):
        message = "catalog evidence request outside declared scope"
        raise EvidenceError(message)
    low, high = bounds
    start = min(row["sent_at"] for row in rows) + low
    end = max(row["received_at"] for row in rows) + high + INGESTION_MARGIN
    records = []
    events = []
    for user in sorted({row["synthetic_identity"] for row in rows}):
        records.extend(access_by_user(client, namespace, lb, user, start, end))
        events.extend(client.pages(namespace, lb, start, end, user=user))
    checks = request_checks(records, events, rows, namespace, lb, bounds)
    if checks is None:
        return None
    code, firewall = client.api(
        "/api/config/namespaces/" + namespace + "/app_firewalls/" + lb + "-waf"
    )
    if code != OK or not isinstance(firewall, dict):
        message = "catalog effective firewall unavailable"
        raise EvidenceError(message)
    return {
        **pending,
        "evidence": {
            "source_commit": request["source_commit"],
            "artifact_sha256": request["artifact_sha256"],
            "scope": {
                "namespace": namespace,
                "loadbalancer": lb,
                "domain": rows[0]["domain"],
            },
            "clock_bounds": [low, high],
            "firewall": firewall,
            "checks": checks,
            "collected_at": time.time(),
        },
    }


def collect_pending(runtime: Any, ssh: list[str], out: dict, client: Client) -> None:
    """Return scoped evidence over the owned SSH route without transferring API secrets."""
    pending = json.loads(
        runtime.run(
            [
                *ssh,
                "sudo",
                "-n",
                "python3",
                "-B",
                "/opt/traffic-generator/current/scripts/catalog_evidence.py",
                "pending",
            ]
        )[0]
    )
    for item in pending:
        bundle = evidence_bundle(client, item, out, client.clock_bounds)
        if bundle is not None:
            runtime.run(
                [
                    *ssh,
                    "sudo",
                    "-n",
                    "python3",
                    "-B",
                    "/opt/traffic-generator/current/scripts/catalog_evidence.py",
                    "install",
                ],
                input_text=json.dumps(bundle),
            )
