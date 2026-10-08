"""Collect scoped XC evidence on the private Ubuntu operator, never on demo guests."""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote

from demo_verify_client import Client, _page_batch
from demo_verify_evidence import decode_event, identified_user, stamp, virtual_host
from demo_verify_types import EvidenceError
from showcase_walkthrough_evidence import matched

if TYPE_CHECKING:
    from collections.abc import Sequence


OK = 200
PAGE_LIMIT = 500
MAX_PAGES = 20
INGESTION_MARGIN = 60
SMALL_IDENTITY_GROUP = 2
IDENTITY_GROUP_LIMIT = 10
EVENT_RECORDING_DELAY_SECONDS = 20


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


def security_bindings(
    probes: list[dict], events: list[dict], namespace: str, lb: str
) -> dict[int, str] | None:
    """Assign complete ordered security records without reusing a server request."""
    keys = {(p["host"], p["path"], p["method"], p["user"]) for p in probes}
    bindings = {}
    for host, path, method, user in keys:
        group = sorted(
            [
                probe
                for probe in probes
                if (probe["host"], probe["path"], probe["method"], probe["user"])
                == (host, path, method, user)
            ],
            key=lambda probe: probe["sent_at"],
        )
        candidates = {
            event["req_id"]: event
            for event in events
            if event.get("req_id")
            and event.get("domain") == host
            and event.get("req_path") == path
            and event.get("method") == method
            and event.get("user") == identified_user(user)
            and event.get("namespace") == namespace
            and event.get("vh_name") == virtual_host(lb)
        }
        ordered = sorted(candidates.values(), key=lambda event: stamp(event["time"]))
        if len(group) != len(ordered):
            return None
        for probe, event in zip(group, ordered, strict=True):
            if matched([event], probe, namespace, lb) is None:
                return None
            bindings[id(probe)] = event["req_id"]
    return bindings


def request_paths(records: list[dict], rows: list[dict]) -> list[dict]:
    """Match one decoded log route to one exact sent route and retain the raw value."""
    result = []
    for record in records:
        paths = {
            row["path"]
            for row in rows
            if record.get("domain") == row["domain"]
            and record.get("user") == identified_user(row["synthetic_identity"])
            and record.get("req_path") in (row["path"], unquote(row["path"]))
        }
        if len(paths) == 1:
            path = next(iter(paths))
            result.append(
                {**record, "req_path": path, "raw_req_path": record["req_path"]}
            )
        else:
            result.append(record)
    return result


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
    records = request_paths(records, rows)
    events = request_paths(events, rows)
    probes = [
        {
            "host": row["domain"],
            "path": row["path"],
            "method": row["method"],
            "user": row["synthetic_identity"],
            "status": row["status"],
            "sent_at": row["sent_at"],
            "received_at": row["received_at"]
            + (
                EVENT_RECORDING_DELAY_SECONDS
                if row["synthetic_identity"].endswith("-request")
                else 0
            ),
            "clock_offset_min": low,
            "clock_offset_max": high,
        }
        for row in rows
    ]
    bindings = security_bindings(probes, events, namespace, lb)
    if bindings is None:
        return None
    checks = []
    used: set[str] = set()
    for row, probe in zip(rows, probes, strict=True):
        request_id = bindings[id(probe)]
        if request_id in used:
            return None
        used.add(request_id)
        candidates = [
            record for record in records if record.get("req_id") == request_id
        ]
        candidates = [
            {
                **record,
                "method": probe["method"],
                "raw_method": record["method"],
                "method_source_request_id": request_id,
            }
            if record.get("method") == "METHOD_UNSPECIFIED"
            and probe["method"]
            not in {
                "GET",
                "POST",
                "PUT",
                "DELETE",
                "PATCH",
                "HEAD",
                "OPTIONS",
                "CONNECT",
                "TRACE",
            }
            else record
            for record in candidates
        ]
        record = matched(
            candidates,
            {**probe, "server_request_id": request_id},
            namespace,
            lb,
        )
        if record is None and any(
            candidate.get("user") == identified_user(probe["user"])
            for candidate in records
        ):
            return None
        checks.append(
            {
                "response": row,
                "action_id": row.get("action_id"),
                "access": record,
                "security_request_id": request_id,
                "events": [
                    event for event in events if event.get("req_id") == request_id
                ],
            }
        )
    return checks


def grouped_records(
    client: Client,
    namespace: str,
    lb: str,
    users: list[str],
    start: float,
    end: float,
    security: bool,
) -> list[dict]:
    """Collect every page for bounded synthetic identities, then reject prefix collisions."""
    users = [identified_user(user) for user in users]
    key = "events" if security else "logs"
    path = (
        "/api/data/namespaces/"
        + namespace
        + "/"
        + ("app_security/events" if security else "access_logs")
    )
    payload = {
        "namespace": namespace,
        "query": "{vh_name="
        + json.dumps(virtual_host(lb))
        + ",user=~"
        + json.dumps("|".join(sorted(users)))
        + "}",
        "start_time": str(int(start)),
        "end_time": str(int(end) + 1),
        "limit": PAGE_LIMIT,
        "scroll": True,
    }
    code, page = client.api(path, payload)
    records: list[dict] = []
    total = None
    seen = set()
    for _ in range(MAX_PAGES):
        batch, count, token = _page_batch(code, page, key)
        if total is not None and count != total:
            message = "grouped telemetry pagination changed"
            raise EvidenceError(message)
        total = count
        records.extend(decode_event(item) for item in batch)
        if len(records) == total:
            return [row for row in records if row.get("user") in users]
        fingerprint = json.dumps(batch, sort_keys=True)
        if len(records) > total or not token or not batch or fingerprint in seen:
            message = "grouped telemetry pagination incomplete"
            raise EvidenceError(message)
        seen.add(fingerprint)
        code, page = client.api(
            path + "/scroll", {"namespace": namespace, "scroll_id": token}
        )
    message = "grouped telemetry pagination exceeded bound"
    raise EvidenceError(message)


def read_retry(client: Client, reader: Any, *args: Any) -> Any:
    """Retry only known transient read failures; malformed evidence still fails."""
    attempts = 3
    for attempt in range(attempts):
        try:
            return reader(*args)
        except EvidenceError as exc:
            cause = exc.__cause__
            transient = isinstance(cause, OSError) and (
                not hasattr(cause, "code") or cause.code in (429, 503)
            )
            if not transient or attempt == attempts - 1:
                raise
            time.sleep(min(attempt + 1, client.remaining()))
    message = "bounded read retry exhausted"
    raise AssertionError(message)


def identity_records(
    client: Client, namespace: str, lb: str, users: list[str], start: float, end: float
) -> tuple[list[dict], list[dict]]:
    """Read complete bounded identity groups; every failed read rejects the bundle."""
    records: list[dict] = []
    events: list[dict] = []
    if len(users) <= SMALL_IDENTITY_GROUP:
        for user in users:
            records.extend(
                read_retry(
                    client, access_by_user, client, namespace, lb, user, start, end
                )
            )
            events.extend(
                read_retry(
                    client,
                    lambda user=user: client.pages(
                        namespace, lb, start, end, user=user
                    ),
                )
            )
        return records, events
    for offset in range(0, len(users), IDENTITY_GROUP_LIMIT):
        group = users[offset : offset + IDENTITY_GROUP_LIMIT]
        records.extend(
            read_retry(
                client, grouped_records, client, namespace, lb, group, start, end, False
            )
        )
        events.extend(
            read_retry(
                client, grouped_records, client, namespace, lb, group, start, end, True
            )
        )
    return records, events


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
    records, events = identity_records(
        client,
        namespace,
        lb,
        sorted({row["synthetic_identity"] for row in rows}),
        start,
        end,
    )
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
            "event_recording_delay_seconds": EVENT_RECORDING_DELAY_SECONDS,
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
