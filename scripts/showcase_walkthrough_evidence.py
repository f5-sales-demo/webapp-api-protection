"""Matched request evidence using existing strict security-event attribution."""

from __future__ import annotations

import json
import time

from demo_verify_client import (
    MAX_PAGES,
    MIN_TELEMETRY_WINDOW,
    PAGE_LIMIT,
    Client,
    _page_batch,
)
from demo_verify_evidence import (
    attributed,
    decode_event,
    identified_user,
    stamp,
    virtual_host,
)
from demo_verify_types import EvidenceError, Probe
from showcase_walkthrough_config import fail, save


def access_pages(
    client: Client, namespace: str, lb: str, start: float, end: float
) -> list[dict]:
    """Require complete bounded pagination, including namespace in the API body."""
    path = "/api/data/namespaces/" + namespace + "/access_logs"
    payload = {
        "namespace": namespace,
        "query": "{vh_name=" + json.dumps(virtual_host(lb)) + "}",
        "start_time": str(min(int(start), int(end) - MIN_TELEMETRY_WINDOW)),
        "end_time": str(int(end) + 1),
        "limit": PAGE_LIMIT,
        "scroll": True,
    }
    code, page = client.api(path, payload)
    result: list[dict] = []
    total = None
    seen: set[str] = set()
    for _ in range(MAX_PAGES):
        batch, count, token = _page_batch(code, page, "logs")
        if total is not None and count != total:
            fail("access-log coverage changed")
        total = count
        result.extend(decode_event(item) for item in batch)
        if len(result) == total:
            return result
        if len(result) > total or not token or not batch:
            fail("incomplete access-log pagination")
        fingerprint = json.dumps(batch, sort_keys=True)
        if fingerprint in seen:
            fail("access-log pagination made no progress")
        seen.add(fingerprint)
        code, page = client.api(
            path + "/scroll", {"namespace": namespace, "scroll_id": token}
        )
    message = "access-log pagination exceeded bound"
    raise EvidenceError(message)


def request_join(event: dict, probe: dict, namespace: str, lb: str) -> bool:
    """Match every actual request; never infer missing records from sampling rates."""
    try:
        return (
            probe["sent_at"] + probe.get("clock_offset_min", 0)
            <= stamp(event["time"])
            <= probe["received_at"] + probe.get("clock_offset_max", 0)
            and event.get("namespace") == namespace
            and event.get("vh_name") == virtual_host(lb)
            and event.get("domain") == probe["host"]
            and event.get("req_path") == probe["path"]
            and event.get("method") == probe["method"]
            and event.get("user") == identified_user(probe["user"])
            and str(event.get("rsp_code")) == str(probe["status"])
        )
    except (EvidenceError, KeyError, TypeError, ValueError):
        return False


def matched(records: list[dict], probe: dict, namespace: str, lb: str) -> dict | None:
    """Require exactly one server request ID; ambiguous attribution is incomplete."""
    matches = {
        r.get("req_id"): r
        for r in records
        if r.get("req_id") and request_join(r, probe, namespace, lb)
    }
    return next(iter(matches.values())) if len(matches) == 1 else None


def blocked(
    events: list[dict], access: dict, probe: Probe, namespace: str, lb: str
) -> bool:
    """Bind control attribution to the actual server-side request ID."""
    return any(
        e.get("req_id") == access["req_id"]
        and attributed(
            e,
            {**probe, "sent_at": probe["sent_at"] + probe.get("clock_offset_min", 0)},
            namespace,
            lb,
            probe["received_at"] + probe.get("clock_offset_max", 0),
        )
        for e in events
    )


def schema_report(events: list[dict], access: dict, label: str) -> bool:
    """Report mode must identify the same invalid request and schema field."""
    return any(
        e.get("req_id") == access["req_id"]
        and e.get("sec_event_name") == "OpenAPI Validation Failure"
        and e.get("oas_req_status") == "OpenAPIViolation"
        and e.get("action") != "block"
        and any(
            v.get("field") == "demo_id"
            and v.get("context") == "Request"
            and v.get("property") == "HTTP Body"
            and (
                (
                    label == "missing"
                    and any(
                        word in str(v.get("description", "")).lower()
                        for word in ("required", "missing")
                    )
                )
                or (
                    label == "type"
                    and "string" in str(v.get("description", "")).lower()
                )
            )
            for v in e.get("violations", [])
            if isinstance(v, dict)
        )
        for e in events
    )


LOG_INGESTION_MARGIN = 10
FORBIDDEN, RATE_DENIAL = 403, 429


def collect(
    client: Client, namespace: str, lb: str, probes: list[dict]
) -> tuple[list[dict], list[dict]]:
    """Poll logs only; never repeat attack requests while waiting for ingestion."""
    start = min(p["sent_at"] + p.get("clock_offset_min", 0) for p in probes)
    end = (
        max(p["received_at"] + p.get("clock_offset_max", 0) for p in probes)
        + LOG_INGESTION_MARGIN
    )
    while True:
        records = access_pages(client, namespace, lb, start, end)
        save(client.walkthrough_directory / "access-log-window.json", records)
        events = client.pages(namespace, lb, start, end)
        save(client.walkthrough_directory / "security-log-window.json", events)
        access_complete = all(matched(records, p, namespace, lb) for p in probes)
        if access_complete:
            required = [
                p
                for p in probes
                if p.get("control")
                and (
                    p["status"] in (FORBIDDEN, RATE_DENIAL) or p["control"] == "schema"
                )
            ]
            ready = all(
                blocked(
                    events, matched(records, p, namespace, lb) or {}, p, namespace, lb
                )
                if p["status"] in (FORBIDDEN, RATE_DENIAL)
                else p["control"] == "schema"
                and schema_report(
                    events, matched(records, p, namespace, lb) or {}, p["label"]
                )
                for p in required
            )
            if ready:
                return records, events
        client.remaining()
        time.sleep(min(5, client.remaining()))
