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
    _event_join,
    attributed,
    decode_event,
    identified_user,
    rate_origin,
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
        if r.get("req_id")
        and (
            not probe.get("server_request_id")
            or r["req_id"] == probe["server_request_id"]
        )
        and request_join(r, probe, namespace, lb)
    }
    return next(iter(matches.values())) if len(matches) == 1 else None


def successful_rate_burst(probe: dict) -> bool:
    """Recognize only the successful native endpoint-limiter burst response."""
    return (
        probe.get("control") == "rate-limit"
        and probe.get("label") == "burst"
        and probe.get("method") == "GET"
        and probe.get("status") == SUCCESS
        and probe.get("path") == "/httpbin/anything/rate-limit"
    )


def bind_ordered_requests(
    records: list[dict], probes: list[dict], namespace: str, lb: str
) -> None:
    """Bind a fresh sequential identity only when every request has one log record."""
    keys = {
        (p["host"], p["path"], p["method"], p["user"], str(p["status"])) for p in probes
    }
    for key in keys:
        group = sorted(
            (
                p
                for p in probes
                if (p["host"], p["path"], p["method"], p["user"], str(p["status"]))
                == key
            ),
            key=lambda p: p["sent_at"],
        )
        logs = [
            r
            for r in records
            if (
                r.get("domain"),
                r.get("req_path"),
                r.get("method"),
                r.get("user"),
                str(r.get("rsp_code")),
            )
            == (*key[:3], identified_user(key[3]), key[4])
            and r.get("namespace") == namespace
            and r.get("vh_name") == virtual_host(lb)
        ]
        if all(
            p.get("control") == "rate-limit" and p.get("label") == "burst"
            for p in group
        ):
            group = [p for p in group if p["status"] == RATE_DENIAL]
            logs = [r for r in logs if str(r.get("rsp_code")) == str(RATE_DENIAL)]
        logs = sorted(
            {r["req_id"]: r for r in logs if r.get("req_id")}.values(),
            key=lambda r: stamp(r["time"]),
        )
        if len(logs) != len(group):
            continue
        if all(
            request_join(r, p, namespace, lb) for r, p in zip(logs, group, strict=True)
        ):
            for record, probe in zip(logs, group, strict=True):
                probe["server_request_id"] = record["req_id"]


def control_anchor(
    records: list[dict],
    events: list[dict],
    probe: dict,
    namespace: str,
    lb: str,
) -> dict | None:
    """Use actual access or uniquely matched rate security evidence, never a fake log."""
    record = matched(records, probe, namespace, lb)
    if record is not None:
        return {**record, "evidence_source": "access_log"}
    if probe.get("control") != "rate-limit" or probe.get("status") != RATE_DENIAL:
        return None
    record = matched(events, probe, namespace, lb)
    return (
        {**record, "evidence_source": "security_event"} if record is not None else None
    )


def blocked(
    events: list[dict], access: dict, probe: Probe, namespace: str, lb: str
) -> bool:
    """Bind control attribution to the actual server-side request ID."""
    if probe.get("control") == "waf" and probe.get("label") == "xss":
        return any(
            e.get("req_id") == access["req_id"]
            and _event_join(
                e,
                {
                    **probe,
                    "sent_at": probe["sent_at"] + probe.get("clock_offset_min", 0),
                },
                namespace,
                lb,
                probe["received_at"] + probe.get("clock_offset_max", 0),
            )
            and e.get("sec_event_type") == "waf_sec_event"
            and e.get("sec_event_name") == "WAF"
            and e.get("app_firewall_name") == lb + "-waf"
            and any(
                str(sig.get("id")) in {"200000098", "200001475", "200015119"}
                and sig.get("state") == "Enabled"
                for sig in e.get("signatures", [])
            )
            for e in events
        )
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


LOG_INGESTION_MARGIN = 60
FORBIDDEN, RATE_DENIAL = 403, 429


SUCCESS = 200


def read_only_retryable(probe: dict) -> bool:
    """Only read-only native HTTPBin negative controls may get fresh identities."""
    return (
        probe.get("method") == "GET"
        and probe.get("status") == SUCCESS
        and not probe.get("control")
        and probe.get("path", "").startswith("/httpbin/")
        and probe.get("label") in {"legitimate", "independent", "admin-get"}
    )


def collect(
    client: Client, namespace: str, lb: str, probes: list[dict]
) -> tuple[list[dict], list[dict]]:
    """Poll logs only; never repeat attack requests while waiting for ingestion."""
    start = min(p["sent_at"] + p.get("clock_offset_min", 0) for p in probes)
    retry_state = {"started": time.monotonic(), "attempts": 0}
    while True:
        end = (
            max(p["received_at"] + p.get("clock_offset_max", 0) for p in probes)
            + LOG_INGESTION_MARGIN
        )
        records = access_pages(client, namespace, lb, start, end)
        save(client.walkthrough_directory / "access-log-window.json", records)
        users = sorted({probe["user"] for probe in probes if probe.get("control")})
        events = [
            event
            for user in users
            for event in client.pages(namespace, lb, start, end, user=user)
        ]
        save(client.walkthrough_directory / "security-log-window.json", events)
        denial_events = [
            event
            for event in events
            if event.get("sec_event_name") == "API Rate Limiting"
        ]
        bind_ordered_requests(
            denial_events,
            [
                p
                for p in probes
                if p.get("control") == "rate-limit" and p.get("status") == RATE_DENIAL
            ],
            namespace,
            lb,
        )
        bind_ordered_requests(records, probes, namespace, lb)
        for probe in probes:
            if successful_rate_burst(probe):
                rate_origin(
                    probe["status"],
                    probe["body"],
                    probe["host"],
                    probe["request_target"],
                    probe["user"],
                )
        access_complete = all(
            successful_rate_burst(p)
            or control_anchor(records, events, p, namespace, lb)
            for p in probes
        )
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
                    events,
                    control_anchor(records, events, p, namespace, lb) or {},
                    p,
                    namespace,
                    lb,
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
        if hasattr(client, "legitimate_sampler"):
            client.legitimate_sampler(
                client, probes, records, namespace, lb, retry_state
            )
        client.remaining()
        time.sleep(min(5, client.remaining()))
