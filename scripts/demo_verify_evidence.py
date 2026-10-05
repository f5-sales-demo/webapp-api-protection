"""Pure, fail-closed evidence evaluation; synthetic fixtures are not live proof."""

from __future__ import annotations

import json
import math
import re
import time
import urllib.parse
from datetime import datetime
from typing import TYPE_CHECKING, Any, TypeGuard

from demo_traffic import evaluate_summary, scheduled_pair
from demo_verify_types import EvidenceError

if TYPE_CHECKING:
    from demo_verify_types import CloudDiagnostic, Probe, TrafficFailure

NAME = re.compile(r"^[a-z][a-z0-9-]{0,62}[a-z0-9]$")
SYNTHETIC = re.compile(
    r"^(?:showcase-[0-9a-f]{32}-[a-z0-9-]+|"
    r"(?:benign|waf|schema|endpoint-denial|rate-limit|mud)-[0-9a-f]{32}(?:-[0-9]+)?)$"
)
RUN_ID = re.compile(r"[0-9a-f]{32}")
RFC3339 = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})"
)
MAX_EVENT_BYTES = 100_000
CLOCK_SKEW = 2
PAIR_LENGTH = 2
DURATION_TOLERANCE = 0.5
RATE_DENIAL = 429
HTTP_SUCCESS = 200
HTTP_PORT = 80
ERROR_CLASSES = frozenset(
    {
        "configuration",
        "authorization",
        "tool_missing",
        "metrics_unavailable",
        "metrics_failed",
        "readiness_failed",
        "attack_failed",
    }
)
ACTIVITY_COUNTERS = (
    "bot_defense_sec_event_count",
    "err_count",
    "failed_login_count",
    "forbidden_access_count",
    "page_not_found_count",
    "rate_limiting_count",
    "req_count",
    "waf_sec_event_count",
)
MITIGATION_COUNTERS = (
    "mum_captcha_challenge",
    "mum_js_challenge",
    "mum_temporarily_blocking",
)
AZURE_REPROVISION_WARNING = (
    "Polling IMDS failed attempt 1 with exception: UrlError('404 Client Error: "
    "Not Found for url: http://169.254.169.254/metadata/reprovisiondata?"
    "api-version=2019-06-01')"
)
CLOUD_STAGES = ("init", "init-local", "modules-config", "modules-final")
CLOUD_INIT_SOURCES = [
    "https://cloudinit.readthedocs.io/en/latest/reference/cli.html#status",
    "https://github.com/canonical/cloud-init/blob/26.1/cloudinit/sources/azure/imds.py",
    "https://github.com/canonical/cloud-init/blob/26.1/cloudinit/sources/DataSourceAzure.py",
]


def stamp(value: Any) -> float:
    """Parse finite epoch or timezone-qualified timestamp evidence."""
    message = "invalid timestamp"
    if isinstance(value, bool):
        raise EvidenceError(message)
    try:
        if isinstance(value, (int, float)) or str(value).isdigit():
            result = float(value)
        else:
            parsed = datetime.fromisoformat(str(value))
            if parsed.tzinfo is None:
                timezone_message = "timestamp lacks timezone"
                raise EvidenceError(timezone_message)
            result = parsed.timestamp()
        if not math.isfinite(result):
            raise EvidenceError(message)
    except (ValueError, TypeError, OverflowError) as exc:
        raise EvidenceError(message) from exc
    return result


def guest_ready(report: Any) -> bool:
    """Require every actual guest check, including each replica, to be ready."""
    if not isinstance(report, dict):
        return False
    checks = report.get("checks")
    return (
        report.get("schema_version") == 1
        and report.get("ready") is True
        and isinstance(checks, list)
        and bool(checks)
        and all(
            isinstance(c, dict)
            and c.get("name")
            and c.get("ready") is True
            and not c.get("skipped")
            for c in checks
        )
    )


def _fresh_terminal(run: Any, since: float) -> bool:
    if not isinstance(run, dict) or run.get("trigger") != "scheduled":
        return False
    try:
        return stamp(run["started_epoch"]) >= since and run.get("status") not in (
            "pending",
            "running",
        )
    except (KeyError, EvidenceError):
        return False


def traffic_failure(
    status: Any, domains: list[str], since: float
) -> TrafficFailure | None:
    """Surface every fresh terminal scheduled failure, including missing metrics."""
    if not isinstance(status, dict) or not isinstance(status.get("history"), list):
        return None
    for run in status["history"]:
        if not _fresh_terminal(run, since):
            continue
        failures = evaluate_summary(run, domains)
        if run.get("status") == "verified" and not failures:
            continue
        rid, error = run.get("run_id"), run.get("error_class")
        return {
            "run_id": rid
            if isinstance(rid, str) and RUN_ID.fullmatch(rid)
            else "invalid_run_id",
            "error_class": error
            if isinstance(error, str) and error in ERROR_CLASSES
            else "metrics_failed",
            "metric_failures": failures,
        }
    return None


def _measurement_fresh(
    run: dict[str, Any], domains: list[str], since: float, now: float
) -> bool:
    start, finish = stamp(run["started_epoch"]), stamp(run["completed_at"])
    return (
        start >= since
        and finish - start >= run["duration_seconds"] - DURATION_TOLERANCE
        and finish <= now + CLOCK_SKEW
        and abs(stamp(run["started_at"]) - start) <= CLOCK_SKEW
        and not evaluate_summary(run, domains)
    )


def _nonnegative_integer(value: Any) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _traffic_pair(
    status: dict[str, Any], domains: list[str], since: float, now: float
) -> bool:
    history = status.get("history")
    if (
        not isinstance(history, list)
        or len(history) < PAIR_LENGTH
        or not all(isinstance(run, dict) for run in history[-2:])
        or not scheduled_pair(history)
    ):
        return False
    try:
        if status.get("run_id") != history[-1]["run_id"]:
            return False
        ids: set[str] = set()
        sequences: list[int] = []
        for run in history[-2:]:
            rid, sequence = run["run_id"], run["sequence"]
            if (
                not isinstance(rid, str)
                or not RUN_ID.fullmatch(rid)
                or rid in ids
                or not _nonnegative_integer(sequence)
            ):
                return False
            ids.add(rid)
            sequences.append(sequence)
            if not _measurement_fresh(run, domains, since, now):
                return False
    except (KeyError, TypeError, EvidenceError, ValueError):
        return False
    return sequences[1] == sequences[0] + 1


CONTINUOUS_HEARTBEAT_MAX_AGE = 10
CONTINUOUS_RATE_MIN, CONTINUOUS_RATE_MAX = 190, 210
CONTINUOUS_BENIGN_SUCCESS = 0.99
CONTINUOUS_BENIGN_RATE_MIN, CONTINUOUS_BENIGN_RATE_MAX = 171, 189


CONTINUOUS_APPLICATION_PATHS = {
    "/juice-shop/rest/products/search",
    "/dvwa/login.php",
    "/vampi/",
    "/httpbin/get",
    "/whoami/",
    "/csd-demo/",
    "/dvga/",
    "/restaurant/openapi.json",
    "/crapi/",
}


def continuous_rotation_ready(
    rates: dict, domains: list[str], elapsed: float, count: int
) -> bool:
    """Require the benign budget, equal domains and rotation over all applications."""
    per_domain = rates.get("benign_per_domain", {})
    per_application = rates.get("benign_per_application", {})
    if (
        not CONTINUOUS_BENIGN_RATE_MIN <= count / elapsed <= CONTINUOUS_BENIGN_RATE_MAX
        or set(per_domain) != set(domains)
    ):
        return False
    if sum(per_domain.values()) != count or any(
        abs(value - count / 2) > max(1, count * 0.025) for value in per_domain.values()
    ):
        return False
    if (
        set(per_application) != CONTINUOUS_APPLICATION_PATHS
        or sum(per_application.values()) != count
    ):
        return False
    return all(
        abs(value - count / 9) <= max(2, count * 0.01)
        for value in per_application.values()
    )


def continuous_traffic_ready(status: Any, domains: list[str], since: float) -> bool:
    """Require two meaningful complete passes and fresh measured continuous traffic."""
    if (
        not isinstance(status, dict)
        or status.get("service_active") is not True
        or status.get("service_enabled") is not True
    ):
        return False
    now = time.time()
    heartbeat = status.get("heartbeat", 0)
    passes = status.get("catalog_passes", [])
    rates = status.get("rates", {})
    if (
        not isinstance(heartbeat, (int, float))
        or not since <= heartbeat <= now
        or now - heartbeat > CONTINUOUS_HEARTBEAT_MAX_AGE
    ):
        return False
    run_started = status.get("run_started", now)
    if (
        not isinstance(passes, list)
        or len(passes) < PAIR_LENGTH
        or any(
            not p.get("complete")
            or not p.get("catalog_complete")
            or not p.get("catalog_accepted")
            or not p.get("passed")
            or p.get("source_commit") != status.get("source_commit")
            or p.get("artifact_sha256") != status.get("artifact_sha256")
            or p.get("started", 0) < run_started
            for p in passes[-2:]
        )
    ):
        return False
    elapsed = rates.get("elapsed", 0)
    count = rates.get("benign_requests", 0)
    attacks = rates.get("attack_requests", 0)
    if (
        elapsed <= 0
        or count <= 0
        or not CONTINUOUS_RATE_MIN <= (count + attacks) / elapsed <= CONTINUOUS_RATE_MAX
    ):
        return False
    completed = rates.get("benign_completed", count)
    if (
        completed <= 0
        or rates.get("benign_success", 0) / completed < CONTINUOUS_BENIGN_SUCCESS
        or rates.get("benign_transport_failures", 1) != 0
        or rates.get("attack_transport_failures", 1) != 0
    ):
        return False
    return continuous_rotation_ready(rates, domains, elapsed, count) and not status.get(
        "failures"
    )


def traffic_ready(status: Any, domains: list[str], since: float) -> bool:
    """Require fresh adjacent guest-evaluated cycles at one captured instant."""
    now = time.time()
    if (
        not isinstance(status, dict)
        or status.get("timer_active") is not True
        or traffic_failure(status, domains, since)
    ):
        return False
    return _traffic_pair(status, domains, since, now)


def virtual_host(lb: str) -> str:
    """Compute telemetry vhost name, never a configuration UID."""
    if not isinstance(lb, str) or not NAME.fullmatch(lb):
        message = "invalid load balancer name"
        raise EvidenceError(message)
    return "ves-io-http-loadbalancer-" + lb


def identified_user(user: str, header: str = "X-MUD-User") -> str:
    """Require a synthetic user and the verified identification header."""
    if not isinstance(user, str) or not SYNTHETIC.fullmatch(user):
        message = "synthetic user required"
        raise EvidenceError(message)
    if not isinstance(header, str) or header.lower() != "x-mud-user":
        message = "unsupported synthetic identification policy"
        raise EvidenceError(message)
    return "Header-" + header.title() + "-" + user


def decode_event(raw: Any) -> dict[str, Any]:
    """Decode the observed JSON-string record once without shape fallbacks."""
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > MAX_EVENT_BYTES:
        message = "invalid security event encoding"
        raise EvidenceError(message)
    try:
        event = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        message = "invalid security event JSON"
        raise EvidenceError(message) from exc
    if not isinstance(event, dict):
        message = "invalid security event object"
        raise EvidenceError(message)
    return event


def policy_hits(event: dict[str, Any]) -> list[dict[str, Any]]:
    """Read only the observed nested policy-hit wrapper."""
    wrapper = event.get("policy_hits")
    hits = wrapper.get("policy_hits") if isinstance(wrapper, dict) else None
    if not isinstance(hits, list) or not all(isinstance(hit, dict) for hit in hits):
        return []
    return hits


def _event_join(
    event: dict[str, Any], probe: Probe, namespace: str, lb: str, end: float
) -> bool:
    value = event.get("time")
    return (
        isinstance(value, str)
        and RFC3339.fullmatch(value) is not None
        and probe["sent_at"] <= stamp(value) <= end
        and event.get("namespace") == namespace
        and event.get("vh_name") == virtual_host(lb)
        and event.get("domain") == probe["host"]
        and event.get("req_path") == probe["path"]
        and event.get("method") == probe["method"]
        and event.get("user") == identified_user(probe["user"])
        and event.get("action") == "block"
    )


def _waf(event: dict[str, Any], lb: str) -> bool:
    signatures = event.get("signatures")
    return (
        event.get("sec_event_type") == "waf_sec_event"
        and event.get("sec_event_name") == "WAF"
        and event.get("app_firewall_name") == lb + "-waf"
        and isinstance(signatures, list)
        and any(
            isinstance(sig, dict)
            and str(sig.get("id")) in {"200002883", "200002835"}
            and sig.get("state") == "Enabled"
            for sig in signatures
        )
    )


def _mud(event: dict[str, Any], namespace: str, lb: str) -> bool:
    return (
        event.get("sec_event_type") == "svc_policy_sec_event"
        and event.get("sec_event_name") == "Malicious User Mitigation"
        and any(
            hit.get("malicious_user_mitigate_action") == "MUM_BLOCK_TEMPORARILY"
            and hit.get("policy_namespace") == namespace
            and hit.get("policy") == "ves-io-http-loadbalancer-oas-validation-" + lb
            and hit.get("policy_set") == "ves-io-http-loadbalancer-waf-exclusion-" + lb
            for hit in policy_hits(event)
        )
    )


def _schema(event: dict[str, Any]) -> bool:
    violations = event.get("violations")
    return (
        event.get("sec_event_name") == "OpenAPI Validation Failure"
        and event.get("oas_req_status") == "OpenAPIViolation"
        and isinstance(violations, list)
        and any(
            isinstance(item, dict)
            and item.get("field") == "demo_id"
            and item.get("context") == "Request"
            and item.get("property") == "HTTP Body"
            for item in violations
        )
    )


def _endpoint_denial(
    event: dict[str, Any], probe: Probe, namespace: str, lb: str
) -> bool:
    policy = "ves-io-http-loadbalancer-api-protection-" + lb
    rule = "ves-io-service-policy-" + policy + "-api-protection-0"
    return (
        event.get("sec_event_name") == "API Protection Rule"
        and probe["path"] == "/httpbin/anything/admin"
        and probe["method"] in {"POST", "DELETE"}
        and any(
            hit.get("result") == "deny"
            and hit.get("policy") == policy
            and hit.get("policy_rule") == rule
            and hit.get("policy_namespace") == namespace
            for hit in policy_hits(event)
        )
    )


def _rate_limit(event: dict[str, Any], probe: Probe, namespace: str, lb: str) -> bool:
    policy_set = "ves-io-http-loadbalancer-rate-limiting-" + lb
    policy = policy_set + "-api-endpoint"
    return (
        probe.get("status") == RATE_DENIAL
        and event.get("sec_event_name") == "API Rate Limiting"
        and event.get("rsp_code") == str(RATE_DENIAL)
        and probe["path"] == "/httpbin/anything/rate-limit"
        and probe["method"] == "GET"
        and any(
            hit.get("rate_limiter_action") == "fail"
            and hit.get("result") == "rate_limiter_drop"
            and hit.get("rate_limiter_user_id") == identified_user(probe["user"])
            and hit.get("policy_namespace") == namespace
            and hit.get("policy_set") == policy_set
            and hit.get("policy") == policy
            and hit.get("policy_rule") == policy + "-rule-0"
            for hit in policy_hits(event)
        )
    )


def _control(event: dict[str, Any], probe: Probe, namespace: str, lb: str) -> bool:
    kind = probe["control"]
    if kind == "waf":
        return _waf(event, lb)
    if kind == "mud":
        return _mud(event, namespace, lb)
    if event.get("sec_event_type") != "api_sec_event":
        return False
    if kind == "schema":
        return _schema(event)
    if kind == "endpoint-denial":
        return _endpoint_denial(event, probe, namespace, lb)
    return kind == "rate-limit" and _rate_limit(event, probe, namespace, lb)


def attributed(event: Any, probe: Probe, namespace: str, lb: str, end: float) -> bool:
    """Require exact identity, scope, time and control-specific joins."""
    try:
        return (
            isinstance(event, dict)
            and _event_join(event, probe, namespace, lb, end)
            and _control(event, probe, namespace, lb)
        )
    except (EvidenceError, KeyError, TypeError, ValueError):
        return False


def telemetry_ready(
    events: list[dict[str, Any]],
    probes: list[Probe],
    namespace: str,
    lb: str,
    end: float,
) -> bool:
    """Require matching telemetry for every independent probe."""
    return bool(probes) and all(
        any(attributed(event, probe, namespace, lb, end) for event in events)
        for probe in probes
    )


def _detection_join(log: dict[str, Any], probe: Probe, namespace: str, lb: str) -> bool:
    return (
        log.get("namespace") == namespace
        and log.get("vh_name") == virtual_host(lb)
        and log.get("user") == identified_user(probe["user"])
        and log.get("suspicion_log_type") == "detection"
        and log.get("threat_level") == "High"
        and all(
            type(log.get(field)) in (int, float) and log[field] == 1.0
            for field in ("suspicion_score", "waf_suspicion_score")
        )
    )


def _finite_nonnegative(value: Any) -> TypeGuard[int | float]:
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def _detection_window(log: dict[str, Any], start: float, end: float) -> bool:
    first, last = log.get("start_time"), log.get("end_time")
    return (
        _finite_nonnegative(first)
        and _finite_nonnegative(last)
        and math.floor(start) <= first <= last <= end
    )


def _counters(values: dict[str, Any], fields: tuple[str, ...]) -> bool:
    return all(
        isinstance(values.get(key), int)
        and not isinstance(values[key], bool)
        and values[key] >= 0
        for key in fields
    )


def _detection_activity(log: dict[str, Any]) -> bool:
    activity = decode_event(log.get("incremental_activity_info"))
    mitigation = decode_event(log.get("mitigation_activity_info"))
    return (
        _counters(activity, ACTIVITY_COUNTERS)
        and _counters(mitigation, MITIGATION_COUNTERS)
        and 0 < activity["waf_sec_event_count"] <= activity["req_count"]
    )


def _detection_attributed(
    log: dict[str, Any],
    probe: Probe,
    events: list[dict[str, Any]],
    namespace: str,
    lb: str,
    end: float,
) -> bool:
    start = probe["attack_started_at"]
    if not (
        _detection_join(log, probe, namespace, lb)
        and _detection_window(log, start, end)
        and _detection_activity(log)
    ):
        return False
    waf_probe: Probe = {**probe, "control": "waf", "sent_at": start}
    return any(
        attributed(event, waf_probe, namespace, lb, min(end, log["end_time"] + 1))
        for event in events
    )


def detection_attributed(
    raw: Any,
    probe: Probe,
    events: list[dict[str, Any]],
    namespace: str,
    lb: str,
    end: float,
) -> bool:
    """Join fresh High detection to positive counters and the same WAF attack."""
    try:
        return _detection_attributed(
            decode_event(raw), probe, events, namespace, lb, end
        )
    except (EvidenceError, KeyError, TypeError, ValueError):
        return False


def detection_ready(
    logs: list[Any],
    probes: list[Probe],
    events: list[dict[str, Any]],
    namespace: str,
    lb: str,
    end: float,
) -> bool:
    """Decode each wire log once and require detection for every probe."""
    try:
        decoded = [decode_event(raw) for raw in logs]
        return bool(probes) and all(
            any(
                _detection_attributed(log, probe, events, namespace, lb, end)
                for log in decoded
            )
            for probe in probes
        )
    except (EvidenceError, KeyError, TypeError, ValueError):
        return False


def _cloud_stages(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    stages = {"overall": report}
    for name in CLOUD_STAGES:
        if name in report:
            if not isinstance(report[name], dict):
                message = "cloud-init malformed stage"
                raise EvidenceError(message)
            stages[name] = report[name]
    for stage in stages.values():
        if not isinstance(stage.get("errors", []), list) or not isinstance(
            stage.get("recoverable_errors", {}), dict
        ):
            message = "cloud-init malformed error evidence"
            raise EvidenceError(message)
    if any(stage.get("errors") for stage in stages.values()):
        message = "cloud-init reported fatal errors"
        raise EvidenceError(message)
    return stages


def _recovered_stage(stage: dict[str, Any]) -> bool:
    start, finish = stage.get("start"), stage.get("finished")
    return (
        stage.get("errors") == []
        and stage.get("recoverable_errors") == {"WARNING": [AZURE_REPROVISION_WARNING]}
        and _finite_nonnegative(start)
        and _finite_nonnegative(finish)
        and 0 < start <= finish
    )


def _recovered_azure(report: dict[str, Any], stages: dict[str, dict[str, Any]]) -> bool:
    return (
        report.get("extended_status") == "degraded done"
        and report.get("datasource") == "azure"
        and report.get("errors") == []
        and report.get("stage") is None
        and report.get("recoverable_errors")
        == {"WARNING": [AZURE_REPROVISION_WARNING] * len(CLOUD_STAGES)}
        and all(
            name in stages and _recovered_stage(stages[name]) for name in CLOUD_STAGES
        )
    )


def cloud_init_state(report: Any) -> CloudDiagnostic | None:
    """Return terminal or pending diagnostics, never guest warning text.

    Recovered-warning completion still requires successful final-unit and live
    application checks in the readiness collector, as in the original verifier.
    """
    if not isinstance(report, dict):
        message = "cloud-init malformed status"
        raise EvidenceError(message)
    stages = _cloud_stages(report)
    status, extended = (
        report.get("status"),
        report.get("extended_status", report.get("status")),
    )
    if status in ("running", "not run") and extended in (
        "running",
        "degraded running",
        "not run",
        "degraded not run",
    ):
        return None
    if status != "done" or extended not in ("done", "degraded done"):
        message = "cloud-init incomplete or degraded"
        raise EvidenceError(message)
    diagnostic: CloudDiagnostic = {
        "status": "done",
        "fatal_errors": 0,
        "warnings_accepted": 0,
    }
    if not any(stage.get("recoverable_errors") for stage in stages.values()):
        if extended != "done":
            message = "cloud-init inconsistent degraded status"
            raise EvidenceError(message)
        return diagnostic
    if not _recovered_azure(report, stages):
        message = "cloud-init disallowed recoverable errors"
        raise EvidenceError(message)
    return {
        **diagnostic,
        "status": "degraded_done",
        "warnings_accepted": len(CLOUD_STAGES),
        "reason": "Azure PPS reprovisiondata first-attempt 404 recovered before "
        "all stages completed; final unit and application readiness required",
        "sources": CLOUD_INIT_SOURCES,
    }


def _origin_route(route: urllib.parse.SplitResult, host: str, path: str) -> bool:
    return (
        route.scheme == "http"
        and route.hostname == host
        and route.path == path
        and not (route.query or route.fragment or route.username)
        and route.port in (None, HTTP_PORT)
    )


def rate_origin(code: int, reply: Any, host: str, path: str, user: str) -> None:
    """Require rate-positive responses to echo the exact origin URL and user."""
    message = "rate positive origin URL or identified-user echo mismatch"
    try:
        if not isinstance(reply, dict) or code != HTTP_SUCCESS:
            raise EvidenceError(message)
        route = urllib.parse.urlsplit(reply.get("url", ""))
        headers = reply.get("headers", {})
        if not (
            _origin_route(route, host, path)
            and isinstance(headers, dict)
            and headers.get("X-Mud-User") == user
        ):
            raise EvidenceError(message)
    except (TypeError, ValueError, AttributeError) as exc:
        raise EvidenceError(message) from exc
