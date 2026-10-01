"""Bounded showcase runner. Response checks are NOT attributed security proof."""

from __future__ import annotations

import base64
import datetime
import fcntl
import hashlib
import ipaddress
import json
import math
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import uuid
from http.client import responses
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn, NotRequired, TypedDict

if TYPE_CHECKING:
    from types import TracebackType

ROOT: Path = Path("/opt/traffic-generator")
CLASSES: tuple[str, ...] = ("waf", "schema", "endpoint-denial", "rate-limit", "mud")
ATTACK_ROTATION: tuple[str, ...] = (
    "waf",
    "schema",
    "endpoint-denial",
    "rate-limit",
    "mud",
    "waf",
    "schema",
    "rate-limit",
    "mud",
    "endpoint-denial",
    "waf",
    "rate-limit",
    "mud",
    "rate-limit",
    "rate-limit",
)
SECURITY_EVIDENCE_SCOPE: str = "measurement only; fresh control attribution required"

# Fixed global budget and acceptance tolerances; times are seconds except latency.
MIN_COUNT: int = 1485
MAX_COUNT: int = 1515
MIN_RATE: int = 49
MAX_RATE: int = 51
MIN_DURATION: float = 29.5
MAX_DURATION: float = 30.5
MIN_BENIGN_MIX: float = 0.89
MAX_BENIGN_MIX: float = 0.91
MIN_BENIGN_SUCCESS: float = 0.99
MAX_LATENCY: int = 5_000_000_000
MIN_CADENCE: int = 295
MAX_CADENCE: int = 310
TARGET_COUNT: int = 1500
DOMAIN_COUNT: int = 2
ATTACK_PERIOD: int = 20
MIX_PERIOD: int = 10
ATTACK_SLOT: int = 9
POST_PERIOD: int = 4
MAX_DOMAIN_LENGTH: int = 253
IPV4_VERSION: int = 4
HTTP_OK: int = 200
HTTP_REDIRECT: int = 300
HTTP_BAD_REQUEST: int = 400
HTTP_FORBIDDEN: int = 403
HTTP_RATE_LIMIT: int = 429


class Target(TypedDict):
    """One Vegeta JSON target, with an optional base64 request body."""

    method: str
    url: str
    header: dict[str, list[str]]
    body: NotRequired[str]


RequestRecord = TypedDict(
    "RequestRecord",
    {
        "domain": str | None,
        "class": str,
        "code": int,
        "error": str,
        "timestamp": str,
        "latency": int,
        "url": str,
        "method": str | None,
        "body": str | None,
    },
)


class Configuration(TypedDict):
    """Fixed guest configuration validated before use."""

    target_domains: list[str]
    target_origin_ip: str
    tool_tier: str
    mud_bad_traffic: bool


class Accounting(TypedDict):
    """Measured request outcomes, not attributed security evidence."""

    transport_errors: int
    http_errors: int
    response_failures: int
    benign_success: float


RateOutcome = TypedDict(
    "RateOutcome",
    {"status_counts": dict[str, int], "429_count": int, "rate_denial_observed": bool},
)


class Summary(TypedDict, total=False):
    """Receipt fields; failed attempts need not contain measured metrics."""

    run_id: str
    sequence: int
    trigger: str
    domains: list[str]
    started_epoch: float
    started_at: str
    completed_at: str
    status: str
    mud_status: str
    attribution_status: str
    security_evidence_scope: str
    failures: list[str]
    error_class: str
    error_stage: str
    count: int
    rate: float
    duration_seconds: float
    latencies: dict[str, Any]
    transport_errors: int
    http_errors: int
    response_failures: int
    benign_success: float
    class_counts: dict[str, int]
    rate_outcomes: dict[str, RateOutcome]


def _invalid(message: str) -> NoReturn:
    """Raise a stable local validation reason without embedding data."""
    raise ValueError(message)


def _configuration_invalid(message: str) -> NoReturn:
    """Raise a safe configuration reason recognized by receipt publishing."""
    raise ConfigurationError(message)


def _integer(value: Any) -> bool:
    """Accept integer accounting, explicitly excluding bool's int subclass."""
    return isinstance(value, int) and not isinstance(value, bool)


def _number(value: Any) -> float:
    """Validate numeric input before conversions can erase a bool's identity."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _invalid("non-finite or negative metric")
    return value


def metric_failures(
    count: float, rate: float, duration: float, latencies: dict[str, Any]
) -> list[str]:
    """Validate measured metrics in seconds and nanoseconds, shared by consumers."""
    failures = []
    numbers = [count, rate, duration] + [
        latencies[k] for k in ("min", "mean", "50th", "90th", "95th", "99th", "max")
    ]
    if any(
        isinstance(v, bool)
        or not isinstance(v, (int, float))
        or not math.isfinite(v)
        or v < 0
        for v in numbers
    ):
        _invalid("non-finite or negative metric")
    if not MIN_COUNT <= count <= MAX_COUNT:
        failures.append("count")
    if not MIN_RATE <= rate <= MAX_RATE:
        failures.append("rate")
    if not MIN_DURATION <= duration <= MAX_DURATION:
        failures.append("duration")
    if (
        not latencies["min"]
        <= latencies["50th"]
        <= latencies["90th"]
        <= latencies["95th"]
        <= latencies["99th"]
        <= latencies["max"]
        or not latencies["min"] <= latencies["mean"] <= latencies["max"]
    ):
        failures.append("latencies")
    if latencies["max"] > MAX_LATENCY or latencies["mean"] <= 0:
        failures.append("latencies")
    return failures


def evaluate_summary(summary: dict[str, Any], domains: list[str]) -> list[str]:
    """Validate the actual guest summary; never manufacture per-request records."""
    failures = []
    try:
        failures.extend(
            metric_failures(
                summary["count"],
                summary["rate"],
                summary["duration_seconds"],
                summary["latencies"],
            )
        )
        counts = summary["class_counts"]
        values = [
            *list(counts.values()),
            summary["transport_errors"],
            summary["benign_success"],
        ]
        if any(
            isinstance(v, bool)
            or not isinstance(v, (int, float))
            or not math.isfinite(v)
            or v < 0
            for v in values
        ):
            _invalid("invalid accounting")
        if (
            set(counts) != {"benign", *CLASSES}
            or any(not isinstance(v, int) or v <= 0 for v in counts.values())
            or sum(counts.values()) != summary["count"]
        ):
            failures.append("classes")
        if not MIN_BENIGN_MIX <= counts["benign"] / summary["count"] <= MAX_BENIGN_MIX:
            failures.append("mix")
        if not MIN_BENIGN_SUCCESS <= summary["benign_success"] <= 1:
            failures.append("benign_success")
        if summary["transport_errors"] != 0:
            failures.append("transport")
        if set(summary["domains"]) != set(domains) or len(set(domains)) < DOMAIN_COUNT:
            failures.append("domains")
        if summary["security_evidence_scope"] != SECURITY_EVIDENCE_SCOPE:
            failures.append("evidence_scope")
        outcomes = summary["rate_outcomes"]
        if set(outcomes) != set(domains):
            failures.append("rate_outcomes")
        total = 0
        for outcome in outcomes.values():
            statuses = outcome["status_counts"]
            if (
                not statuses
                or not set(statuses) <= {"200", "429"}
                or any(not _integer(v) or v < 0 for v in statuses.values())
            ):
                _invalid("invalid rate outcomes")
            denied = statuses.get("429", 0)
            if (
                not _integer(outcome["429_count"])
                or outcome["429_count"] != denied
                or not isinstance(outcome["rate_denial_observed"], bool)
                or outcome["rate_denial_observed"] != (denied > 0)
            ):
                failures.append("rate_outcomes")
            total += sum(statuses.values())
        if total != counts["rate-limit"]:
            failures.append("rate_outcomes")
        if summary["status"] != "verified" or summary["failures"] != []:
            failures.append("guest_evaluation")
    except (KeyError, TypeError, ValueError, ZeroDivisionError):
        failures.append("malformed_metrics")
    return sorted(set(failures))


def transport_error(record: RequestRecord) -> bool:
    """Vegeta v12.12.0 sets Error=r.Status for completed non-success HTTP.

    attack.go assigns Code only after reading the complete response body; code
    zero therefore remains a transport failure even with an HTTP-looking error.
    """
    code, error = record["code"], record["error"]
    if (
        isinstance(code, bool)
        or not isinstance(code, int)
        or (code != 0 and code not in responses)
        or not isinstance(error, str)
    ):
        _invalid("malformed response outcome")
    if code == 0:
        return True
    return bool(error) and (
        HTTP_OK <= code < HTTP_BAD_REQUEST or error != f"{code} {responses[code]}"
    )


def response_failure(record: RequestRecord) -> bool:
    """Check class-specific response expectations independently of transport."""
    code, cls = record["code"], record["class"]
    return (
        (cls == "benign" and not HTTP_OK <= code < HTTP_REDIRECT)
        or (
            cls in ("waf", "schema", "endpoint-denial")
            and code not in (HTTP_BAD_REQUEST, HTTP_FORBIDDEN)
        )
        or (cls == "rate-limit" and code not in (HTTP_OK, HTTP_RATE_LIMIT))
        or (
            cls == "mud"
            and code not in (HTTP_OK, HTTP_BAD_REQUEST, HTTP_FORBIDDEN, HTTP_RATE_LIMIT)
        )
    )


def outcome_accounting(records: list[RequestRecord]) -> Accounting:
    """Keep completed HTTP denials separate from actual network failures."""
    transport = [transport_error(r) for r in records]
    benign = [r for r in records if r["class"] == "benign"]
    return {
        "transport_errors": sum(transport),
        "http_errors": sum(
            bool(r["error"]) and not failed
            for r, failed in zip(records, transport, strict=True)
        ),
        "response_failures": sum(response_failure(r) for r in records),
        "benign_success": sum(
            HTTP_OK <= r["code"] < HTTP_REDIRECT and not transport_error(r)
            for r in benign
        )
        / max(1, len(benign)),
    }


def rate_origin_response(record: RequestRecord) -> bool:
    """Confirm actual Vegeta base64 body echoes the fresh rate request at httpbin.

    Owned capture 1138b519: nginx strips /httpbin; anything returns method,
    url, and headers (including Host and X-Mud-User). Status alone is insufficient.
    """
    try:
        request = urllib.parse.urlsplit(record["url"])
        query = urllib.parse.parse_qs(request.query)
        run = query["demo_run"][0]
        encoded_body = record["body"]
        if not isinstance(encoded_body, str):
            return False
        body = json.loads(base64.b64decode(encoded_body, validate=True))
        headers = {k.lower(): v for k, v in body["headers"].items()}
        echoed = urllib.parse.urlsplit(body["url"])
        return (
            record["method"] == body["method"] == "GET"
            and request.hostname == record["domain"] == echoed.hostname
            and request.path == "/httpbin/anything/rate-limit"
            and echoed.path == "/anything/rate-limit"
            and echoed.scheme == request.scheme == "http"
            and urllib.parse.parse_qs(echoed.query) == query
            and query["demo_class"] == ["rate-limit"]
            and query["demo_run"] == [run]
            and headers["host"] == record["domain"]
            and headers["x-mud-user"] == "rate-limit-" + run
        )
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        return False


def rate_outcomes(
    records: list[RequestRecord], domains: list[str]
) -> dict[str, RateOutcome]:
    """Summarize measurement-only rate responses per configured domain."""
    outcomes: dict[str, RateOutcome] = {}
    for domain in domains:
        rows = [
            r for r in records if r["domain"] == domain and r["class"] == "rate-limit"
        ]
        counts = {
            str(code): sum(r["code"] == code for r in rows)
            for code in sorted({r["code"] for r in rows})
        }
        denied = counts.get("429", 0)
        outcomes[domain] = {
            "status_counts": counts,
            "429_count": denied,
            "rate_denial_observed": denied > 0,
        }
    return outcomes


def evaluate(
    report: dict[str, Any], records: list[RequestRecord], domains: list[str]
) -> list[str]:
    """Fail closed on malformed metrics and measured contract violations."""
    failures = []
    try:
        count = report["requests"]
        rate = report["rate"]
        duration = _number(report["duration"]) / 1e9
        latencies = report["latencies"]
        failures.extend(metric_failures(count, rate, duration, latencies))
        if count != len(records):
            failures.append("count")
        observed = {r["domain"] for r in records}
        if observed != set(domains) or len(observed) < DOMAIN_COUNT:
            failures.append("domains")
        benign = [r for r in records if r["class"] == "benign"]
        if (
            not records
            or not MIN_BENIGN_MIX <= len(benign) / len(records) <= MAX_BENIGN_MIX
        ):
            failures.append("mix")
        accounting = outcome_accounting(records)
        if not benign or accounting["benign_success"] < MIN_BENIGN_SUCCESS:
            failures.append("benign_success")
        if accounting["transport_errors"]:
            failures.append("transport")
        errors = report["errors"]
        if not isinstance(errors, list) or any(
            not isinstance(e, str) or not e for e in errors
        ):
            _invalid("malformed aggregate errors")
        if set(errors) != {r["error"] for r in records if r["error"]}:
            failures.append("error_accounting")
        if any(r["class"] == "benign" and response_failure(r) for r in records):
            failures.append("unexpected_response")
        if {r["class"] for r in records} != {"benign", *CLASSES}:
            failures.append("classes")
        if any(
            r["class"] in ("waf", "schema", "endpoint-denial")
            and r["code"] not in (HTTP_BAD_REQUEST, HTTP_FORBIDDEN)
            for r in records
        ):
            failures.append("expected_denial")
        if any(
            (r["class"] == "rate-limit" and r["code"] not in (HTTP_OK, HTTP_RATE_LIMIT))
            or (
                r["class"] == "mud"
                and r["code"]
                not in (HTTP_OK, HTTP_BAD_REQUEST, HTTP_FORBIDDEN, HTTP_RATE_LIMIT)
            )
            for r in records
        ):
            failures.append("unexpected_response")
        if any(
            r["class"] == "rate-limit"
            and r["code"] == HTTP_OK
            and not rate_origin_response(r)
            for r in records
        ):
            failures.append("rate_origin_response_unconfirmed")
    except (KeyError, TypeError, ValueError, ZeroDivisionError):
        failures.append("malformed_metrics")
    return sorted(set(failures))


def scheduled_pair(history: list[dict[str, Any]]) -> bool:
    """Only two consecutive successful scheduled cycles satisfy cadence evidence."""
    try:
        return (
            len(history) >= DOMAIN_COUNT
            and all(
                x.get("trigger") == "scheduled" and x.get("status") == "verified"
                for x in history[-DOMAIN_COUNT:]
            )
            and MIN_CADENCE
            <= history[-1]["started_epoch"] - history[-DOMAIN_COUNT]["started_epoch"]
            <= MAX_CADENCE
        )
    except (KeyError, TypeError, ValueError):
        return False


def targets(
    domains: list[str], run: str, sequence: int, mud: bool = True
) -> list[Target]:
    """Generate the unchanged global budget with front-loaded rate identities."""
    result = []
    # Preserve the global 90/10 budget, not a per-second attack ratio.
    # Move existing rate probes to the first 50 slots (0.98s at 50/s), with
    # alternating hosts and one fresh rate identity; never add requests.
    for i in range(TARGET_COUNT):
        attack_index = (i // ATTACK_PERIOD) * DOMAIN_COUNT + (
            i % ATTACK_PERIOD // MIX_PERIOD
        )
        cls = (
            ATTACK_ROTATION[(attack_index + sequence) % len(ATTACK_ROTATION)]
            if i % MIX_PERIOD == ATTACK_SLOT
            else "benign"
        )
        domain = domains[(i + i // MIX_PERIOD) % len(domains)]
        body: dict[str, str] | None = None
        method, path = "GET", "/httpbin/get"
        if cls == "benign" and i % POST_PERIOD == 0:
            method, path, body = "POST", "/httpbin/post", {"demo_id": run}
        elif cls in ("waf", "mud"):
            path = "/httpbin/get?q=%27%20OR%201%3D1--"
        elif cls == "schema":
            method, path, body = "POST", "/httpbin/post", {}
        elif cls == "endpoint-denial":
            method, path = (
                ("POST" if attack_index % DOMAIN_COUNT else "DELETE"),
                "/httpbin/anything/admin",
            )
        elif cls == "rate-limit":
            path = "/httpbin/anything/rate-limit"
        identity = (
            f"{cls}-{run}" if cls in ("rate-limit", "mud") else f"{cls}-{run}-{i}"
        )
        if cls == "mud" and not mud:
            _invalid("showcase requires mud_bad_traffic")
        url = f"http://{domain}{path}"
        url += ("&" if "?" in url else "?") + urllib.parse.urlencode(
            {"demo_run": run, "demo_class": cls}
        )
        headers = {"X-MUD-User": [identity], "X-Demo-Class": [cls], "X-Demo-Run": [run]}
        target: Target = {"method": method, "url": url, "header": headers}
        if body is not None:
            headers["Content-Type"] = ["application/json"]
            target["body"] = base64.b64encode(json.dumps(body).encode()).decode()
        result.append(target)
    rate = [t for t in result if t["header"]["X-Demo-Class"] == ["rate-limit"]]
    by_domain = [
        [t for t in rate if urllib.parse.urlsplit(t["url"]).hostname == domain]
        for domain in domains
    ]
    return [t for pair in zip(*by_domain, strict=False) for t in pair] + [
        t for t in result if t["header"]["X-Demo-Class"] != ["rate-limit"]
    ]


def atomic(path: Path, value: Any) -> None:
    """Publish local JSON without exposing a partially written receipt."""
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(value, indent=DOMAIN_COUNT) + "\n")
    tmp.replace(path)


class ConfigurationError(ValueError):
    """Safe configuration reason; never includes input values or response bodies."""


def validate_config(value: Any) -> None:
    """Reject malformed configuration before authorizing any traffic."""
    try:
        if not isinstance(value, dict) or set(value) != {
            "target_domains",
            "target_origin_ip",
            "tool_tier",
            "mud_bad_traffic",
        }:
            _configuration_invalid("invalid_configuration")
        domains = value["target_domains"]
        if (
            not isinstance(domains, list)
            or len(domains) != DOMAIN_COUNT
            or any(
                not isinstance(d, str)
                or len(d) > MAX_DOMAIN_LENGTH
                or not all(
                    re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                    for label in d.split(".")
                )
                for d in domains
            )
            or len(set(domains)) != DOMAIN_COUNT
        ):
            _configuration_invalid("invalid_domains")
        origin = ipaddress.ip_address(value["target_origin_ip"])
        if (
            origin.version != IPV4_VERSION
            or origin.is_loopback
            or origin.is_unspecified
            or origin.is_multicast
        ):
            _configuration_invalid("invalid_origin")
        if value["tool_tier"] not in ("standard", "full"):
            _configuration_invalid("invalid_tool_tier")
        if value["mud_bad_traffic"] is not True:
            _configuration_invalid("mud_bad_traffic_required")
        # Exercise the same complete target generator used by the scheduled attack.
        targets(domains, "configuration-check", 0, value["mud_bad_traffic"])
    except ConfigurationError:
        raise
    except (KeyError, TypeError, ValueError):
        _configuration_invalid("invalid_configuration")


def config() -> Any:
    """Read fixed guest configuration without starting a timer."""
    return json.loads((ROOT / "config.json").read_text())


def fingerprint(value: Any) -> str:
    """Bind readiness authorization to the exact configuration JSON."""
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Prevent health checks from following redirects to unvalidated endpoints."""

    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> NoReturn:
        """Reject redirects rather than opening an unvalidated target."""
        _invalid("readiness redirect is not permitted")


def cheap_ready(value: Configuration) -> None:
    """Check pinned tooling and origin/domain health without redirects."""
    validate_config(value)
    version = subprocess.run(
        ["vegeta", "-version"],  # noqa: S607 -- guest installs pinned Vegeta on PATH
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    # Upstream v12.12.0 main.go emits these four lines; the release retains v.
    if not re.fullmatch(
        r"Version: v12\.12\.0\nCommit: [^\r\n]+\nRuntime: [^\r\n]+\nDate: [^\r\n]+\n",
        version,
    ):
        _invalid("mandatory pinned Vegeta unavailable")
    for host in [value["target_origin_ip"], *value["target_domains"]]:
        opener = urllib.request.build_opener(NoRedirect)
        with opener.open(f"http://{host}/health", timeout=5) as response:
            if response.status != HTTP_OK:
                _invalid("health not ready")


class _Attempt:
    """Record ordinary operational failures while propagating process interrupts."""

    def __init__(self, summary: Summary) -> None:
        self.summary = summary
        self.stage = "configuration"

    def __enter__(self) -> _Attempt:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        if not isinstance(exc, Exception):
            return False
        error = _failure_class(exc, self.stage)
        self.summary["error_class"] = error
        self.summary["error_stage"] = self.stage
        self.summary["failures"].append(
            str(exc) if isinstance(exc, ConfigurationError) else error
        )
        return True


def _failure_class(exc: Exception, stage: str) -> str:
    """Classify ordinary failures without exposing tool output or configuration."""
    if isinstance(exc, ConfigurationError):
        return "configuration"
    if stage == "authorization":
        return "authorization"
    if isinstance(exc, FileNotFoundError):
        return "tool_missing"
    if stage == "metrics":
        return "metrics_unavailable"
    return stage + "_failed"


def _prepare_targets(value: Configuration, folder: Path, summary: Summary) -> Path:
    """Publish the fixed budget only after readiness succeeds."""
    cheap_ready(value)
    target_file = folder / "targets.jsonl"
    target_file.write_text(
        "".join(
            json.dumps(target) + "\n"
            for target in targets(
                value["target_domains"],
                summary["run_id"],
                summary["sequence"],
                value["mud_bad_traffic"],
            )
        ),
        encoding="utf-8",
    )
    return target_file


def _attack(folder: Path, target_file: Path, run: str) -> Path:
    """Run the unchanged bounded Vegeta attack and close its output streams."""
    raw = folder / "results.bin"
    with (
        raw.open("wb") as output,
        (folder / "attack.stderr").open("w", encoding="utf-8") as errors,
    ):
        subprocess.run(  # noqa: S603 -- pinned guest tool and fixed argv
            [  # noqa: S607 -- fixed guest tool, no shell or user executable
                "vegeta",
                "attack",
                "-format=json",
                "-targets=" + str(target_file),
                "-rate=50/s",
                "-duration=30s",
                "-timeout=5s",
                "-redirects=0",
                "-max-workers=100",
                "-name=" + run,
            ],
            stdout=output,
            stderr=errors,
            check=True,
        )
    return raw


def _record(item: dict[str, Any], run: str) -> RequestRecord:
    """Decode one observed response while checking its fresh request run ID."""
    url = urllib.parse.urlsplit(item["url"])
    query = urllib.parse.parse_qs(url.query)
    if query["demo_run"] != [run]:
        _invalid("mismatched run ID")
    return {
        "domain": url.hostname,
        "class": query["demo_class"][0],
        "code": item["code"],
        "error": item.get("error", ""),
        "timestamp": item["timestamp"],
        "latency": item["latency"],
        "url": item["url"],
        "method": item.get("method"),
        "body": item.get("body"),
    }


def _report(
    folder: Path, raw: Path, run: str
) -> tuple[dict[str, Any], list[RequestRecord]]:
    """Collect actual aggregate and per-request tool output for this attempt."""
    report_path = folder / "vegeta-report.json"
    with report_path.open("w", encoding="utf-8") as output:
        subprocess.run(  # noqa: S603 -- pinned guest tool and fixed argv
            ["vegeta", "report", "-type=json", str(raw)],  # noqa: S607 -- pinned guest tool
            stdout=output,
            check=True,
        )
    encoded = folder / "requests.jsonl"
    with encoded.open("w", encoding="utf-8") as output:
        subprocess.run(  # noqa: S603 -- pinned guest tool and fixed argv
            ["vegeta", "encode", "-to=json", str(raw)],  # noqa: S607 -- pinned guest tool
            stdout=output,
            check=True,
        )
    records = [
        _record(json.loads(line), run) for line in encoded.read_text().splitlines()
    ]
    atomic(folder / "accounting.json", records)
    return json.loads(report_path.read_text()), records


def _update_summary(
    summary: Summary,
    report: dict[str, Any],
    records: list[RequestRecord],
    domains: list[str],
) -> None:
    """Attach only measured fields and preserve pending security attribution."""
    summary["failures"] = evaluate(report, records, domains)
    summary["count"] = len(records)
    summary["rate"] = report["rate"]
    summary["duration_seconds"] = _number(report["duration"]) / 1e9
    summary["latencies"] = report["latencies"]
    accounting = outcome_accounting(records)
    summary["transport_errors"] = accounting["transport_errors"]
    summary["http_errors"] = accounting["http_errors"]
    summary["response_failures"] = accounting["response_failures"]
    summary["benign_success"] = accounting["benign_success"]
    summary["class_counts"] = {
        cls: sum(record["class"] == cls for record in records)
        for cls in ("benign", *CLASSES)
    }
    summary["rate_outcomes"] = rate_outcomes(records, domains)
    summary["status"] = "failed" if summary["failures"] else "verified"
    if summary["failures"]:
        summary["error_class"] = "metrics_failed"
        summary["error_stage"] = "metrics"


def _publish(folder: Path, summary: Summary, history: list[Any]) -> int:
    """Publish summary, then preserved history, then the latest guest status."""
    summary["completed_at"] = datetime.datetime.now(datetime.UTC).isoformat()
    atomic(folder / "summary.json", summary)
    history.append(summary)
    atomic(folder.parent / "history.json", history)
    atomic(
        ROOT / "status.json",
        {
            **summary,
            "history": history,
            "scheduled_pair": scheduled_pair(history),
        },
    )
    return int(summary["status"] != "verified")


def run_cycle(value: Any, trigger: str) -> int:
    """Run one globally bounded attempt and publish only actual collected metrics."""
    results = ROOT / "results"
    results.mkdir(exist_ok=True)
    with (ROOT / "run.lock").open("w", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        history_path = results / "history.json"
        history = json.loads(history_path.read_text()) if history_path.exists() else []
        run = uuid.uuid4().hex
        folder = results / run
        folder.mkdir()
        summary: Summary = {
            "run_id": run,
            "sequence": len(history),
            "trigger": trigger,
            "domains": [],
            "started_epoch": time.time(),
            "started_at": datetime.datetime.now(datetime.UTC).isoformat(),
            "status": "failed",
            "mud_status": "pending",
            "attribution_status": "pending",
            "security_evidence_scope": SECURITY_EVIDENCE_SCOPE,
            "failures": [],
        }
        with _Attempt(summary) as attempt:
            validate_config(value)
            summary["domains"] = value["target_domains"]
            attempt.stage = "authorization"
            authorization = json.loads((ROOT / "authorization.json").read_text())
            if authorization["config_sha256"] != fingerprint(value):
                _invalid("readiness authorization stale")
            attempt.stage = "readiness"
            target_file = _prepare_targets(value, folder, summary)
            attempt.stage = "attack"
            raw = _attack(folder, target_file, run)
            attempt.stage = "metrics"
            report, records = _report(folder, raw, run)
            _update_summary(summary, report, records, value["target_domains"])
        return _publish(folder, summary, history)


def main() -> int:
    """Dispatch unchanged guest commands without implicit authorization."""
    command = sys.argv[1] if len(sys.argv) > 1 else "status"
    if command == "status":
        status = json.loads((ROOT / "status.json").read_text())
        history_path = ROOT / "results/history.json"
        status["history"] = (
            json.loads(history_path.read_text()) if history_path.exists() else []
        )
        status["timer_active"] = (
            subprocess.run(
                ["systemctl", "is-active", "--quiet", "tgen-continuous.timer"],  # noqa: S607 -- fixed system tool
                check=False,
            ).returncode
            == 0
        )
        print(json.dumps(status))
        return 0
    if command in ("run-once", "scheduled"):
        try:
            value = config()
        except (OSError, ValueError):
            value = {}
        if not isinstance(value, dict):
            value = {}
        return run_cycle(value, "manual" if command == "run-once" else "scheduled")
    if command == "start":
        # Lifecycle calls start ONLY after its complete readiness verifier succeeds.
        try:
            value = config()
        except (OSError, ValueError):
            _configuration_invalid("invalid_configuration")
        cheap_ready(value)
        atomic(
            ROOT / "authorization.json",
            {"config_sha256": fingerprint(value), "authorized_at": time.time()},
        )
        subprocess.run(
            ["systemctl", "enable", "--now", "tgen-continuous.timer"],  # noqa: S607 -- fixed system tool
            check=True,
        )
        return 0
    if command == "stop":
        subprocess.run(
            ["systemctl", "disable", "--now", "tgen-continuous.timer"],  # noqa: S607 -- fixed system tool
            check=True,
        )
        subprocess.run(
            ["systemctl", "stop", "tgen-continuous.service"],  # noqa: S607 -- fixed system tool
            check=True,
        )
        (ROOT / "authorization.json").unlink(missing_ok=True)
        return 0
    _invalid("expected start, stop, status or run-once")


if __name__ == "__main__":
    sys.exit(main())
