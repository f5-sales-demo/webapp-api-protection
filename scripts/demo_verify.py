#!/usr/bin/env python3
"""Bounded live showcase orchestration; synthetic fixtures are not security proof.

Reports contain allowlisted summaries, never raw API, SSH or HTTP bodies.
Scope validation, transport and pure evidence evaluation have separate owners.
Detection and mitigation require independent fresh-user telemetry joins.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.parse
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import demo_verify_client as transport
import demo_verify_evidence as evaluation
import demo_verify_scope as scope
import demo_verify_types as contracts

if TYPE_CHECKING:
    from demo_verify_types import (
        AcceptanceEvidence,
        CloudDiagnostic,
        Probe,
        ProbeResult,
        RateBurstSummary,
        ReadinessEvidence,
        ShowcaseOutputs,
        TrafficRunSummary,
        VerificationReport,
        VerifyOptions,
        Vm,
    )

# Existing public report references and independently documented bucket semantics.
SOURCES = [
    "https://docs.cloud.f5.com/docs-v2/platform/reference/security-events-reference",
    "xcsh://api-catalog/events",
    "xcsh://api-catalog/events-scroll",
    "xcsh://api-catalog/suspicious-user-logs",
    "xcsh://api-catalog/suspicious-user-logs-scroll",
    "xcsh://api-spec/virtual?resource=suspicious_user_logs",
    (
        "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/"
        "how-to/observe/monitor-waap#explore-security-monitoring"
    ),
    (
        "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/"
        "how-to/adv-security/malicious-users#enable-malicious-user-mitigation"
    ),
]
RATE_BUCKET_SOURCE = "https://my.f5.com/manage/s/article/K000161473"
SUCCESS = 200
FORBIDDEN = 403
RATE_DENIAL = 429
SUCCESS_END = 300
BURST_LIMIT = 30
BURST_SECONDS = 30
RATE_THRESHOLD = 20
MAX_TIMEOUT = 3600
MAX_POLL = 60
GATES = ("controls_attributed", "scheduled_traffic", "mud_detection", "mud_mitigation")
TRAFFIC_FIELDS = (
    "run_id",
    "count",
    "rate",
    "duration_seconds",
    "latencies",
    "transport_errors",
    "benign_success",
    "class_counts",
    "rate_outcomes",
    "security_evidence_scope",
)
RATE_PATH = "/httpbin/anything/rate-limit"
GET_PATH = "/httpbin/get"
WAF_PATH = GET_PATH + "?demo=" + urllib.parse.quote("' OR 1=1--")


def _fail(message: str) -> contracts.EvidenceError:
    return contracts.EvidenceError(message)


def mitigation_probe(client: transport.Client, probe: Probe) -> bool:
    """Check propagation after detection, preserving the first mitigation time."""
    sent = time.time()
    code, _ = client.request(
        probe["host"], probe["path"], probe["method"], probe["user"]
    )
    good, reply = client.request(
        probe["host"], probe["path"], probe["method"], probe["user"] + "-negative"
    )
    if not (SUCCESS <= good < SUCCESS_END and isinstance(reply, dict)):
        msg = "independent MUD application control failed"
        raise _fail(msg)
    if code not in (SUCCESS, FORBIDDEN):
        msg = "unexpected MUD propagation response"
        raise _fail(msg)
    if "mitigation_sent_at" not in probe:
        probe["mitigation_sent_at"] = sent
    return code == FORBIDDEN


def _cloud_ready(
    client: transport.Client, vm: Vm, args: VerifyOptions, role: str
) -> CloudDiagnostic:
    """Poll nonblocking cloud-init status; terminal proof includes the final unit."""
    while True:
        client.remaining(phase_budget=True)
        raw = json.loads(
            client.ssh(
                vm, args, "sudo -n cloud-init status --format json", allowed=(0, 2)
            )
        )
        diagnostic = evaluation.cloud_init_state(raw)
        if diagnostic is not None:
            unit = client.ssh(
                vm,
                args,
                "systemctl show cloud-final.service -p Result -p ExecMainStatus",
            )
            if set(unit.splitlines()) != {"Result=success", "ExecMainStatus=0"}:
                msg = role + " cloud-final unit failed"
                raise _fail(msg)
            diagnostic["final_unit_success"] = True
            return diagnostic
        time.sleep(min(args.poll_seconds, client.remaining(phase_budget=True)))


def _application_ready(client: transport.Client, domain: str) -> None:
    client.command(["getent", "ahosts", domain])
    code, body = client.request(
        domain, GET_PATH, "GET", "showcase-" + uuid.uuid4().hex + "-ready"
    )
    route = (
        urllib.parse.urlsplit(body.get("url", "")) if isinstance(body, dict) else None
    )
    if not (
        code == SUCCESS
        and route is not None
        and route.scheme == "http"
        and route.hostname == domain
        and route.path == "/get"
        and not (route.query or route.fragment or route.username)
        and route.port in (None, evaluation.HTTP_PORT)
    ):
        msg = "expected live application response missing"
        raise _fail(msg)


def readiness(
    client: transport.Client, out: ShowcaseOutputs, args: VerifyOptions
) -> ReadinessEvidence:
    """Require effective controls, terminal guest success and current applications."""
    scope.effective(client, out)
    cloud_info = {
        role: _cloud_ready(client, vm, args, role)
        for role, vm in (("origin", out["origin"]), ("generator", out["generator"]))
    }
    native = json.loads(
        client.ssh(
            out["origin"],
            args,
            "sudo -n /usr/local/bin/demo-origin-ready",
            phase_budget=True,
        )
    )
    if not evaluation.guest_ready(native):
        msg = "origin service or replica readiness failed"
        raise _fail(msg)
    for domain in out["domains"]:
        _application_ready(client, domain)
    catalog = json.loads(
        client.ssh(
            out["generator"],
            args,
            "sudo -n python3 /opt/traffic-generator/current/scripts/catalog_readiness.py --config /opt/traffic-generator/catalog-config.json",
            phase_budget=True,
        )
    )
    if catalog.get("ready") is not True:
        message = "complete installed catalog readiness failed"
        raise _fail(message)
    return {
        "effective_controls": True,
        "cloud_init": True,
        "cloud_init_info": cloud_info,
        "origin_checks": len(native["checks"]),
        "application_domains": len(out["domains"]),
    }


def _rate_summary(host: str, budget: float) -> RateBurstSummary:
    return {
        "control": "rate-burst",
        "host": host,
        "request_limit": BURST_LIMIT,
        "duration_budget_seconds": budget,
        "threshold": RATE_THRESHOLD,
        "unit": "MINUTE",
        "identity": "X-MUD-User",
        "status_counts": {},
        "bucket_semantics": "capacity returns during traffic; no fixed request-21 denial",
        "bucket_semantics_source": RATE_BUCKET_SOURCE,
        "rate_proof_source": "fresh API Rate Limiting / fail / rate_limiter_drop / rule-0",
    }


def _rate_requests(
    client: transport.Client, host: str, user: str, summary: RateBurstSummary
) -> list[contracts.DenialRequest]:
    denials: list[contracts.DenialRequest] = []
    for index in range(BURST_LIMIT):
        if time.monotonic() >= client.deadline:
            msg = "probe duration budget exhausted; burst too slow"
            raise _fail(msg)
        sent = time.time()
        code, reply = client.request(host, RATE_PATH, "GET", user)
        statuses = summary["status_counts"]
        statuses[str(code)] = statuses.get(str(code), 0) + 1
        if index == 0 or code == SUCCESS:
            evaluation.rate_origin(code, reply, host, RATE_PATH, user)
        elif code != RATE_DENIAL:
            msg = "rate probe unexpected response; only HTTP 429 proves denial"
            raise _fail(msg)
        if code == RATE_DENIAL:
            denials.append({"request": index + 1, "sent_at": sent})
        if time.monotonic() >= client.deadline:
            msg = "probe duration budget exhausted; burst too slow"
            raise _fail(msg)
    if not denials:
        msg = "no HTTP 429 in bounded burst; policy or transport pacing unproven"
        raise _fail(msg)
    return denials


def rate_burst(
    client: transport.Client, host: str, user: str
) -> tuple[Probe, RateBurstSummary]:
    """Saturate one fresh identified bucket with bounded sequential requests."""
    started = time.monotonic()
    original_deadline = client.deadline
    client.deadline = min(original_deadline, started + BURST_SECONDS)
    summary = _rate_summary(host, client.deadline - started)
    try:
        denials = _rate_requests(client, host, user, summary)
        burst_end, duration = time.time(), time.monotonic() - started
        client.deadline = original_deadline
        for path, identity in ((RATE_PATH, user + "-independent"), (GET_PATH, user)):
            code, reply = client.request(host, path, "GET", identity)
            evaluation.rate_origin(code, reply, host, path, identity)
        summary.update(
            request_count=sum(summary["status_counts"].values()),
            duration_seconds=duration,
            denial_count=len(denials),
            first_denial_request=denials[0]["request"],
            independent_user_allowed=True,
            same_user_unrelated_path_allowed=True,
        )
        probe: Probe = {
            "host": host,
            "path": RATE_PATH,
            "method": "GET",
            "user": user,
            "sent_at": denials[0]["sent_at"],
            "burst_end": burst_end,
            "control": "rate-limit",
            "status": RATE_DENIAL,
            "denial_requests": denials,
        }
    except contracts.EvidenceError as exc:
        summary.update(
            request_count=sum(summary["status_counts"].values()),
            duration_seconds=time.monotonic() - started,
            diagnostic=str(exc),
        )
        raise _fail(
            "rate burst failed: " + json.dumps(summary, sort_keys=True)
        ) from exc
    finally:
        client.deadline = original_deadline
    return probe, summary


@dataclass(frozen=True)
class _RequestOptions:
    """One request's body and response expectation, separate from routing."""

    control: str | None = None
    body: dict[str, Any] | None = None
    expect: str | None = None


@dataclass
class _ProbeSender:
    """Collect one fresh bounded probe set, never replaying it during polling."""

    client: transport.Client
    run: str
    required: list[Probe]
    results: list[ProbeResult | RateBurstSummary]

    def send(
        self,
        host: str,
        path: str,
        method: str,
        suffix: str,
        options: _RequestOptions | None = None,
    ) -> int:
        """Record sanitized status and the exact telemetry join identity."""
        options = options if options is not None else _RequestOptions()
        user, sent = self.run + "-" + suffix, time.time()
        code, reply = self.client.request(host, path, method, user, options.body)
        self.results.append({"control": options.control or "positive", "status": code})
        if options.expect == "allow" and not (
            SUCCESS <= code < SUCCESS_END and isinstance(reply, dict)
        ):
            msg = "positive application control failed"
            raise _fail(msg)
        if options.expect == "deny" and code not in (FORBIDDEN, RATE_DENIAL):
            msg = "negative control not blocked"
            raise _fail(msg)
        if options.control:
            self.required.append(
                {
                    "host": host,
                    "path": path.split("?", 1)[0],
                    "method": method,
                    "user": user,
                    "sent_at": sent,
                    "control": options.control,
                }
            )
        return code

    def admin(self, host: str, origin: str, prefix: str) -> None:
        """Prove direct admin availability and independent protected denials."""
        for method in ("POST", "DELETE"):
            self.send(
                origin,
                "/httpbin/anything/admin",
                method,
                prefix + "-direct-" + method.lower(),
                _RequestOptions(body={"demo_id": self.run}, expect="allow"),
            )
            self.send(
                host,
                "/httpbin/anything/admin",
                method,
                prefix + "-deny-" + method.lower(),
                _RequestOptions(
                    control="endpoint-denial", body={"demo_id": self.run}, expect="deny"
                ),
            )

    def schema(self, host: str, prefix: str) -> None:
        """Pair schema violations with valid and unrelated endpoint controls."""
        self.send(
            host,
            "/httpbin/post",
            "POST",
            prefix + "-valid",
            _RequestOptions(body={"demo_id": self.run}, expect="allow"),
        )
        for suffix, body in (("missing", {}), ("wrong", {"demo_id": 123})):
            self.send(
                host,
                "/httpbin/post",
                "POST",
                prefix + "-" + suffix,
                _RequestOptions(control="schema", body=body, expect="deny"),
            )
        self.send(
            host,
            "/httpbin/anything/unrelated",
            "POST",
            prefix + "-unrelated",
            _RequestOptions(body={}, expect="allow"),
        )

    def waf(self, host: str, prefix: str) -> None:
        """Pair benign input with one signature-bearing WAF request."""
        self.send(
            host,
            GET_PATH + "?demo=plain",
            "GET",
            prefix + "-waf-positive",
            _RequestOptions(expect="allow"),
        )
        self.send(
            host,
            WAF_PATH,
            "GET",
            prefix + "-waf",
            _RequestOptions(control="waf", expect="deny"),
        )

    def mud(self, host: str, prefix: str) -> None:
        """Train one synthetic user, retaining separate later mitigation proof."""
        attack_started = time.time()
        for _ in range(BURST_LIMIT):
            self.send(host, WAF_PATH, "GET", prefix + "-mud")
        self.send(
            host, GET_PATH, "GET", prefix + "-mud", _RequestOptions(control="mud")
        )
        self.required[-1]["attack_started_at"] = attack_started
        self.send(
            host,
            GET_PATH,
            "GET",
            prefix + "-mud-negative",
            _RequestOptions(expect="allow"),
        )


def probes(
    client: transport.Client, out: ShowcaseOutputs
) -> tuple[str, list[Probe], list[ProbeResult | RateBurstSummary]]:
    """Send one bounded control set per domain, not per polling iteration."""
    sender = _ProbeSender(client, "showcase-" + uuid.uuid4().hex, [], [])
    for index, host in enumerate(out["domains"]):
        prefix = "d" + str(index)
        sender.admin(host, out["origin"]["public_ip"], prefix)
        sender.schema(host, prefix)
        sender.waf(host, prefix)
        probe, summary = rate_burst(client, host, sender.run + "-" + prefix + "-rate")
        sender.required.append(probe)
        sender.results.append(summary)
        sender.mud(host, prefix)
    return sender.run, sender.required, sender.results


def _acceptance_report(
    run: str, results: list[ProbeResult | RateBurstSummary]
) -> AcceptanceEvidence:
    bursts: list[RateBurstSummary] = []
    count = 0
    for result in results:
        if "status_counts" in result:
            bursts.append(result)
            count += result.get("request_count", 1) + 2
        else:
            count += 1
    return {
        "run_id": run,
        "probe_count": count,
        "controls_attributed": False,
        "scheduled_traffic": False,
        "mud_detection": False,
        "mud_mitigation": False,
        "suspicious_log_count": 0,
        "rate_bursts": bursts,
    }


@dataclass(frozen=True)
class _FreshEvidenceWindow:
    """Capture the exact scope and bounded interval used by one polling read."""

    out: ShowcaseOutputs
    since: float
    end: float

    def matches(self, event: dict[str, Any], probe: Probe) -> bool:
        """Join an ordinary event to its independent control-specific probe."""
        return evaluation.attributed(
            event, probe, self.out["namespace"], self.out["loadbalancer_name"], self.end
        )

    def telemetry(self, events: list[dict[str, Any]], required: list[Probe]) -> bool:
        """Evaluate complete decoded telemetry within this captured interval."""
        return evaluation.telemetry_ready(
            events,
            required,
            self.out["namespace"],
            self.out["loadbalancer_name"],
            self.end,
        )

    def ordinary(
        self, client: transport.Client, required: list[Probe]
    ) -> list[dict[str, Any]]:
        """Read complete bounded windows around each attributed request, excluding background time."""
        events: list[dict[str, Any]] = []
        for probe in required:
            events.extend(
                client.pages(
                    self.out["namespace"],
                    self.out["loadbalancer_name"],
                    probe["sent_at"],
                    self.end,
                    False,
                    probe["user"],
                )
            )
        return list(
            {json.dumps(event, sort_keys=True): event for event in events}.values()
        )

    def suspicious(self, client: transport.Client, required: list[Probe]) -> list[Any]:
        """Page opaque detection records for each fresh identified MUD user."""
        logs: list[Any] = []
        for probe in required:
            logs.extend(
                client.pages(
                    self.out["namespace"],
                    self.out["loadbalancer_name"],
                    self.since,
                    self.end,
                    True,
                    probe["user"],
                )
            )
        return logs


def _rate_attribution(
    evidence: AcceptanceEvidence,
    required: list[Probe],
    events: list[dict[str, Any]],
    window: _FreshEvidenceWindow,
) -> None:
    for summary in evidence["rate_bursts"]:
        probe = next(
            p
            for p in required
            if p["control"] == "rate-limit" and p["host"] == summary["host"]
        )
        summary["attributed_event_count"] = sum(
            window.matches(event, probe) for event in events
        )


def _mud_evidence(
    client: transport.Client,
    evidence: AcceptanceEvidence,
    required: list[Probe],
    events: list[dict[str, Any]],
    window: _FreshEvidenceWindow,
) -> None:
    mud = [probe for probe in required if probe["control"] == "mud"]
    logs = window.suspicious(client, mud)
    evidence["suspicious_log_count"] = len(logs)
    evidence["mud_detection"] = evaluation.detection_ready(
        logs,
        mud,
        events,
        window.out["namespace"],
        window.out["loadbalancer_name"],
        window.end,
    )
    mitigation: list[Probe] = [
        {**probe, "sent_at": probe["mitigation_sent_at"]}
        for probe in mud
        if "mitigation_sent_at" in probe
    ]
    evidence["mud_mitigation"] = (
        len(mitigation) == len(mud)
        and all(p.get("mitigation_blocked") for p in mud)
        and window.telemetry(events, mitigation)
    )
    if evidence["mud_detection"] and not evidence["mud_mitigation"]:
        for probe in mud:
            probe["mitigation_blocked"] = mitigation_probe(client, probe)
    evidence["controls_attributed"] = (
        window.telemetry(events, [p for p in required if p["control"] != "mud"])
        and evidence["mud_mitigation"]
    )


def _traffic_projection(status: Any) -> list[TrafficRunSummary]:
    # Called only after traffic_ready validates the complete fresh scheduled pair.
    return [
        {key: sample[key] for key in TRAFFIC_FIELDS}
        for sample in status["history"][-2:]
    ]


def _poll_acceptance(
    client: transport.Client,
    args: VerifyOptions,
    required: list[Probe],
    evidence: AcceptanceEvidence,
    started: _FreshEvidenceWindow,
) -> int:
    out, invoked_at = started.out, started.since
    since = min(probe["sent_at"] for probe in required)
    while True:
        status = json.loads(
            client.ssh(
                out["generator"], args, "sudo -n /usr/local/bin/tgen-control status"
            )
        )
        failed = evaluation.traffic_failure(status, out["domains"], invoked_at)
        if failed:
            evidence["traffic_failure"] = failed
            evidence["failure"] = "fresh scheduled traffic failed"
            return contracts.FAILURE
        window = _FreshEvidenceWindow(out, since, time.time())
        events = window.ordinary(client, required)
        _rate_attribution(evidence, required, events, window)
        _mud_evidence(client, evidence, required, events, window)
        evidence["scheduled_traffic"] = evaluation.continuous_traffic_ready(
            status, out["domains"], invoked_at
        )
        evidence["traffic_runs"] = []
        evidence["continuous_catalog"] = status.get("catalog_passes", [])
        evidence["continuous_rates"] = status.get("rates", {})
        missing = [gate for gate in GATES if not evidence[gate]]
        if not missing:
            evidence.pop("pending", None)
            return contracts.VERIFIED
        evidence["pending"] = "awaiting fresh evidence: " + ", ".join(missing)
        if time.monotonic() + args.poll_seconds >= client.deadline:
            return contracts.PENDING
        time.sleep(args.poll_seconds)


def acceptance(
    client: transport.Client, out: ShowcaseOutputs, args: VerifyOptions
) -> tuple[int, AcceptanceEvidence]:
    """Require independent control proof and two fresh scheduled measurement runs."""
    invoked_at = time.time()
    scope.effective(client, out)
    run, required, results = probes(client, out)
    evidence = _acceptance_report(run, results)
    code = _poll_acceptance(
        client,
        args,
        required,
        evidence,
        _FreshEvidenceWindow(out, invoked_at, invoked_at),
    )
    return code, evidence


def _arguments(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--outputs-json", required=True)
    parser.add_argument(
        "--phase", required=True, choices=("readiness", "acceptance", "absence")
    )
    parser.add_argument("--timeout-seconds", type=float, default=900)
    parser.add_argument("--poll-seconds", type=float, default=10)
    parser.add_argument("--report", required=True)
    parser.add_argument("--run-manifest")
    parser.add_argument("--ssh-key")
    parser.add_argument("--known-hosts")
    return parser.parse_args(argv)


def _collect(
    client: transport.Client, args: argparse.Namespace, report: VerificationReport
) -> int:
    if args.phase == "absence":
        if not args.run_manifest:
            msg = "run manifest required for absence"
            raise _fail(msg)
        manifest = json.loads(Path(args.run_manifest).read_text(encoding="utf-8"))
        return (
            contracts.VERIFIED if scope.absence(client, manifest) else contracts.PENDING
        )
    out = scope.outputs(args.outputs_json)
    if args.phase == "readiness":
        report["evidence"] = readiness(client, out, args)
        return contracts.VERIFIED
    code, report["evidence"] = acceptance(client, out, args)
    return code


def _write_report(path: Path, report: VerificationReport) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600
    )
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")


def main(argv: list[str] | None = None) -> int:
    """Collect bounded evidence and persist only the existing private report shape."""
    args = _arguments(argv)
    report: VerificationReport = {
        "schema_version": 1,
        "phase": args.phase,
        "verified": False,
        "sources": SOURCES,
    }
    code, client = contracts.FAILURE, None
    try:
        if (
            not 0 < args.timeout_seconds <= MAX_TIMEOUT
            or not 0 < args.poll_seconds <= MAX_POLL
        ):
            msg = "invalid bounded polling settings"
            raise _fail(msg)
        client = transport.Client(time.monotonic() + args.timeout_seconds)
        code = _collect(client, args, report)
        report["verified"] = code == contracts.VERIFIED
    except contracts.EvidenceError as exc:
        report["failure"] = str(exc)
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        report["failure"] = "missing, malformed or inaccessible required evidence"
    if client is not None and client.read_retries:
        report["read_retries"] = client.read_retries
    report["exit_code"] = code
    _write_report(Path(args.report), report)
    print(
        json.dumps(
            {"phase": args.phase, "verified": report["verified"], "exit_code": code}
        )
    )
    return code


if __name__ == "__main__":
    sys.exit(main())
