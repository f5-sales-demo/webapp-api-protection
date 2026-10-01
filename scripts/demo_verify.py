#!/usr/bin/env python3
# ruff: noqa: ANN001,ANN201,ANN202,ANN204,D101,D102,D103,D107,EM101,PLR0911,PLR2004,S310,S603,TRY003,TRY300,TRY301

"""Bounded live showcase verifier; deterministic evaluators are NOT security proof.

Manifest v1 (absence): {schema_version:1, subscription_id, azure_owned:[ARM id],
xc_owned:[{path,uid}], azure_preserved:[], xc_preserved:[{path,uid}],
azure_api_versions:{ARM id: captured provider API version}}.
XC owned paths are exact /api/config/namespaces/... object paths; namespace
preservation uses /api/web/namespaces/{name}.
Guest readiness v1: {ready:true, checks:[{name,ready:true},...]} (all checks).
Generator: {history:[{run_id,sequence,trigger,started_epoch,started_at,
completed_at,domains,count,rate,duration_seconds,latencies,transport_errors,
benign_success,class_counts,status,failures}], timer_active:true}.
Reports whitelist summaries only: never raw API/SSH/HTTP output or identities.

Event field semantics: pinned 20260928 security-events-reference. Only exact
flat fields / documented policy_hits object are supported, never recursive key
search. Suspicious-user item parsing is grounded in the private synthetic live
receipt zerochange-deploy-live-proof-20261001, independently re-read 20261001:
JSON-string records, numeric-second aggregation bounds, nested JSON counters.
Detection and service-policy mitigation are independent, fresh-user joins.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import os
import re
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime
from pathlib import Path

from demo_traffic import evaluate_summary, scheduled_pair

VERIFIED, FAILURE, PENDING = 0, 2, 3
SOURCES = [
    "https://docs.cloud.f5.com/docs-v2/platform/reference/security-events-reference",
    "xcsh://api-catalog/events",
    "xcsh://api-catalog/events-scroll",
    "xcsh://api-catalog/suspicious-user-logs",
    "xcsh://api-catalog/suspicious-user-logs-scroll",
    "xcsh://api-spec/virtual?resource=suspicious_user_logs",
    "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-to/observe/monitor-waap#explore-security-monitoring",
    "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-to/adv-security/malicious-users#enable-malicious-user-mitigation",
]
NAME = re.compile(r"^[a-z][a-z0-9-]{0,62}[a-z0-9]$")
# Generator targets() uses <class>-<run>[-<index>]; acceptance probes use
# showcase-<run>-<domain/control>. Neither permits real user identities.
SYNTHETIC = re.compile(
    r"^(?:showcase-[0-9a-f]{32}-[a-z0-9-]+|"
    r"(?:benign|waf|schema|endpoint-denial|rate-limit|mud)-[0-9a-f]{32}(?:-[0-9]+)?)$"
)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never forward API authorization or accept redirected application proof."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


class EvidenceError(Exception):
    """Safe error containing no upstream strings or credential material."""


def stamp(value):
    if isinstance(value, bool):
        raise EvidenceError("invalid timestamp")
    try:
        if isinstance(value, (int, float)) or str(value).isdigit():
            result = float(value)
        else:
            parsed = datetime.fromisoformat(str(value))
            if parsed.tzinfo is None:
                raise EvidenceError("timestamp lacks timezone")
            result = parsed.timestamp()
        if not math.isfinite(result):
            raise EvidenceError("invalid timestamp")
        return result
    except (ValueError, TypeError, OverflowError) as exc:
        raise EvidenceError("invalid timestamp") from exc


def guest_ready(report):
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


def traffic_failure(status, domains, since):
    """Surface every fresh terminal scheduled failure, including missing metrics."""
    if not isinstance(status, dict) or not isinstance(status.get("history"), list):
        return None
    for run in status["history"]:
        if not isinstance(run, dict) or run.get("trigger") != "scheduled":
            continue
        try:
            if stamp(run["started_epoch"]) < since:
                continue
        except (KeyError, EvidenceError):
            continue
        if run.get("status") in ("pending", "running"):
            continue
        failures = evaluate_summary(run, domains)
        if run.get("status") == "verified" and not failures:
            continue
        rid = run.get("run_id")
        safe_id = rid if isinstance(rid, str) and re.fullmatch(r"[0-9a-f]{32}", rid) else "invalid_run_id"
        error = run.get("error_class")
        allowed = {"configuration", "authorization", "tool_missing", "metrics_unavailable", "metrics_failed", "readiness_failed", "attack_failed"}
        return {"run_id": safe_id, "error_class": error if isinstance(error, str) and error in allowed else "metrics_failed", "metric_failures": failures}
    return None


def traffic_ready(status, domains, since):
    """Fresh adjacent guest-evaluated cycles; no second invented traffic format."""
    if not isinstance(status, dict) or status.get("timer_active") is not True or traffic_failure(status, domains, since):
        return False
    history = status.get("history")
    if (
        not isinstance(history, list)
        or len(history) < 2
        or not all(isinstance(run, dict) for run in history[-2:])
        or not scheduled_pair(history)
    ):
        return False
    try:
        if status.get("run_id") != history[-1]["run_id"]:
            return False
        ids = set()
        sequences = []
        for run in history[-2:]:
            rid = run["run_id"]
            if (
                not isinstance(rid, str)
                or not re.fullmatch(r"[0-9a-f]{32}", rid)
                or rid in ids
            ):
                return False
            ids.add(rid)
            sequence = run["sequence"]
            if (
                isinstance(sequence, bool)
                or not isinstance(sequence, int)
                or sequence < 0
            ):
                return False
            sequences.append(sequence)
            start = stamp(run["started_epoch"])
            finish = stamp(run["completed_at"])
            if (
                start < since
                or finish - start < run["duration_seconds"] - 0.5
                or finish > time.time() + 2
                or abs(stamp(run["started_at"]) - start) > 2
                or evaluate_summary(run, domains)
            ):
                return False
        return sequences[1] == sequences[0] + 1
    except (KeyError, TypeError, EvidenceError, ValueError):
        return False


def virtual_host(lb):
    if not isinstance(lb, str) or not NAME.fullmatch(lb):
        raise EvidenceError("invalid load balancer name")
    return "ves-io-http-loadbalancer-" + lb


def identified_user(user, header="X-MUD-User"):
    if not isinstance(user, str) or not SYNTHETIC.fullmatch(user):
        raise EvidenceError("synthetic user required")
    if header.lower() != "x-mud-user":
        raise EvidenceError("unsupported synthetic identification policy")
    return "Header-" + header.title() + "-" + user


def decode_event(raw):
    """Decode the observed JSON-string wire record once, without shape fallbacks."""
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > 100_000:
        raise EvidenceError("invalid security event encoding")
    try:
        event = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise EvidenceError("invalid security event JSON") from exc
    if not isinstance(event, dict):
        raise EvidenceError("invalid security event object")
    return event


def policy_hits(event):
    wrapper = event.get("policy_hits")
    hits = wrapper.get("policy_hits") if isinstance(wrapper, dict) else None
    if not isinstance(hits, list) or not all(isinstance(hit, dict) for hit in hits):
        return []
    return hits


def attributed(event, probe, namespace, lb, end):
    """Exact joins and control markers, never response status or config UID."""
    if not isinstance(event, dict) or not SYNTHETIC.fullmatch(probe["user"]):
        return False
    try:
        value = event.get("time")
        if not isinstance(value, str) or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})", value
        ):
            return False
        if not (probe["sent_at"] <= stamp(value) <= end):
            return False
    except EvidenceError:
        return False
    if (
        event.get("namespace") != namespace
        or event.get("vh_name") != virtual_host(lb)
        or event.get("domain") != probe["host"]
        or event.get("req_path") != probe["path"]
        or event.get("method") != probe["method"]
        or event.get("user") != identified_user(probe["user"])
        or event.get("action") != "block"
    ):
        return False
    kind = probe["control"]
    if kind == "waf":
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
    if kind == "mud":
        return (
            event.get("sec_event_type") == "svc_policy_sec_event"
            and event.get("sec_event_name") == "Malicious User Mitigation"
            and any(
                hit.get("malicious_user_mitigate_action") == "MUM_BLOCK_TEMPORARILY"
                and hit.get("policy_namespace") == namespace
                and hit.get("policy") == "ves-io-http-loadbalancer-oas-validation-" + lb
                and hit.get("policy_set")
                == "ves-io-http-loadbalancer-waf-exclusion-" + lb
                for hit in policy_hits(event)
            )
        )
    if event.get("sec_event_type") != "api_sec_event":
        return False
    if kind == "schema":
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
    if kind == "endpoint-denial":
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
    if kind == "rate-limit":
        policy_set = "ves-io-http-loadbalancer-rate-limiting-" + lb
        policy = policy_set + "-api-endpoint"
        return (
            probe.get("status") == 429
            and event.get("sec_event_name") == "API Rate Limiting"
            and event.get("rsp_code") == "429"
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
    return False


def telemetry_ready(events, probes, namespace, lb, end):
    return bool(probes) and all(
        any(attributed(e, p, namespace, lb, end) for e in events) for p in probes
    )


def detection_attributed(raw, probe, events, namespace, lb, end):
    """Observed wire contract; High alone is not fresh attack detection proof."""
    try:
        log = decode_event(raw)
        if (
            log.get("namespace") != namespace
            or log.get("vh_name") != virtual_host(lb)
            or log.get("user") != identified_user(probe["user"])
            or log.get("suspicion_log_type") != "detection"
            or log.get("threat_level") != "High"
        ):
            return False
        for field in ("suspicion_score", "waf_suspicion_score"):
            score = log.get(field)
            if type(score) not in (int, float) or score != 1.0:
                return False
        first, last = log.get("start_time"), log.get("end_time")
        if any(
            type(value) not in (int, float) or not math.isfinite(value) or value < 0
            for value in (first, last)
        ):
            return False
        # Live aggregation truncates to seconds. Never interpret milliseconds,
        # strings, or first_event_time/last_event_time aliases as these bounds.
        start = probe["attack_started_at"]
        if not (math.floor(start) <= first <= last <= end):
            return False
        activity = decode_event(log.get("incremental_activity_info"))
        mitigation = decode_event(log.get("mitigation_activity_info"))
        counters = (
            "bot_defense_sec_event_count",
            "err_count",
            "failed_login_count",
            "forbidden_access_count",
            "page_not_found_count",
            "rate_limiting_count",
            "req_count",
            "waf_sec_event_count",
        )
        mitigation_counters = (
            "mum_captcha_challenge",
            "mum_js_challenge",
            "mum_temporarily_blocking",
        )
        for values, fields in ((activity, counters), (mitigation, mitigation_counters)):
            if any(
                type(values.get(key)) is not int or values[key] < 0 for key in fields
            ):
                return False
        if not 0 < activity["waf_sec_event_count"] <= activity["req_count"]:
            return False
        waf_probe = dict(probe, control="waf", sent_at=start)
        return any(
            attributed(event, waf_probe, namespace, lb, min(end, last + 1))
            for event in events
        )
    except (EvidenceError, KeyError, TypeError, ValueError):
        return False


def detection_ready(logs, probes, events, namespace, lb, end):
    return bool(probes) and all(
        any(
            detection_attributed(raw, probe, events, namespace, lb, end) for raw in logs
        )
        for probe in probes
    )


def mitigation_probe(client, probe):
    """Called only after detection; initial allowed responses remain pending."""
    sent = time.time()
    code, _ = client.request(
        probe["host"], probe["path"], probe["method"], probe["user"]
    )
    good, reply = client.request(
        probe["host"], probe["path"], probe["method"], probe["user"] + "-negative"
    )
    if not (200 <= good < 300 and isinstance(reply, dict)):
        raise EvidenceError("independent MUD application control failed")
    if code not in (200, 403):
        raise EvidenceError("unexpected MUD propagation response")
    if "mitigation_sent_at" not in probe:
        probe["mitigation_sent_at"] = sent
    return code == 403


class Client:
    def __init__(self, deadline):
        self.deadline = deadline
        self.read_retries = []
        self.base = os.environ.get("XCSH_API_URL", "").rstrip("/")
        self.token = os.environ.get("XCSH_API_TOKEN", "")
        parsed = urllib.parse.urlsplit(self.base)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.query
        ):
            raise EvidenceError("valid HTTPS XCSH_API_URL required")
        if not self.token:
            raise EvidenceError("XCSH_API_TOKEN required")

    def remaining(self, *, phase_budget=False):
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise EvidenceError("deadline exceeded")
        return left if phase_budget else min(left, 20)

    def command(self, argv, *, phase_budget=False, allowed=(0,)):
        try:
            timeout = self.remaining(phase_budget=phase_budget)
            if phase_budget:
                with subprocess.Popen(
                    argv,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                ) as process:
                    try:
                        stdout, _ = process.communicate(timeout=timeout)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.communicate()
                        raise
            else:
                process = subprocess.run(
                    argv, capture_output=True, check=False, timeout=timeout
                )
                stdout = process.stdout
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise EvidenceError("command unavailable or timed out") from exc
        if process.returncode not in allowed:
            raise EvidenceError("required command failed")
        if len(stdout) > 4_000_000:
            raise EvidenceError("command output exceeded bound")
        return stdout.decode("utf-8")

    def api(self, path, payload=None):
        headers = {"Authorization": "APIToken " + self.token}
        data = None
        if payload is not None:
            data = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base + path, data=data, headers=headers)
        try:
            with HTTP.open(request, timeout=self.remaining()) as response:
                body = response.read(4_000_001)
                if len(body) > 4_000_000:
                    raise EvidenceError("API response exceeded bound")
                return response.status, json.loads(body)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return 404, {}
            raise EvidenceError("API access or service failure") from exc
        except (OSError, ValueError) as exc:
            raise EvidenceError("API transport or JSON failure") from exc

    def azure_exists(self, subscription, rid, api_version):
        """Read an exact ARM object through the existing authenticated Azure CLI."""
        if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}(-preview)?", api_version):
            raise EvidenceError("captured ARM API version required")
        argv = [
            "az",
            "rest",
            "--method",
            "get",
            "--url",
            "https://management.azure.com" + rid + "?api-version=" + api_version,
            "--subscription",
            subscription,
            "--output",
            "json",
            "--verbose",
        ]
        for attempt in range(2):
            reason = None
            try:
                process = subprocess.run(
                    argv, capture_output=True, check=False, timeout=self.remaining()
                )
            except subprocess.TimeoutExpired:
                reason = "timeout"
            except OSError as exc:
                raise EvidenceError("Azure command unavailable") from exc
            if reason is None:
                if len(process.stdout) + len(process.stderr) > 4_000_000:
                    raise EvidenceError("Azure response exceeded bound")
                if not process.returncode:
                    try:
                        resource = json.loads(process.stdout)
                    except ValueError as exc:
                        raise EvidenceError("Azure JSON failure") from exc
                    if (
                        not isinstance(resource, dict)
                        or not isinstance(resource.get("id"), str)
                        or resource["id"].lower() != rid.lower()
                    ):
                        raise EvidenceError("Azure identity response mismatch")
                    return True
                # Only exact GET failures may retry; diagnostics never contain
                # CLI stderr, request identifiers, credentials or resource names.
                error = process.stderr.decode("utf-8", errors="replace")
                statuses = re.findall(
                    r"^INFO:\s*(?:azure\.cli\.core\.util:\s*)?Response status:\s*(\d{3})\s*$",
                    error,
                    re.MULTILINE,
                )
                if statuses == ["404"]:
                    try:
                        body, _ = json.JSONDecoder().raw_decode(
                            error[error.index("{") :]
                        )
                    except ValueError as exc:
                        raise EvidenceError("Azure not-found JSON failure") from exc
                    arm_error = body.get("error") if isinstance(body, dict) else None
                    if (
                        not isinstance(arm_error, dict)
                        or arm_error.get("code")
                        not in ("ResourceNotFound", "ResourceGroupNotFound")
                        or (
                            "target" in arm_error
                            and arm_error["target"] != rid
                        )
                    ):
                        raise EvidenceError("Azure not-found response unproven")
                    message = arm_error.get("message", "")
                    if not isinstance(message, str):
                        raise EvidenceError("Azure error response malformed")
                    referenced_ids = re.findall(
                        r"/subscriptions/[A-Za-z0-9_./-]+", message
                    )
                    if any(value.lower() != rid.lower() for value in referenced_ids):
                        raise EvidenceError("Azure not-found identity mismatch")
                    return False
                if statuses in (["429"], ["503"]):
                    reason = "http-" + statuses[0]
                elif not statuses and re.search(
                    r"(?:requests\.exceptions\.|urllib3\.exceptions\.)"
                    r"(?:ConnectionError|ReadTimeout|ConnectTimeout|ProtocolError|"
                    r"NewConnectionError|NameResolutionError|MaxRetryError)\b",
                    error,
                ):
                    reason = "transport"
                else:
                    raise EvidenceError("Azure access or service failure; absence unproven")
            if attempt or self.deadline - time.monotonic() <= 1:
                raise EvidenceError("Azure transient read failed; absence unproven")
            self.read_retries.append({"reason": reason, "attempt": 1})
            time.sleep(1)
        raise EvidenceError("Azure read failed; absence unproven")

    def pages(self, namespace, lb, since, end, suspicious=False, user=None):
        resource, key = (
            ("suspicious_user_logs", "logs") if suspicious else ("events", "events")
        )
        path = f"/api/data/namespaces/{namespace}/app_security/{resource}"
        # Catalog permits event field matchers. Live comparison: canonical
        # vh_name returns 11 known records; catalog spelling Vh_name returns 0.
        query = "{vh_name=" + json.dumps(virtual_host(lb))
        if user is not None:
            identity = identified_user(user)
            if suspicious:
                query += ",user=" + json.dumps(identity)
        query += "}"
        payload = {
            "query": query,
            "start_time": str(int(since)),
            "end_time": str(int(end) + 1),
            "limit": 500,
            "scroll": True,
        }
        code, page = self.api(path, payload)
        records, tokens, total = [], set(), None
        for _ in range(20):
            if (
                code != 200
                or not isinstance(page, dict)
                or not isinstance(page.get(key), list)
            ):
                raise EvidenceError("malformed telemetry page")
            batch = page[key]
            if len(batch) > 500 or page.get("errors") or page.get("truncated"):
                raise EvidenceError("incomplete telemetry")
            try:
                page_total = int(page["total_hits"])
            except (KeyError, TypeError, ValueError) as exc:
                raise EvidenceError("unknown telemetry coverage") from exc
            if total is None:
                total = page_total
            if total != page_total or total < 0:
                raise EvidenceError("inconsistent telemetry coverage")
            records.extend(
                batch if suspicious else [decode_event(raw) for raw in batch]
            )
            token = page.get("scroll_id", "")
            if not isinstance(token, str) or len(records) > total:
                raise EvidenceError("invalid telemetry coverage")
            # Live service retains scroll_id even when all total_hits have been
            # returned. Exact count proves completion without an empty scroll.
            if len(records) == total:
                return records
            if not token:
                raise EvidenceError("truncated telemetry coverage")
            if token in tokens or not batch:
                raise EvidenceError("invalid pagination progress")
            tokens.add(token)
            code, page = self.api(path + "/scroll", {"scroll_id": token})
        raise EvidenceError("telemetry pagination exceeded bound")

    def ssh(self, vm, args, remote, *, phase_budget=False, allowed=(0,)):
        if not args.ssh_key or not args.known_hosts:
            raise EvidenceError("dedicated SSH key and known-hosts required")
        ipaddress.ip_address(vm["public_ip"])
        username = vm["admin_username"]
        if not re.fullmatch(r"[a-z_][a-z0-9_-]*", username):
            raise EvidenceError("invalid SSH username")
        return self.command(
            [
                "ssh",
                "-i",
                args.ssh_key,
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "ConnectTimeout=10",
                "-o",
                "UserKnownHostsFile=" + args.known_hosts,
                username + "@" + vm["public_ip"],
                remote,
            ],
            phase_budget=phase_budget,
            allowed=allowed,
        )

    def request(self, host, path, method, user, body=None):
        if not SYNTHETIC.fullmatch(user):
            raise EvidenceError("synthetic user required")
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            "http://" + host + path,
            data=data,
            method=method,
            headers={"X-MUD-User": user, "Content-Type": "application/json"},
        )
        try:
            with HTTP.open(request, timeout=self.remaining()) as response:
                raw = response.read(1_000_001)
                code = response.status
        except urllib.error.HTTPError as exc:
            code, raw = exc.code, exc.read(1_000_001)
        except OSError as exc:
            raise EvidenceError("application transport failure") from exc
        if len(raw) > 1_000_000:
            raise EvidenceError("application body exceeded bound")
        try:
            result = json.loads(raw)
        except ValueError:
            result = None
        return code, result


def outputs(path):
    value = json.loads(Path(path).read_text())
    if "showcase" in value:
        value = value["showcase"]["value"]
    for key in ("namespace", "loadbalancer_name"):
        if not NAME.fullmatch(value[key]):
            raise EvidenceError("invalid output resource name")
    if len(value["domains"]) != 2 or len(set(value["domains"])) != 2:
        raise EvidenceError("two distinct domains required")
    for host in value["domains"]:
        if not re.fullmatch(r"[a-z0-9.-]+", host) or "." not in host:
            raise EvidenceError("invalid output domain")
    expected = {
        "waf_mode": "blocking",
        "csd_enabled": False,
        "mud_enabled": True,
        "mud_user_id": "user_identification",
        "api_definition_choice": "specification",
        "api_specification_validation": "all_spec_endpoints",
        "api_validation_request_mode": "block",
        "rate_limiting_mode": "api_rate_limit",
    }
    if any(value["protection"].get(k) != v for k, v in expected.items()):
        raise EvidenceError("showcase protection outputs mismatch")
    return value


def effective(client, out):
    namespace, lb = out["namespace"], out["loadbalancer_name"]
    code, config = client.api(
        f"/api/config/namespaces/{namespace}/http_loadbalancers/{lb}"
    )
    if code != 200:
        raise EvidenceError("load balancer unavailable")
    metadata = config.get("metadata", {})
    if metadata.get("name") != lb or metadata.get("namespace") != namespace:
        raise EvidenceError("effective load balancer scope mismatch")
    spec = config.get("spec", {})

    def object_field(value, key):
        child = value.get(key, {}) if isinstance(value, dict) else None
        if not isinstance(child, dict):
            raise EvidenceError("malformed effective control configuration")
        return child

    def selected(value, arm, alternatives=()):
        # An empty-object marker selects a oneOf arm; truthiness does not.
        return (
            isinstance(value, dict)
            and isinstance(value.get(arm), dict)
            and all(value.get(other) is None for other in alternatives)
        )

    def reference(ref):
        if (
            not isinstance(ref, dict)
            or ref.get("namespace") != namespace
            or not isinstance(ref.get("name"), str)
            or not NAME.fullmatch(ref["name"])
        ):
            raise EvidenceError("effective control reference mismatch")
        return ref

    validation = object_field(
        object_field(
            object_field(spec, "api_specification"), "validation_all_spec_endpoints"
        ),
        "validation_mode",
    )
    challenge_arms = (
        "enable_challenge",
        "policy_based_challenge",
        "no_challenge",
        "js_challenge",
        "captcha_challenge",
    )
    challenges = [k for k in challenge_arms if spec.get(k) is not None]
    if (
        set(spec.get("domains", [])) != set(out["domains"])
        or config.get("metadata", {}).get("disable")
        or spec.get("client_side_defense") is not None
        or not selected(spec, "enable_api_discovery", ("disable_api_discovery",))
        or not selected(
            spec,
            "enable_malicious_user_detection",
            ("disable_malicious_user_detection",),
        )
        or not selected(spec, "user_identification", ("user_id_client_ip",))
        or not selected(spec, "api_rate_limit", ("disable_rate_limit", "rate_limit"))
        or not selected(spec, "api_specification", ("disable_api_definition",))
        or not selected(validation, "validation_mode_active", ("skip_validation",))
        or not selected(
            validation.get("validation_mode_active", {}),
            "enforcement_block",
            ("enforcement_report",),
        )
        or not selected(spec, "app_firewall", ("disable_waf",))
        or len(challenges) != 1
        or challenges[0] not in ("enable_challenge", "policy_based_challenge")
    ):
        raise EvidenceError("effective control configuration mismatch")
    challenge = spec[challenges[0]]
    if not selected(
        challenge, "malicious_user_mitigation", ("default_mitigation_settings",)
    ):
        raise EvidenceError("effective MUD mitigation attachment missing")
    reference(spec["api_specification"].get("api_definition"))
    rules = spec["api_rate_limit"].get("api_endpoint_rules", [])
    rule = rules[0] if isinstance(rules, list) and rules else None
    if not (
        isinstance(rule, dict)
        and rule.get("api_endpoint_path") == "/httpbin/anything/rate-limit"
        and rule.get("api_endpoint_method", {}).get("methods") == ["GET"]
        and not rule["api_endpoint_method"].get("invert_matcher", False)
        and not rule.get("base_path")
        and selected(rule, "any_domain", ("specific_domain",))
        and selected(rule, "inline_rate_limiter", ("ref_rate_limiter",))
        and rule["inline_rate_limiter"].get("threshold") == 20
        and rule["inline_rate_limiter"].get("unit") == "MINUTE"
        and selected(
            rule["inline_rate_limiter"], "use_http_lb_user_id", ("ref_user_id",)
        )
    ):
        raise EvidenceError("effective API rate limit configuration mismatch")
    ref = reference(spec["app_firewall"])
    code, waf = client.api(
        f"/api/config/namespaces/{namespace}/app_firewalls/{ref['name']}"
    )
    if (
        code != 200
        or waf.get("metadata", {}).get("disable")
        or not selected(waf.get("spec", {}), "blocking", ("monitoring",))
    ):
        raise EvidenceError("effective WAF not blocking")
    ref = reference(spec["user_identification"])
    code, identity = client.api(
        f"/api/config/namespaces/{namespace}/user_identifications/{ref['name']}"
    )
    if (
        code != 200
        or identity.get("metadata", {}).get("disable")
        or identity.get("spec", {}).get("rules") != [{"http_header_name": "X-MUD-User"}]
    ):
        raise EvidenceError("effective synthetic-user header identification mismatch")
    ref = reference(challenge["malicious_user_mitigation"])
    code, mitigation = client.api(
        f"/api/config/namespaces/{namespace}/malicious_user_mitigations/{ref['name']}"
    )
    rules = object_field(object_field(mitigation, "spec"), "mitigation_type").get(
        "rules", []
    )
    if (
        code != 200
        or mitigation.get("metadata", {}).get("disable")
        or not isinstance(rules, list)
        or len(rules) != 3
        or not all(
            sum(
                isinstance(rule, dict)
                and rule.get("threat_level") == {level: {}}
                and rule.get("mitigation_action") == {"block_temporarily": {}}
                for rule in rules
            )
            == 1
            for level in ("low", "medium", "high")
        )
    ):
        raise EvidenceError("effective MUD temporary-block policy mismatch")


# Observed cloud-init 26.1 Azure PPS retry, copied into all four stages.
# This is a recovered reprovision fetch, NOT an unused/optional endpoint.
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


def cloud_init_state(report):
    """Return pending/terminal diagnostic; never echo guest warning text."""
    if not isinstance(report, dict):
        raise EvidenceError("cloud-init malformed status")
    stages = {"overall": report}
    for name in CLOUD_STAGES:
        if name in report:
            if not isinstance(report[name], dict):
                raise EvidenceError("cloud-init malformed stage")
            stages[name] = report[name]
    for stage in stages.values():
        if not isinstance(stage.get("errors", []), list) or not isinstance(
            stage.get("recoverable_errors", {}), dict
        ):
            raise EvidenceError("cloud-init malformed error evidence")
    if any(stage.get("errors") for stage in stages.values()):
        raise EvidenceError("cloud-init reported fatal errors")
    status = report.get("status")
    extended = report.get("extended_status", status)
    if status in ("running", "not run") and extended in (
        "running",
        "degraded running",
        "not run",
        "degraded not run",
    ):
        # Recoverable warnings are not a terminal failure while modules run.
        return None
    if status != "done" or extended not in ("done", "degraded done"):
        raise EvidenceError("cloud-init incomplete or degraded")
    recoverable = any(stage.get("recoverable_errors") for stage in stages.values())
    diagnostic = {"status": "done", "fatal_errors": 0, "warnings_accepted": 0}
    if not recoverable:
        if extended != "done":
            raise EvidenceError("cloud-init inconsistent degraded status")
        return diagnostic
    expected = {"WARNING": [AZURE_REPROVISION_WARNING]}
    if (
        extended != "degraded done"
        or report.get("datasource") != "azure"
        or report.get("errors") != []
        or report.get("stage") is not None
        or report.get("recoverable_errors")
        != {"WARNING": [AZURE_REPROVISION_WARNING] * 4}
        or any(
            name not in stages
            or stages[name].get("errors") != []
            or stages[name].get("recoverable_errors") != expected
            or not isinstance(stages[name].get("start"), (int, float))
            or isinstance(stages[name].get("start"), bool)
            or not isinstance(stages[name].get("finished"), (int, float))
            or isinstance(stages[name].get("finished"), bool)
            or not math.isfinite(stages[name]["start"])
            or not math.isfinite(stages[name]["finished"])
            or not 0 < stages[name]["start"] <= stages[name]["finished"]
            for name in CLOUD_STAGES
        )
    ):
        raise EvidenceError("cloud-init disallowed recoverable errors")
    return {
        **diagnostic,
        "status": "degraded_done",
        "warnings_accepted": 4,
        "reason": "Azure PPS reprovisiondata first-attempt 404 recovered before "
        "all stages completed; final unit and application readiness required",
        "sources": CLOUD_INIT_SOURCES,
    }


def readiness(client, out, args):
    effective(client, out)
    cloud_info = {}
    for role in ("origin", "generator"):
        while True:
            client.remaining(phase_budget=True)
            report = json.loads(
                client.ssh(
                    out[role],
                    args,
                    "sudo -n cloud-init status --format json",
                    allowed=(0, 2),
                )
            )
            diagnostic = cloud_init_state(report)
            if diagnostic is not None:
                unit = client.ssh(
                    out[role],
                    args,
                    "systemctl show cloud-final.service -p Result -p ExecMainStatus",
                )
                if set(unit.splitlines()) != {"Result=success", "ExecMainStatus=0"}:
                    raise EvidenceError(role + " cloud-final unit failed")
                diagnostic["final_unit_success"] = True
                cloud_info[role] = diagnostic
                break
            time.sleep(min(args.poll_seconds, client.remaining(phase_budget=True)))
    native = json.loads(
        client.ssh(
            out["origin"],
            args,
            "sudo -n /usr/local/bin/demo-origin-ready",
            phase_budget=True,
        )
    )
    if not guest_ready(native):
        raise EvidenceError("origin service or replica readiness failed")
    for domain in out["domains"]:
        client.command(["getent", "ahosts", domain])
        user = "showcase-" + uuid.uuid4().hex + "-ready"
        code, body = client.request(domain, "/httpbin/get", "GET", user)
        route = (
            urllib.parse.urlsplit(body.get("url", ""))
            if isinstance(body, dict)
            else None
        )
        if (
            code != 200
            or route is None
            or route.scheme != "http"
            or route.hostname != domain
            or route.path != "/get"
            or route.query
            or route.fragment
            or route.username
            or route.port not in (None, 80)
        ):
            raise EvidenceError("expected live application response missing")
    return {
        "effective_controls": True,
        "cloud_init": True,
        "cloud_init_info": cloud_info,
        "origin_checks": len(native["checks"]),
        "application_domains": 2,
    }


RATE_BUCKET_SOURCE = "https://my.f5.com/manage/s/article/K000161473"


def rate_origin(code, reply, host, path, user):
    route = (
        urllib.parse.urlsplit(reply.get("url", "")) if isinstance(reply, dict) else None
    )
    headers = reply.get("headers", {}) if isinstance(reply, dict) else {}
    if (
        code != 200
        or route is None
        or route.scheme != "http"
        or route.hostname != host
        or route.path != path.removeprefix("/httpbin")
        or route.query
        or route.fragment
        or route.username
        or route.port not in (None, 80)
        or not isinstance(headers, dict)
        or headers.get("X-Mud-User") != user
    ):
        raise EvidenceError("rate positive origin URL or identified-user echo mismatch")


def rate_burst(client, host, user):
    """Bounded endpoint saturation, not a fixed-window request-21 assertion."""
    path = "/httpbin/anything/rate-limit"
    started = time.monotonic()
    original_deadline = client.deadline
    client.deadline = min(original_deadline, started + 30)
    statuses, denials = {}, []
    summary = {
        "control": "rate-burst",
        "host": host,
        "request_limit": 30,
        "duration_budget_seconds": client.deadline - started,
        "threshold": 20,
        "unit": "MINUTE",
        "identity": "X-MUD-User",
        "status_counts": statuses,
        "bucket_semantics": "capacity returns during traffic; no fixed request-21 denial",
        "bucket_semantics_source": RATE_BUCKET_SOURCE,
        "rate_proof_source": "fresh API Rate Limiting / fail / rate_limiter_drop / rule-0",
    }
    try:
        for index in range(30):
            if time.monotonic() >= client.deadline:
                raise EvidenceError("probe duration budget exhausted; burst too slow")
            sent = time.time()
            code, reply = client.request(host, path, "GET", user)
            statuses[str(code)] = statuses.get(str(code), 0) + 1
            if index == 0 or code == 200:
                rate_origin(code, reply, host, path, user)
            elif code != 429:
                raise EvidenceError(
                    "rate probe unexpected response; only HTTP 429 proves denial"
                )
            if code == 429:
                denials.append({"request": index + 1, "sent_at": sent})
            if time.monotonic() >= client.deadline:
                raise EvidenceError("probe duration budget exhausted; burst too slow")
        if not denials:
            raise EvidenceError(
                "no HTTP 429 in bounded burst; policy or transport pacing unproven"
            )
        burst_end = time.time()
        burst_duration = time.monotonic() - started
        client.deadline = original_deadline
        for control_path, control_user in (
            (path, user + "-independent"),
            ("/httpbin/get", user),
        ):
            code, reply = client.request(host, control_path, "GET", control_user)
            rate_origin(code, reply, host, control_path, control_user)
        summary.update(
            request_count=sum(statuses.values()),
            duration_seconds=burst_duration,
            denial_count=len(denials),
            first_denial_request=denials[0]["request"],
            independent_user_allowed=True,
            same_user_unrelated_path_allowed=True,
        )
        return {
            "host": host,
            "path": path,
            "method": "GET",
            "user": user,
            "sent_at": denials[0]["sent_at"],
            "burst_end": burst_end,
            "control": "rate-limit",
            "status": 429,
            "denial_requests": denials,
        }, summary
    except EvidenceError as exc:
        summary.update(
            request_count=sum(statuses.values()),
            duration_seconds=time.monotonic() - started,
            diagnostic=str(exc),
        )
        raise EvidenceError(
            "rate burst failed: " + json.dumps(summary, sort_keys=True)
        ) from exc
    finally:
        client.deadline = original_deadline


def probes(client, out):
    """One bounded set per invocation; never repeat probes in telemetry polling."""
    run = "showcase-" + uuid.uuid4().hex
    required, results = [], []

    def send(host, path, method, suffix, control=None, body=None, expect=None):
        user = run + "-" + suffix
        sent = time.time()
        code, reply = client.request(host, path, method, user, body)
        results.append({"control": control or "positive", "status": code})
        if expect == "allow" and not (200 <= code < 300 and isinstance(reply, dict)):
            raise EvidenceError("positive application control failed")
        if expect == "deny" and code not in (403, 429):
            raise EvidenceError("negative control not blocked")
        if control:
            required.append(
                {
                    "host": host,
                    "path": path.split("?", 1)[0],
                    "method": method,
                    "user": user,
                    "sent_at": sent,
                    "control": control,
                }
            )
        return code

    for index, host in enumerate(out["domains"]):
        prefix = "d" + str(index)
        for method in ("POST", "DELETE"):
            send(
                out["origin"]["public_ip"],
                "/httpbin/anything/admin",
                method,
                prefix + "-direct-" + method.lower(),
                body={"demo_id": run},
                expect="allow",
            )
            send(
                host,
                "/httpbin/anything/admin",
                method,
                prefix + "-deny-" + method.lower(),
                "endpoint-denial",
                {"demo_id": run},
                "deny",
            )
        send(
            host,
            "/httpbin/post",
            "POST",
            prefix + "-valid",
            body={"demo_id": run},
            expect="allow",
        )
        for suffix, body in (("missing", {}), ("wrong", {"demo_id": 123})):
            send(
                host,
                "/httpbin/post",
                "POST",
                prefix + "-" + suffix,
                "schema",
                body,
                "deny",
            )
        send(
            host,
            "/httpbin/anything/unrelated",
            "POST",
            prefix + "-unrelated",
            body={},
            expect="allow",
        )
        send(
            host,
            "/httpbin/get?demo=plain",
            "GET",
            prefix + "-waf-positive",
            expect="allow",
        )
        send(
            host,
            "/httpbin/get?demo=" + urllib.parse.quote("' OR 1=1--"),
            "GET",
            prefix + "-waf",
            "waf",
            expect="deny",
        )
        rate_probe, rate_summary = rate_burst(
            client, host, run + "-" + prefix + "-rate"
        )
        required.append(rate_probe)
        results.append(rate_summary)
        # Fresh user, bounded 30 WAF inputs; no real identity or source-IP targeting.
        attack_started = time.time()
        for _ in range(30):
            send(
                host,
                "/httpbin/get?demo=" + urllib.parse.quote("' OR 1=1--"),
                "GET",
                prefix + "-mud",
            )
        send(host, "/httpbin/get", "GET", prefix + "-mud", "mud")
        required[-1]["attack_started_at"] = attack_started
        send(host, "/httpbin/get", "GET", prefix + "-mud-negative", expect="allow")
    return run, required, results


def acceptance(client, out, args):
    invoked_at = time.time()
    effective(client, out)
    run, required, results = probes(client, out)
    since = min(p["sent_at"] for p in required)
    evidence = {
        "run_id": run,
        "probe_count": sum(
            r.get("request_count", 1) + (2 if r["control"] == "rate-burst" else 0)
            for r in results
        ),
        "controls_attributed": False,
        "scheduled_traffic": False,
        "mud_detection": False,
        "mud_mitigation": False,
        "suspicious_log_count": 0,
        "rate_bursts": [r for r in results if r["control"] == "rate-burst"],
    }
    while True:
        status = json.loads(
            client.ssh(
                out["generator"], args, "sudo -n /usr/local/bin/tgen-control status"
            )
        )
        failed = traffic_failure(status, out["domains"], invoked_at)
        if failed:
            evidence["traffic_failure"] = failed
            evidence["failure"] = "fresh scheduled traffic failed"
            return FAILURE, evidence
        end = time.time()
        events = client.pages(out["namespace"], out["loadbalancer_name"], since, end)
        for summary in evidence["rate_bursts"]:
            rate_probe = next(
                p
                for p in required
                if p["control"] == "rate-limit" and p["host"] == summary["host"]
            )
            summary["attributed_event_count"] = sum(
                attributed(
                    event, rate_probe, out["namespace"], out["loadbalancer_name"], end
                )
                for event in events
            )
        mud_probes = [p for p in required if p["control"] == "mud"]
        suspicious = []
        # The documented envelope is paged completely; opaque items are not
        # converted into invented detection proof or copied into the report.
        for probe in mud_probes:
            suspicious.extend(
                client.pages(
                    out["namespace"],
                    out["loadbalancer_name"],
                    since,
                    end,
                    True,
                    probe["user"],
                )
            )
        evidence["suspicious_log_count"] = len(suspicious)
        evidence["mud_detection"] = detection_ready(
            suspicious,
            mud_probes,
            events,
            out["namespace"],
            out["loadbalancer_name"],
            end,
        )
        mitigation_probes = [
            dict(p, sent_at=p["mitigation_sent_at"])
            for p in mud_probes
            if "mitigation_sent_at" in p
        ]
        evidence["mud_mitigation"] = (
            len(mitigation_probes) == len(mud_probes)
            and all(p.get("mitigation_blocked") for p in mud_probes)
            and telemetry_ready(
                events,
                mitigation_probes,
                out["namespace"],
                out["loadbalancer_name"],
                end,
            )
        )
        if evidence["mud_detection"] and not evidence["mud_mitigation"]:
            for probe in mud_probes:
                probe["mitigation_blocked"] = mitigation_probe(client, probe)
        evidence["controls_attributed"] = (
            telemetry_ready(
                events,
                [p for p in required if p["control"] != "mud"],
                out["namespace"],
                out["loadbalancer_name"],
                end,
            )
            and evidence["mud_mitigation"]
        )
        evidence["scheduled_traffic"] = traffic_ready(
            status, out["domains"], invoked_at
        )
        evidence["traffic_runs"] = []
        if evidence["scheduled_traffic"]:
            for sample in status["history"][-2:]:
                evidence["traffic_runs"].append(
                    {
                        key: sample[key]
                        for key in (
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
                    }
                )
        gates = (
            "controls_attributed",
            "scheduled_traffic",
            "mud_detection",
            "mud_mitigation",
        )
        missing = [gate for gate in gates if not evidence[gate]]
        if not missing:
            evidence.pop("pending", None)
            return VERIFIED, evidence
        evidence["pending"] = "awaiting fresh evidence: " + ", ".join(missing)
        if time.monotonic() + args.poll_seconds >= client.deadline:
            return PENDING, evidence
        time.sleep(args.poll_seconds)


def absence(client, manifest):
    if manifest.get("schema_version") != 1:
        raise EvidenceError("owned manifest version required")
    owned = manifest.get("azure_owned", []) + manifest.get("xc_owned", [])
    preserved = manifest.get("azure_preserved", []) + manifest.get("xc_preserved", [])
    if (
        not owned
        or not preserved
        or any(not manifest.get(k) for k in ("azure_owned", "xc_owned", "xc_preserved"))
        or manifest.get("azure_preserved") != []
    ):
        raise EvidenceError(
            "complete owned and external foundation preservation manifest required"
        )
    sub = manifest["subscription_id"]
    if not re.fullmatch(r"[0-9a-f-]{36}", sub):
        raise EvidenceError("invalid subscription scope")
    azure_deleted = set(manifest["azure_owned"])
    azure_retained = set(manifest["azure_preserved"])
    xc_deleted = {o["path"] for o in manifest["xc_owned"]}
    xc_retained = {o["path"] for o in manifest["xc_preserved"]}
    if azure_deleted & azure_retained or xc_deleted & xc_retained:
        raise EvidenceError("owned and preserved scopes overlap")
    outcomes = []
    for group, present in (("azure_owned", False), ("azure_preserved", True)):
        for rid in manifest[group]:
            if (
                not isinstance(rid, str)
                or not re.fullmatch(r"/[A-Za-z0-9_./-]+", rid)
                or ".." in rid
                or not rid.lower().startswith(
                    "/subscriptions/" + sub.lower() + "/resourcegroups/"
                )
            ):
                raise EvidenceError("manifest Azure scope mismatch")
            actual = client.azure_exists(sub, rid, manifest["azure_api_versions"][rid])
            outcomes.append(actual is present)
    for group, present in (("xc_owned", False), ("xc_preserved", True)):
        for obj in manifest[group]:
            path = obj["path"]
            object_path = re.fullmatch(
                r"/api/config/namespaces/[a-z0-9-]+/[a-z_]+/[a-z0-9-]+", path
            )
            namespace_path = present and re.fullmatch(
                r"/api/web/namespaces/[a-z][a-z0-9-]*[a-z0-9]", path
            )
            if not (object_path or namespace_path) or not obj.get("uid"):
                raise EvidenceError("exact captured XC object identity required")
            code, response = client.api(path)
            outcomes.append(
                (
                    code == 200
                    and response.get("system_metadata", {}).get("uid") == obj["uid"]
                )
                if present
                else code == 404
            )
    return all(outcomes)


def main(argv=None):
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
    args = parser.parse_args(argv)
    report = {
        "schema_version": 1,
        "phase": args.phase,
        "verified": False,
        "sources": SOURCES,
    }
    code = FAILURE
    client = None
    try:
        if not 0 < args.timeout_seconds <= 3600 or not 0 < args.poll_seconds <= 60:
            raise EvidenceError("invalid bounded polling settings")
        client = Client(time.monotonic() + args.timeout_seconds)
        if args.phase == "absence":
            if not args.run_manifest:
                raise EvidenceError("run manifest required for absence")
            passed = absence(client, json.loads(Path(args.run_manifest).read_text()))
            code = VERIFIED if passed else PENDING
        else:
            out = outputs(args.outputs_json)
            if args.phase == "readiness":
                report["evidence"] = readiness(client, out, args)
                code = VERIFIED
            else:
                code, report["evidence"] = acceptance(client, out, args)
        report["verified"] = code == VERIFIED
    except EvidenceError as exc:
        report["failure"] = str(exc)
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        report["failure"] = "missing, malformed or inaccessible required evidence"
    if client is not None and client.read_retries:
        report["read_retries"] = client.read_retries
    report["exit_code"] = code
    path = Path(args.report)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    print(
        json.dumps(
            {"phase": args.phase, "verified": report["verified"], "exit_code": code}
        )
    )
    return code


if __name__ == "__main__":
    sys.exit(main())
