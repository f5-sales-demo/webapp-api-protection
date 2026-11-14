"""Continuous synthetic AI comparison traffic; never a catalog acceptance receipt."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import re
import signal
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.client import HTTPException
from pathlib import Path
from typing import Any

HOSTS = {
    phase: "ai-waf-" + phase + ".f5-sales-demo.com" for phase in ("before", "after")
}
MAX_RESPONSE = 1_000_000
LOG_BYTES = 1_000_000
AGGREGATE_RPS = 2
EXAMPLE_COUNT = 18
HTTP_OK = 200


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Keep every request inside the declared pair, including redirect responses."""

    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        """Return every redirect to the caller instead of following its location."""
        return


def load(config_path: Path, fixture_path: Path) -> tuple[dict, dict]:
    """Reject scope or immutable-fixture substitution before opening a connection."""
    config = json.loads(config_path.read_bytes())
    raw = fixture_path.read_bytes()
    fixture = json.loads(raw)
    if any(
        (
            config.get("schema_version") != 1,
            config.get("hosts") != HOSTS,
            config.get("aggregate_rps") != AGGREGATE_RPS,
            config.get("fixture_sha256") != hashlib.sha256(raw).hexdigest(),
            fixture.get("schema_version") != 1,
            fixture.get("path") != "/httpbin/anything/ai-waf",
            fixture.get("diagnostic_only") is not True,
        )
    ):
        message = "AI traffic configuration or immutable fixture differs"
        raise ValueError(message)
    rows = fixture.get("requests")
    if not isinstance(rows, list) or len(rows) != EXAMPLE_COUNT:
        message = "AI traffic requires the complete 18-example rotation"
        raise ValueError(message)
    labels = set()
    for row in rows:
        if not isinstance(row, dict):
            message = "AI traffic fixture entry is invalid"
            raise TypeError(message)
        if (
            not isinstance(row.get("label"), str)
            or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", row["label"])
            or row["label"] in labels
            or row.get("kind") not in ("benign", "attack")
            or not isinstance(row.get("input"), str)
        ):
            message = "AI traffic fixture entry is invalid"
            raise ValueError(message)
        if row.get("expected_status") not in (
            {"before": 200, "after": 200},
            {"before": 403, "after": 403},
            {"before": 403, "after": 200},
        ):
            message = "AI traffic fixture response contract is invalid"
            raise ValueError(message)
        labels.add(row["label"])
    return config, fixture


def origin_echo(body: object, host: str, user: str, item: dict, path: str) -> bool:
    """Verify a successful response came from the intended native echo route."""
    if not isinstance(body, dict) or not isinstance(body.get("headers"), dict):
        return False
    headers = {key.lower(): value for key, value in body["headers"].items()}
    url = urllib.parse.urlsplit(str(body.get("url", "")))
    return (
        body.get("method") == "GET"
        and body.get("args") == {"input": item["input"]}
        and headers.get("host") == host
        and headers.get("x-mud-user") == user
        and url.hostname == host
        and url.path == path.removeprefix("/httpbin")
        and urllib.parse.parse_qs(url.query) == {"input": [item["input"]]}
    )


def bounded_response(raw: bytes) -> None:
    """Reject truncated oversized responses instead of accepting their status code."""
    if len(raw) > MAX_RESPONSE:
        message = "AI traffic response exceeds bound"
        raise ValueError(message)


def response_framing(raw: bytes, declared_length: str | None) -> None:
    """Bounded reads can return short bodies without raising IncompleteRead."""
    if declared_length is not None and (
        not declared_length.isdecimal() or len(raw) != int(declared_length)
    ):
        message = "AI traffic response body length differs from HTTP framing"
        raise HTTPException(message)


def request(
    http: urllib.request.OpenerDirector,
    host: str,
    phase: str,
    item: dict,
    path: str,
    rotation: str,
) -> dict:
    """Keep wire target, response hash, identity and failures for each actual request."""
    user = "showcase-" + rotation + "-ai-waf-" + phase + "-" + item["label"]
    target = path + "?" + urllib.parse.urlencode({"input": item["input"]})
    record = {
        "rotation": rotation,
        "phase": phase,
        "label": item["label"],
        "kind": item["kind"],
        "host": host,
        "user": user,
        "request_target": target,
        "sent_at": time.time(),
        "status": 0,
        "expected_status": item["expected_status"][phase],
        "origin_echo": False,
        "transport_failure": False,
    }
    try:
        req = urllib.request.Request(
            "https://" + host + target,
            headers={"X-MUD-User": user, "Content-Type": "application/json"},
        )
        try:
            response = http.open(req, timeout=20)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            declared_length = response.headers.get("Content-Length")
            raw = response.read(MAX_RESPONSE + 1)
            response_framing(raw, declared_length)
            record["status"] = response.code
        bounded_response(raw)
        record["response_sha256"] = hashlib.sha256(raw).hexdigest()
        if record["status"] == HTTP_OK:
            record["origin_echo"] = origin_echo(json.loads(raw), host, user, item, path)
    except (OSError, ValueError, TimeoutError, HTTPException) as exc:
        record["transport_failure"] = True
        record["error_type"] = type(exc).__name__
    record["received_at"] = time.time()
    record["expected_response"] = (
        not record["transport_failure"]
        and record["status"] == record["expected_status"]
        and (record["status"] != HTTP_OK or record["origin_echo"])
    )
    return record


def save(path: Path, value: dict) -> None:
    """Atomically replace bounded private status without losing previous log receipts."""
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True) + "\n")
    temporary.chmod(0o600)
    temporary.replace(path)


def append(root: Path, record: dict) -> None:
    """Retain four rotated private journals with explicit rotation identities."""
    path = root / "requests.jsonl"
    if path.exists() and path.stat().st_size >= LOG_BYTES:
        for index in (3, 2, 1):
            previous = root / ("requests." + str(index) + ".jsonl")
            if previous.exists():
                previous.replace(root / ("requests." + str(index + 1) + ".jsonl"))
        path.replace(root / "requests.1.jsonl")
    with path.open("a") as stream:
        stream.write(json.dumps(record, sort_keys=True) + "\n")
    path.chmod(0o600)


def run(config: dict, fixture: dict, root: Path, stopping: threading.Event) -> None:
    """Run until stopped; counters describe observations, not AI model acceptance."""
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (root / "runner.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        http = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect()
        )
        status = {
            "schema_version": 1,
            "run_id": uuid.uuid4().hex,
            "running": True,
            "started_at": time.time(),
            "fixture_sha256": config["fixture_sha256"],
            "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "hosts": config["hosts"],
            "target_aggregate_rps": config["aggregate_rps"],
            "catalog_acceptance": False,
            "ai_attribution_accepted": False,
            "requests": 0,
            "rotations": 0,
            "transport_failures": 0,
            "unexpected_responses": 0,
            "benign_requests": 0,
            "benign_successes": 0,
            "counts": {},
        }
        save(root / "status.json", status)
        try:
            while not stopping.is_set():
                rotation = uuid.uuid4().hex
                for item in fixture["requests"]:
                    for phase, host in config["hosts"].items():
                        if stopping.is_set():
                            break
                        sent = time.monotonic()
                        record = request(
                            http, host, phase, item, fixture["path"], rotation
                        )
                        append(root, record)
                        status["requests"] += 1
                        status["transport_failures"] += int(record["transport_failure"])
                        status["unexpected_responses"] += int(
                            not record["expected_response"]
                        )
                        if item["kind"] == "benign":
                            status["benign_requests"] += 1
                            status["benign_successes"] += int(
                                record["expected_response"]
                                and record["status"] == HTTP_OK
                            )
                        key = phase + "/" + item["label"] + "/" + str(record["status"])
                        status["counts"][key] = status["counts"].get(key, 0) + 1
                        status["last_request_at"] = record["received_at"]
                        status["observed_aggregate_rps"] = status["requests"] / max(
                            0.001, time.time() - status["started_at"]
                        )
                        save(root / "status.json", status)
                        stopping.wait(
                            max(
                                0,
                                1 / config["aggregate_rps"] - (time.monotonic() - sent),
                            )
                        )
                if not stopping.is_set():
                    status["rotations"] += 1
        finally:
            status.update(running=False, finished_at=time.time())
            save(root / "status.json", status)


def main() -> None:
    """Validate immutable inputs before either a check or the supervised traffic loop."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--state", type=Path, default=Path("/var/lib/demo-ai-traffic"))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    config, fixture = load(args.config, args.fixture)
    if args.check:
        return
    stopping = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopping.set())
    signal.signal(signal.SIGINT, lambda *_: stopping.set())
    run(config, fixture, args.state, stopping)


if __name__ == "__main__":
    main()
