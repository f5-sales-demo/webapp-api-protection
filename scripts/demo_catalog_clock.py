"""Calibrate the operator to XC log time without lifecycle imports."""

from __future__ import annotations

import math
import time
from typing import TYPE_CHECKING

from demo_catalog_evidence import access_by_user
from demo_verify_client import Client

if TYPE_CHECKING:
    from demo_lifecycle_runtime import Runtime
    from demo_lifecycle_state import Context
from demo_verify_evidence import identified_user, rate_origin, stamp, virtual_host
from showcase_walkthrough_config import fail, save

LOG_INGESTION_MARGIN = 60
MAX_CLOCK_OFFSET = 5


def clock_probe(client: Client, host: str, user: str) -> dict:
    """Send one benign identity with exact request timing."""
    start = time.time()
    code, body = client.request(host, "/httpbin/get", "GET", user)
    return {
        "host": host,
        "path": "/httpbin/get",
        "method": "GET",
        "user": user,
        "sent_at": start,
        "received_at": time.time(),
        "status": code,
        "body": body,
    }


def calibrate_clock(client: Client, out: dict, prefix: str) -> None:
    """Measure bounded server-log offset using three fresh benign identities."""
    probes = [
        clock_probe(client, out["domains"][0], prefix + "-clock-" + str(i))
        for i in range(3)
    ]
    for probe in probes:
        rate_origin(
            probe["status"], probe["body"], probe["host"], probe["path"], probe["user"]
        )
    while True:
        records = [
            record
            for probe in probes
            for record in access_by_user(
                client,
                out["namespace"],
                out["loadbalancer_name"],
                probe["user"],
                probe["sent_at"] - 5,
                probe["received_at"] + LOG_INGESTION_MARGIN,
            )
        ]
        clocks = []
        for probe in probes:
            hits = [
                r
                for r in records
                if r.get("user") == identified_user(probe["user"])
                and r.get("domain") == probe["host"]
                and r.get("req_path") == probe["path"]
                and r.get("namespace") == out["namespace"]
                and r.get("vh_name") == virtual_host(out["loadbalancer_name"])
                and r.get("method") == "GET"
                and r.get("rsp_code") == "200"
            ]
            if len(hits) == 1:
                moment = stamp(hits[0]["time"])
                clocks.append(
                    (moment - probe["received_at"], moment - probe["sent_at"])
                )
        if len(clocks) == len(probes):
            low, high = (
                math.floor(min(c[0] for c in clocks)) - 1,
                math.ceil(max(c[1] for c in clocks)) + 1,
            )
            if not -MAX_CLOCK_OFFSET <= low <= high <= MAX_CLOCK_OFFSET:
                fail("log clock calibration exceeds five-second bound")
            client.clock_bounds = (low, high)
            save(
                client.walkthrough_directory / "clock-calibration.json",
                {
                    "probes": probes,
                    "access_logs": records,
                    "offset_min": low,
                    "offset_max": high,
                },
            )
            return
        client.remaining()
        time.sleep(min(5, client.remaining()))


def catalog_client(context: Context, outputs: dict) -> Client:
    """Keep scoped log time calibration in the operator's private state."""
    client = Client(context.state.deadline)
    client.walkthrough_directory = context.paths.state / "catalog-clock"
    client.walkthrough_directory.mkdir(mode=0o700, exist_ok=True)
    calibrate_clock(
        client, outputs, "showcase-" + __import__("uuid").uuid4().hex + "-catalog-clock"
    )
    return client


def align_generator_clock(client: Client, runtime: Runtime, ssh: list[str]) -> None:
    """Measure the guest clock through the verified SSH route before joining receipts."""
    samples = []
    for _ in range(3):
        before = time.time()
        remote = float(
            runtime.run([*ssh, "python3", "-c", "'import time;print(time.time())'"])[0]
        )
        after = time.time()
        samples.append((remote - after, remote - before))
    lower, upper = min(v[0] for v in samples), max(v[1] for v in samples)
    bounds = (client.clock_bounds[0] - upper, client.clock_bounds[1] - lower)
    if not -MAX_CLOCK_OFFSET <= bounds[0] <= bounds[1] <= MAX_CLOCK_OFFSET:
        fail("generator clock calibration exceeds five-second bound")
    client.clock_bounds = bounds
    save(
        client.walkthrough_directory / "generator-clock.json",
        {"samples": samples, "clock_bounds": bounds},
    )
