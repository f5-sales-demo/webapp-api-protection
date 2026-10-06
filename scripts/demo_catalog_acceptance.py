"""Measured full-catalog throughput and availability acceptance."""

from __future__ import annotations

import math
from typing import Any

_MIN_HTTP_RATE = 190
_MAX_HTTP_RATE = 210
_MIN_BENIGN_SUCCESS = 0.99


def catalog_metrics(status: dict[str, Any]) -> bool:
    """Check actual aggregate HTTP pacing and benign availability."""
    metrics = status.get("rates", {})
    if not isinstance(metrics, dict):
        return False
    keys = (
        "elapsed",
        "benign_requests",
        "attack_requests",
        "benign_completed",
        "benign_success",
        "benign_transport_failures",
        "attack_transport_failures",
    )
    if any(
        isinstance(metrics.get(key), bool)
        or not isinstance(metrics.get(key), (int, float))
        or not math.isfinite(metrics[key])
        or metrics[key] < 0
        for key in keys
    ):
        return False
    elapsed, benign = metrics["elapsed"], metrics["benign_completed"]
    if elapsed <= 0 or benign <= 0:
        return False
    requests = metrics["benign_requests"] + metrics["attack_requests"]
    return (
        _MIN_HTTP_RATE <= requests / elapsed <= _MAX_HTTP_RATE
        and metrics["benign_success"] / benign >= _MIN_BENIGN_SUCCESS
        and metrics["benign_transport_failures"] == 0
        and metrics["attack_transport_failures"] == 0
    )
