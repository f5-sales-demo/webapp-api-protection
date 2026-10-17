"""HTTP and HTTPS listeners must both support declared application WebSocket routes."""

import unittest
from pathlib import Path


class HttpWebSocketRoutes(unittest.TestCase):
    def test_companion_emits_declared_websocket_paths(self):
        source = (
            Path(__file__).resolve().parents[1] / "terraform/modules/http-lb/main.tf"
        ).read_text()
        assert "routes.value.use_websocket" in source
        assert "content { use_websocket = true }" in source
        assert "routes.value.path_value" in source
        assert "xcsh_origin_pool.origin.name" in source


def test_http_companion_keeps_costly_query_route_timeout():
    source = (
        Path(__file__).resolve().parents[1] / "terraform/modules/http-lb/main.tf"
    ).read_text()
    assert "routes.value.timeout_ms" in source
    assert "timeout = routes.value.timeout_ms" in " ".join(source.split())


def test_stream_idle_timeout_reaches_both_owned_listeners():
    root = Path(__file__).resolve().parents[1]
    for name in ("main.tf",):
        source = (root / "terraform/modules/http-lb" / name).read_text()
        assert "idle_timeout = var.lb_stream_idle_timeout_ms" in " ".join(
            source.split()
        )
        assert (
            "var.lb_stream_idle_timeout_ms != null" in source
            or "var.lb_stream_idle_timeout_ms == null" in source
        )
