"""HTTP and HTTPS listeners must both support declared application WebSocket routes."""

import unittest
from pathlib import Path


class HttpWebSocketRoutes(unittest.TestCase):
    def test_companion_emits_declared_websocket_paths(self):
        source = (
            Path(__file__).resolve().parents[1]
            / "terraform/modules/http-lb/http_companion.tf"
        ).read_text()
        assert "route.use_websocket" in source
        assert "content { use_websocket = true }" in source
        assert "routes.value.path_value" in source
        assert "xcsh_origin_pool.origin.name" in source


def test_http_companion_keeps_costly_query_route_timeout():
    source = (
        Path(__file__).resolve().parents[1]
        / "terraform/modules/http-lb/http_companion.tf"
    ).read_text()
    assert "route.timeout_ms != null" in source
    assert "timeout  = routes.value.timeout_ms" in source
