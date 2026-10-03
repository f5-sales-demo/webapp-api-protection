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
        assert "web_socket_config { use_websocket = true }" in source
        assert "routes.value.path_value" in source
        assert "xcsh_origin_pool.origin.name" in source
