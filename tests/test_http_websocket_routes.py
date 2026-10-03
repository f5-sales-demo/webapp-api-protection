"""HTTP and HTTPS listeners must both support declared application WebSocket routes."""

import unittest
from pathlib import Path


class HttpWebSocketRoutes(unittest.TestCase):
    def test_companion_emits_declared_websocket_paths(self):
        source = (Path(__file__).resolve().parents[1] / "terraform/modules/http-lb/http_companion.tf").read_text()
        self.assertIn("route.use_websocket", source)
        self.assertIn("web_socket_config { use_websocket = true }", source)
        self.assertIn("routes.value.path_value", source)
        self.assertIn("xcsh_origin_pool.origin.name", source)
