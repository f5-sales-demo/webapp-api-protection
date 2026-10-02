"""Continuous acceptance rejects partial catalogs and traffic-only protection claims."""

import copy
import time
import unittest

from scripts.demo_verify_evidence import continuous_traffic_ready


class ContinuousTests(unittest.TestCase):
    def status(self):
        now = time.time()
        return {
            "service_active": True,
            "service_enabled": True,
            "heartbeat": now,
            "catalog_passes": [
                {"complete": True, "passed": True, "started": now - 20},
                {"complete": True, "passed": True, "started": now - 10},
            ],
            "rates": {
                "elapsed": 30,
                "benign_requests": 5400,
                "benign_success": 5400,
                "attack_requests": 600,
                "benign_transport_failures": 0,
                "attack_transport_failures": 0,
                "benign_per_domain": {
                    "www.example.test": 2700,
                    "api.example.test": 2700,
                },
            },
            "failures": [],
        }

    def test_two_passes_and_measured_budget_required(self):
        status = self.status()
        domains = ["www.example.test", "api.example.test"]
        assert continuous_traffic_ready(status, domains, time.time() - 60)
        for field, value in [
            ("service_active", False),
            ("catalog_passes", []),
            ("failures", [{"id": "missing-fixture"}]),
        ]:
            broken = copy.deepcopy(status)
            broken[field] = value
            assert not continuous_traffic_ready(broken, domains, time.time() - 60)
        for field, value in [
            ("benign_success", 5300),
            ("benign_transport_failures", 1),
            ("attack_transport_failures", 1),
            ("attack_requests", 0),
        ]:
            broken = copy.deepcopy(status)
            broken["rates"][field] = value
            assert not continuous_traffic_ready(broken, domains, time.time() - 60)
