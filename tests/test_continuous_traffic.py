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
            "source_commit": "a" * 40,
            "artifact_sha256": "b" * 64,
            "service_enabled": True,
            "heartbeat": now,
            "run_started": now - 30,
            "catalog_passes": [
                {
                    "complete": True,
                    "catalog_complete": True,
                    "catalog_accepted": True,
                    "source_commit": "a" * 40,
                    "artifact_sha256": "b" * 64,
                    "passed": True,
                    "started": now - 20,
                },
                {
                    "complete": True,
                    "catalog_complete": True,
                    "catalog_accepted": True,
                    "source_commit": "a" * 40,
                    "artifact_sha256": "b" * 64,
                    "passed": True,
                    "started": now - 10,
                },
            ],
            "rates": {
                "elapsed": 30,
                "benign_requests": 5400,
                "benign_success": 5400,
                "attack_requests": 600,
                "benign_per_application": dict.fromkeys(
                    [
                        "/juice-shop/rest/products/search",
                        "/dvwa/login.php",
                        "/vampi/",
                        "/httpbin/get",
                        "/whoami/",
                        "/csd-demo/",
                        "/dvga/",
                        "/restaurant/openapi.json",
                        "/crapi/",
                    ],
                    600,
                ),
                "benign_transport_failures": 0,
                "attack_transport_failures": 0,
                "benign_per_domain": {
                    "www.example.test": 2700,
                    "api.example.test": 2700,
                },
            },
            "failures": [],
        }

    def test_focused_suite_passes_cannot_establish_catalog_acceptance(self):
        status = self.status()
        status["catalog_passes"][0]["catalog_complete"] = False
        assert not continuous_traffic_ready(
            status, ["www.example.test", "api.example.test"], time.time() - 60
        )

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

    def test_current_run_passes_can_precede_acceptance_invocation(self):
        status = self.status()
        assert continuous_traffic_ready(
            status, ["www.example.test", "api.example.test"], time.time() - 1
        )

    def test_old_run_passes_cannot_establish_current_run_acceptance(self):
        status = self.status()
        status["run_started"] = time.time() - 5
        assert not continuous_traffic_ready(
            status, ["www.example.test", "api.example.test"], time.time() - 1
        )


class CatalogRejectionTests(unittest.TestCase):
    def test_old_artifact_or_unverified_catalog_cannot_establish_acceptance(self):
        status = ContinuousTests().status()
        for field, value in [
            ("source_commit", "e" * 40),
            ("artifact_sha256", "e" * 64),
            ("catalog_accepted", False),
        ]:
            changed = copy.deepcopy(status)
            changed["catalog_passes"][0][field] = value
            assert not continuous_traffic_ready(
                changed, ["www.example.test", "api.example.test"], time.time() - 60
            )

    def test_unbalanced_domains_or_missing_application_traffic_fails(self):
        status = ContinuousTests().status()
        domains = ["www.example.test", "api.example.test"]
        changed = copy.deepcopy(status)
        changed["rates"]["benign_per_domain"] = dict(
            zip(domains, [5399, 1], strict=True)
        )
        assert not continuous_traffic_ready(changed, domains, time.time() - 60)
        changed = copy.deepcopy(status)
        changed["rates"]["benign_per_application"] = {"/whoami/": 5400}
        assert not continuous_traffic_ready(changed, domains, time.time() - 60)

    def test_aggregate_rate_cannot_hide_missing_benign_budget(self):
        status = ContinuousTests().status()
        status["rates"].update(
            benign_requests=3000, benign_success=3000, attack_requests=3000
        )
        assert not continuous_traffic_ready(
            status, ["www.example.test", "api.example.test"], time.time() - 60
        )
