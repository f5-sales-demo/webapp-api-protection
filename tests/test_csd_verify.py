# ruff: noqa: PT009,PT027
import json
import unittest
from pathlib import Path

from scripts.csd_verify import CONFIG_FAILURE, PENDING, VERIFIED, evaluate

FIXTURES = Path(__file__).parent / "fixtures" / "csd"
DOMAIN = "cdn-simulator-rmordasiewicz.eastus2.cloudapp.azure.com"
SINCE = 1_788_451_000


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class CsdVerifierTests(unittest.TestCase):
    def test_exact_fresh_high_risk_detection_with_affected_users_verifies(self) -> None:
        result = evaluate(fixture("detection.json"), DOMAIN, "detection", SINCE)
        self.assertEqual(result.exit_code, VERIFIED)

    def test_unrelated_statistics_never_satisfy_expected_domain(self) -> None:
        result = evaluate(fixture("unrelated.json"), DOMAIN, "detection", SINCE)
        self.assertEqual(result.exit_code, PENDING)
        self.assertIn("exact expected domain", result.reason)

    def test_stale_detection_is_pending(self) -> None:
        data = fixture("detection.json")
        data["scripts"]["scripts"][0]["lastSeen"] = SINCE - 1
        self.assertEqual(evaluate(data, DOMAIN, "detection", SINCE).exit_code, PENDING)

    def test_low_risk_or_missing_affected_users_is_pending(self) -> None:
        data = fixture("detection.json")
        data["scripts"]["scripts"][0]["risk"] = "Medium Risk"
        self.assertEqual(evaluate(data, DOMAIN, "detection", SINCE).exit_code, PENDING)
        data = fixture("detection.json")
        data["scripts"]["scripts"][0]["affected_users_count"] = 0
        self.assertEqual(evaluate(data, DOMAIN, "detection", SINCE).exit_code, PENDING)

    def test_mitigation_requires_domain_registration_and_blocking_statistics(
        self,
    ) -> None:
        data = fixture("detection.json")
        self.assertEqual(evaluate(data, DOMAIN, "mitigation", SINCE).exit_code, PENDING)
        self.assertEqual(
            evaluate(fixture("mitigation.json"), DOMAIN, "mitigation", SINCE).exit_code,
            VERIFIED,
        )

    def test_disabled_configuration_is_a_configuration_failure(self) -> None:
        data = fixture("detection.json")
        data["status"]["isEnabled"] = False
        self.assertEqual(
            evaluate(data, DOMAIN, "detection", SINCE).exit_code, CONFIG_FAILURE
        )

    def test_invalid_phase_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            evaluate(fixture("detection.json"), DOMAIN, "other", SINCE)


if __name__ == "__main__":
    unittest.main()
