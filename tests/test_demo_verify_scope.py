"""Synthetic verifier checks; not live security acceptance proof."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import Mock

from tests import demo_verify_fixtures as fixtures
from tests.demo_test_support import ensure, ensure_equal, expect_error

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
import demo_verify_scope as scope
import demo_verify_types as contracts

USER = fixtures.USER
DOMAINS = fixtures.DOMAINS


class ScopeIntegrityTests(unittest.TestCase):
    def test_absence_missing_manifest_rejected(self):
        with expect_error(contracts.EvidenceError):
            scope.absence(Mock(), {"schema_version": 1})

    def test_absence_and_preservation(self):
        sub = "11111111-1111-1111-1111-111111111111"
        owned = f"/subscriptions/{sub}/resourceGroups/demo/providers/Microsoft.Compute/virtualMachines/demo"
        manifest: dict[str, Any] = {
            "schema_version": 1,
            "subscription_id": sub,
            "azure_owned": [owned],
            "azure_preserved": [],
            "azure_api_versions": {owned: "2024-03-01"},
            "xc_owned": [
                {
                    "path": "/api/config/namespaces/demo/http_loadbalancers/demo-lb",
                    "uid": "owned-uid",
                }
            ],
            "xc_preserved": [
                {
                    "path": "/api/web/namespaces/demo",
                    "uid": "namespace-uid",
                }
            ],
        }
        client = Mock()
        client.azure_exists.side_effect = [False]
        client.api.side_effect = [
            (404, {}),
            (200, {"system_metadata": {"uid": "namespace-uid"}}),
        ]
        ensure(bool(scope.absence(client, manifest)))
        client.azure_exists.assert_called_once_with(sub, owned, "2024-03-01")
        client.azure_exists.side_effect = [False]
        client.api.side_effect = [
            (404, {}),
            (200, {"system_metadata": {"uid": "changed-namespace-uid"}}),
        ]
        ensure(not scope.absence(client, manifest))
        obsolete = dict(
            manifest,
            azure_preserved=[f"/subscriptions/{sub}/resourceGroups/old-backend"],
        )
        with expect_error(contracts.EvidenceError):
            scope.absence(Mock(), obsolete)
        incomplete = dict(manifest)
        incomplete.pop("azure_preserved")
        with expect_error(contracts.EvidenceError):
            scope.absence(Mock(), incomplete)
        # A later malformed identity must reject the entire receipt before I/O.
        for path, uid in (
            (
                "/api/config/namespaces/demo/http_loadbalancers/demo-lb?query=other",
                "uid",
            ),
            ("/api/config/namespaces/other/http_loadbalancers/demo-lb", "uid"),
            ("/api/config/namespaces/demo/unknown_collections/demo-lb", "uid"),
            ("/api/config/namespaces/demo/origin_pools/demo-pool", " "),
        ):
            malformed = copy.deepcopy(manifest)
            malformed["xc_owned"].append({"path": path, "uid": uid})
            reader = Mock(spec=contracts.EvidenceReader)
            with (
                self.subTest(path=path, uid=uid),
                expect_error(contracts.EvidenceError),
            ):
                scope.absence(reader, malformed)
            reader.api.assert_not_called()
            reader.azure_exists.assert_not_called()

    def test_effective_actual_top_level_empty_markers_and_policy_arms(self):
        for challenge in ("enable_challenge", "policy_based_challenge"):
            client, out, _, _ = fixtures.effective_fixture(challenge)
            scope.effective(client, out)
            ensure_equal(client.api.call_count, 4)
            ensure_equal(
                client.api.call_args.args[0],
                "/api/config/namespaces/demo/malicious_user_mitigations/demo-mud",
            )

    def test_effective_rejects_missing_disabled_nested_and_wrong_controls(self):
        for mutate in (
            lambda s: s.pop("enable_malicious_user_detection"),
            lambda s: s.update(disable_malicious_user_detection={}),
            lambda s: s.update(enable_malicious_user_detection=None),
            lambda s: s.update(enable_malicious_user_detection=[]),
            lambda s: s.update(api_specification=None),
            lambda s: s["api_specification"].update(validation_all_spec_endpoints=None),
            lambda s: s.update(
                single_lb_app={
                    "enable_malicious_user_detection": s.pop(
                        "enable_malicious_user_detection"
                    )
                }
            ),
            lambda s: s["enable_challenge"].pop("malicious_user_mitigation"),
            lambda s: s["enable_challenge"].update(malicious_user_mitigation={}),
            lambda s: s["enable_challenge"].update(default_mitigation_settings={}),
            lambda s: s.update(no_challenge={}),
            lambda s: s["user_identification"].update(namespace="other"),
            lambda s: s.update(user_id_client_ip={}),
            lambda s: s["api_rate_limit"].update(api_endpoint_rules=[]),
            lambda s: s["api_rate_limit"].update(api_endpoint_rules=None),
            lambda s: s["api_rate_limit"]["api_endpoint_rules"][0][
                "api_endpoint_method"
            ].update(invert_matcher=True),
            lambda s: s["api_rate_limit"]["api_endpoint_rules"][0][
                "inline_rate_limiter"
            ].update(ref_user_id={}),
            lambda s: s["api_specification"]["validation_all_spec_endpoints"][
                "validation_mode"
            ]["validation_mode_active"].update(enforcement_report={}),
            lambda s: s.update(disable_api_discovery={}),
            lambda s: s.update(client_side_defense={}),
        ):
            client, out, spec, _ = fixtures.effective_fixture()
            mutate(spec)
            with self.subTest(mutate=mutate), expect_error(contracts.EvidenceError):
                scope.effective(client, out)

    def test_effective_rejects_wrong_header_and_mitigation_policy(self):
        for target, mutate in (
            (2, lambda p: p["spec"]["rules"][0].update(http_header_name="X-Other")),
            (2, lambda p: p["spec"]["rules"].append({"client_ip": {}})),
            (2, lambda p: p.update(metadata={"disable": True})),
            (3, lambda p: p["spec"]["mitigation_type"].update(rules=[])),
            (3, lambda p: p["spec"].update(mitigation_type=None)),
            (3, lambda p: p["spec"]["mitigation_type"].update(rules=None)),
            (
                3,
                lambda p: p["spec"]["mitigation_type"]["rules"][0].update(
                    mitigation_action={"javascript_challenge": {}}
                ),
            ),
            (
                3,
                lambda p: p["spec"]["mitigation_type"]["rules"][0].update(
                    threat_level={"high": {}}
                ),
            ),
            (3, lambda p: p.update(metadata={"disable": True})),
        ):
            client, out, _, responses = fixtures.effective_fixture()
            mutate(responses[target][1])
            with (
                self.subTest(target=target, mutate=mutate),
                expect_error(contracts.EvidenceError),
            ):
                scope.effective(client, out)
        client, out, _, responses = fixtures.effective_fixture()
        responses[3] = (404, {})
        with expect_error(contracts.EvidenceError):
            scope.effective(client, out)

    def test_outputs_actual_user_identification(self):
        protection = {
            "waf_mode": "blocking",
            "csd_enabled": False,
            "mud_enabled": True,
            "mud_user_id": "user_identification",
            "api_definition_choice": "specification",
            "api_specification_validation": "all_spec_endpoints",
            "api_validation_request_mode": "block",
            "rate_limiting_mode": "api_rate_limit",
        }
        out = {
            "namespace": "demo",
            "loadbalancer_name": "demo-lb",
            "domains": DOMAINS,
            "protection": protection,
            "origin": {"public_ip": "192.0.2.1", "admin_username": "demo"},
            "generator": {"public_ip": "192.0.2.2", "admin_username": "demo"},
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "outputs.json"
            path.write_text(json.dumps({"showcase": {"value": out}}))
            ensure_equal(scope.outputs(path), out)
            protection["mud_user_id"] = "header"
            path.write_text(json.dumps(out))
            with expect_error(contracts.EvidenceError):
                scope.outputs(path)

    def test_rate_rule_must_be_effective_endpoint_index_zero(self):
        client, out, spec, _ = fixtures.effective_fixture()
        rule = spec["api_rate_limit"]["api_endpoint_rules"][0]
        spec["api_rate_limit"]["api_endpoint_rules"].insert(
            0, dict(rule, api_endpoint_path="/other")
        )
        with expect_error(contracts.EvidenceError, "rate limit configuration mismatch"):
            scope.effective(client, out)
