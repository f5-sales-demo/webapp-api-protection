"""AI acceptance rejects analytics-only, wrong-policy and ambiguous live evidence."""

import copy
import unittest
from unittest.mock import Mock

import pytest
from demo_test_support import ensure, ensure_equal
from demo_verify_evidence import identified_user, virtual_host
from demo_verify_types import EvidenceError
from showcase_ai_waf import configuration, probes
from showcase_ai_waf_evidence import (
    evaluate_phase,
    pair_configuration,
    require_control_difference,
    risk_evidence,
)


def pair():
    return {
        phase: {
            "domain": "ai-waf-" + phase + ".f5-sales-demo.com",
            "namespace": "example",
            "origin_pool_name": "shared-origin",
            "loadbalancer_name": "ai-waf-" + phase,
            "app_firewall_name": "ai-waf-" + phase + "-waf",
            "user_identification_name": "ai-waf-" + phase + "-user",
        }
        for phase in ("before", "after")
    }


def configs():
    result = {}
    for phase, endpoint in pair().items():
        result[phase] = {
            "names": endpoint,
            "firewall": {
                "spec": {
                    "blocking": {},
                    "detection_settings": {
                        "signature_selection_setting": {
                            "high_medium_accuracy_signatures": {}
                        }
                    },
                    **(
                        {"disable_ai_enhancements": {}}
                        if phase == "before"
                        else {
                            "enable_ai_enhancements": {"mitigate_high_risk_action": {}}
                        }
                    ),
                }
            },
            "listener": {
                "spec": {
                    "app_firewall": {
                        "name": endpoint["app_firewall_name"],
                        "namespace": endpoint["namespace"],
                    },
                    "user_identification": {
                        "name": endpoint["user_identification_name"],
                        "namespace": endpoint["namespace"],
                    },
                    "domains": [endpoint["domain"]],
                    "disable_malicious_user_detection": {},
                    "no_challenge": {},
                    "default_route_pools": [
                        {"pool": {"name": "shared-origin", "namespace": "example"}}
                    ],
                }
            },
            "identity": {"spec": {"rules": [{"http_header_name": "X-MUD-User"}]}},
        }
    return result


def request_and_event():
    endpoint = pair()["after"]
    probe = {
        "host": endpoint["domain"],
        "path": "/httpbin/anything/ai-waf",
        "method": "GET",
        "user": "showcase-" + "a" * 32 + "-ai-waf-after-sqli",
        "sent_at": 100,
        "received_at": 102,
        "status": 403,
    }
    event = {
        "namespace": "example",
        "vh_name": virtual_host(endpoint["loadbalancer_name"]),
        "domain": probe["host"],
        "req_path": probe["path"],
        "method": "GET",
        "user": identified_user(probe["user"]),
        "time": "1970-01-01T00:01:41Z",
        "rsp_code": "403",
        "req_id": "synthetic-request",
        "sec_event_type": "waf_sec_event",
        "sec_event_name": "WAF",
        "app_firewall_name": endpoint["app_firewall_name"],
        "action": "block",
        "recommended_action": "block",
        "req_risk": "high",
        "req_risk_reasons": [
            "The AI has verified that the payload identified by the attack signature 200002883 is malicious"
        ],
        "signatures": [
            {
                "id": "200002883",
                "state": "Enabled",
                "attack_type": "ATTACK_TYPE_SQL_INJECTION",
                "accuracy": "high_accuracy",
            }
        ],
    }
    return probe, event


class AiEvidence(unittest.TestCase):
    def test_equal_configuration_and_exact_high_risk_selection(self):
        pair_configuration(configs())

    def test_server_nulls_are_not_enabled_controls(self):
        value = configs()
        for endpoint in value.values():
            endpoint["listener"]["spec"]["api_protection_rules"] = None
        pair_configuration(value)

    def test_unrelated_control_enable_or_missing_disable_fails(self):
        for field in (
            "enable_malicious_user_detection",
            "enable_challenge",
            "api_rate_limit",
            "api_protection_rules",
            "api_specification",
        ):
            value = configs()
            value["after"]["listener"]["spec"][field] = {}
            with pytest.raises(EvidenceError):
                pair_configuration(value)

    def test_missing_baseline_disable_and_wrong_ai_action_fail(self):
        for phase, field, replacement in (
            ("before", "disable_ai_enhancements", None),
            (
                "after",
                "enable_ai_enhancements",
                {"mitigate_high_medium_risk_action": {}},
            ),
        ):
            value = configs()
            value[phase]["firewall"]["spec"][field] = replacement
            with pytest.raises(EvidenceError):
                pair_configuration(value)

    def test_unequal_origin_or_signature_configuration_fails(self):
        for kind, key, replacement in (
            ("listener", "default_route_pools", []),
            ("firewall", "detection_settings", {}),
        ):
            value = configs()
            value["after"][kind]["spec"][key] = replacement
            with pytest.raises(EvidenceError):
                pair_configuration(value)

    def test_actual_risk_and_model_reason_are_request_bound(self):
        probe, event = request_and_event()
        result = risk_evidence([event], event, probe, "example", "ai-waf-after")
        ensure_equal(result["risk"], "high")
        ensure_equal(result["signature_ids"], ["200002883"])

    def test_false_positive_classification_is_preserved_without_low_risk_alias(self):
        probe, event = request_and_event()
        event["req_risk"] = "false positive"
        event["req_risk_reasons"] = [
            "The AI has determined that the triggered signatures are false positives"
        ]
        result = risk_evidence([event], event, probe, "example", "ai-waf-after")
        ensure_equal(result["risk"], "false positive")
        ensure_equal(result["signature_ids"], ["200002883"])

    def test_false_positive_reason_cannot_substitute_for_supported_signature(self):
        probe, event = request_and_event()
        event["req_risk"] = "false positive"
        event["req_risk_reasons"] = [
            "The AI has determined that the triggered signatures are false positives"
        ]
        for field, value in (
            ("req_id", "wrong-request"),
            ("signatures", []),
            ("req_risk_reasons", ["unbound false positive"]),
            ("req_risk", "high"),
        ):
            changed = copy.deepcopy(event)
            changed[field] = value
            with pytest.raises(EvidenceError):
                risk_evidence([changed], event, probe, "example", "ai-waf-after")

    def test_attributed_false_positive_contrast_is_accepted(self):
        before = {"sqli": {"risk": "high", "status": 403, "input": "same"}}
        after = {
            **before,
            "tutorial": {"risk": "false positive", "status": 200, "input": "same"},
        }
        before["tutorial"] = {"status": 403, "input": "same"}
        require_control_difference(before, after)
        for field, value in (
            ("risk", "unknown"),
            ("status", 403),
            ("input", "changed"),
        ):
            changed = copy.deepcopy(after)
            changed["tutorial"][field] = value
            with pytest.raises(EvidenceError):
                require_control_difference(before, changed)
        del after["sqli"]
        with pytest.raises(EvidenceError):
            require_control_difference(before, after)

    def test_numeric_analytics_score_alone_fails(self):
        probe, event = request_and_event()
        del event["req_risk"]
        event["risk_score_info"] = {"score": 100}
        with pytest.raises(EvidenceError):
            risk_evidence([event], event, probe, "example", "ai-waf-after")

    def test_wrong_request_policy_signature_or_model_identity_fails(self):
        probe, original = request_and_event()
        for field, replacement in (
            ("req_id", "another-request"),
            ("app_firewall_name", "other-waf"),
            ("domain", "unrelated.example.test"),
            ("req_risk", "unknown"),
            (
                "signatures",
                [
                    {
                        "id": "200002883",
                        "state": "Staged",
                        "attack_type": "ATTACK_TYPE_SQL_INJECTION",
                        "accuracy": "high_accuracy",
                    }
                ],
            ),
            (
                "req_risk_reasons",
                [
                    "The AI has verified that the payload identified by the attack signature 999999 is malicious"
                ],
            ),
        ):
            changed = copy.deepcopy(original)
            changed[field] = replacement
            with pytest.raises(EvidenceError):
                risk_evidence([changed], original, probe, "example", "ai-waf-after")

    def test_duplicate_request_identity_is_ambiguous(self):
        probe, event = request_and_event()
        other = {**event, "req_id": "another-request"}
        with pytest.raises(EvidenceError):
            risk_evidence(
                [event, other],
                {"req_id": "missing-request"},
                probe,
                "example",
                "ai-waf-after",
            )

    def test_shared_denial_is_not_causal_ai_acceptance(self):
        both = {"sqli": {"risk": "high", "status": 403, "input": "synthetic"}}
        with pytest.raises(EvidenceError):
            require_control_difference(both, both)
        before = {**both, "low": {"status": 403, "input": "same"}}
        after = {**both, "low": {"status": 200, "risk": "low", "input": "same"}}
        require_control_difference(before, after)
        after["low"]["input"] = "changed"
        with pytest.raises(EvidenceError):
            require_control_difference(before, after)

    def test_transport_keeps_fixture_and_unique_synthetic_identities(self):
        client = Mock()
        client.request.return_value = (200, {})
        del client.clock_bounds
        del client.walkthrough_directory
        fixture: dict = {
            "path": "/httpbin/anything/ai-waf",
            "requests": [
                {"label": "sqli", "input": "1' OR '1'='1'--", "kind": "attack"}
            ],
        }
        rows = probes(
            client, pair()["after"], fixture, "showcase-" + "a" * 32 + "-ai-waf-after"
        )
        ensure_equal(rows[0]["input"], fixture["requests"][0]["input"])
        ensure("input=" in rows[0]["request_target"])
        ensure(identified_user(rows[0]["user"]).startswith("Header-X-Mud-User-"))

    def test_configuration_performs_only_exact_gets(self):
        expected = configs()

        def read(path):
            phase = "before" if "before" in path else "after"
            kind = (
                "listener"
                if "/http_loadbalancers/" in path
                else "firewall"
                if "/app_firewalls/" in path
                else "identity"
            )
            name = path.rsplit("/", 1)[1]
            return 200, {
                **expected[phase][kind],
                "metadata": {"name": name, "namespace": "example"},
            }

        client = Mock()
        client.api.side_effect = read
        configuration(client, pair())
        ensure_equal(client.api.call_count, 6)
        ensure(all(len(call.args) == 1 for call in client.api.call_args_list))

    def test_phase_preserves_origin_echo_and_rejects_unattributed_denial(self):
        probe, event = request_and_event()
        endpoint = pair()["after"]
        probe.update(
            label="sqli", kind="attack", input="synthetic", request_target=probe["path"]
        )
        result = evaluate_phase([event], [event], [probe], endpoint, True)
        ensure_equal(result["sqli"]["risk"], "high")
        with pytest.raises(EvidenceError):
            evaluate_phase([event], [], [probe], endpoint, True)
        event["recommended_action"] = "allow"
        with pytest.raises(EvidenceError):
            evaluate_phase([event], [event], [probe], endpoint, True)

    def test_legitimate_response_requires_exact_input_host_and_identity(self):
        probe, event = request_and_event()
        probe.update(
            status=200,
            label="legitimate",
            kind="benign",
            input="synthetic",
            request_target=probe["path"],
            body={
                "url": "http://" + probe["host"] + probe["path"],
                "headers": {"X-Mud-User": probe["user"]},
                "args": {"input": "synthetic"},
            },
        )
        event["rsp_code"] = "200"
        evaluate_phase([event], [], [probe], pair()["after"], True)
        probe["body"]["args"]["input"] = "other"
        with pytest.raises(EvidenceError):
            evaluate_phase([event], [], [probe], pair()["after"], True)


class NativeAiReadback(unittest.TestCase):
    def test_native_operational_fields_and_route_ids_preserve_raw_identity(self):
        value = configs()
        for index, phase in enumerate(("before", "after")):
            spec = value[phase]["listener"]["spec"]
            spec.update(state="Ready", host_name=phase, auto_cert_info={"state": phase})
            spec["routes"] = [
                {
                    "simple_route": {
                        "uuid": "00000000-0000-4000-8000-00000000000" + str(index),
                        "path": {"prefix": "/dvga/subscriptions"},
                        "origin_pools": [
                            {
                                "pool": {
                                    "name": "shared-origin",
                                    "namespace": "example",
                                    "tenant": "example",
                                }
                            }
                        ],
                    }
                }
            ]
            for reference in (
                spec["app_firewall"],
                spec["user_identification"],
                spec["default_route_pools"][0]["pool"],
            ):
                reference["tenant"] = "example"
        original = copy.deepcopy(value)
        pair_configuration(value)
        ensure_equal(value, original)
        value["after"]["listener"]["spec"]["routes"][0]["simple_route"]["uuid"] = (
            "invalid-uuid"
        )
        with pytest.raises(EvidenceError):
            pair_configuration(value)

    def test_reference_namespace_name_and_tenant_mismatches_fail(self):
        for reference in ("app_firewall", "user_identification"):
            for field, replacement in (
                ("namespace", "other"),
                ("name", "other"),
                ("tenant", "other"),
            ):
                value = configs()
                value["after"]["listener"]["spec"][reference][field] = replacement
                with pytest.raises(EvidenceError):
                    pair_configuration(value)
        value = configs()
        for phase in value.values():
            phase["listener"]["spec"]["default_route_pools"][0]["pool"]["tenant"] = (
                "example"
            )
            phase["listener"]["spec"]["app_firewall"]["tenant"] = "example"
            phase["listener"]["spec"]["user_identification"]["tenant"] = "example"
            phase["listener"]["spec"]["routes"] = [
                {
                    "simple_route": {
                        "origin_pools": [{"pool": {"tenant": "example-other"}}]
                    }
                }
            ]
        with pytest.raises(EvidenceError):
            pair_configuration(value)

    def test_native_parentheses_echo_preserves_original_wire_target(self):
        probe, event = request_and_event()
        input_value = "The database tutorial uses SELECT VERSION() to show its version."
        wire = (
            probe["path"]
            + "?input=The+database+tutorial+uses+SELECT+VERSION%28%29+to+show+its+version."
        )
        native = wire.replace("%28%29", "()")
        probe.update(
            status=200,
            label="tutorial",
            kind="benign",
            input=input_value,
            request_target=wire,
            origin_request_target=native,
            body={
                "url": "http://" + probe["host"] + native,
                "headers": {"X-Mud-User": probe["user"]},
                "args": {"input": input_value},
            },
        )
        event["rsp_code"] = "200"
        evaluate_phase([event], [], [probe], pair()["after"], True)
        ensure_equal(probe["request_target"], wire)
        for replacement in (
            native + "&extra=changed",
            "//other.example.test" + native,
            native.replace("/ai-waf", "/other"),
        ):
            changed = copy.deepcopy(probe)
            changed["origin_request_target"] = replacement
            with pytest.raises(EvidenceError):
                evaluate_phase([event], [], [changed], pair()["after"], True)
        for key, replacement in (
            ("url", "http://other.example.test" + native),
            ("headers", {"X-Mud-User": "other"}),
            ("args", {"input": "other"}),
        ):
            changed = copy.deepcopy(probe)
            changed["body"][key] = replacement
            with pytest.raises(EvidenceError):
                evaluate_phase([event], [], [changed], pair()["after"], True)
