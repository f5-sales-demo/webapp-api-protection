"""Synthetic verifier checks; not live security acceptance proof."""

from __future__ import annotations

import copy
import json
import sys
import time
import unittest
from pathlib import Path
from typing import Any

from tests import demo_verify_fixtures as fixtures
from tests.demo_test_support import ensure, ensure_equal, expect_error

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
import demo_verify_evidence as evaluation
import demo_verify_types as contracts

USER = fixtures.USER
DOMAINS = fixtures.DOMAINS


class ControlTrafficEvidenceTests(unittest.TestCase):
    def test_observed_sanitized_records(self):
        fixture = json.loads(
            (Path(__file__).parent / "fixtures/demo_security_events.json").read_text()
        )
        events = [evaluation.decode_event(raw) for raw in fixture["events"]]
        ensure_equal(len(events), int(fixture["total_hits"]))
        for event, control, suffix in zip(
            events,
            ["waf", "schema", "endpoint-denial"],
            ["waf", "wrong", "deny-post"],
            strict=True,
        ):
            probe = fixtures.probe(control)
            probe.update(
                user="showcase-" + "a" * 32 + "-d0-" + suffix,
                path=event["req_path"],
                method=event["method"],
                sent_at=evaluation.stamp("2026-10-01T05:23:00Z"),
            )
            ensure(
                bool(
                    evaluation.attributed(
                        event,
                        probe,
                        "demo",
                        "demo-lb",
                        evaluation.stamp("2026-10-01T05:29:59Z"),
                    )
                )
            )
            ensure(
                not evaluation.attributed(
                    event, fixtures.probe("mud"), "demo", "demo-lb", 110
                )
            )

    def test_wire_records_fail_closed(self):
        raw: dict[str, Any] | str
        for raw in (
            {},
            "opaque",
            "[]",
            "null",
            json.dumps(json.dumps(fixtures.event())),
            "x" * 100001,
        ):
            with (
                self.subTest(raw_type=type(raw).__name__),
                expect_error(contracts.EvidenceError),
            ):
                evaluation.decode_event(raw)

    def test_wrong_waf_profile_signature_name_and_identity_prefix(self):
        for key, value in (
            ("app_firewall_name", "other"),
            ("signatures", [{"id": "1", "state": "Enabled"}]),
            ("sec_event_name", "Other"),
            ("user", USER),
            ("user", "Header-x-mud-user-" + USER),
            ("time", "1970-01-01 00:01:41+00:00"),
        ):
            event = dict(fixtures.event(), **{key: value})
            ensure(
                not evaluation.attributed(
                    event, fixtures.probe(), "demo", "demo-lb", 110
                )
            )

    def test_config_uid_is_not_virtual_host_identity(self):
        event = fixtures.event()
        event["vhost_id"] = "not-the-config-uid"
        ensure(
            bool(evaluation.attributed(event, fixtures.probe(), "demo", "demo-lb", 110))
        )
        event["vh_name"] = "demo-lb"
        ensure(
            not evaluation.attributed(event, fixtures.probe(), "demo", "demo-lb", 110)
        )

    def test_identification_header_case_from_verified_policy(self):
        ensure_equal(
            evaluation.identified_user(USER, "X-MUD-User"),
            evaluation.identified_user(USER, "x-mud-user"),
        )
        with expect_error(contracts.EvidenceError):
            evaluation.identified_user(USER, "Other-Header")

    def test_rfc3339_outside_probe_window_fails(self):
        for value in ("1970-01-01T00:01:39Z", "1970-01-01T00:01:51Z"):
            ensure(
                not evaluation.attributed(
                    dict(fixtures.event(), time=value),
                    fixtures.probe(),
                    "demo",
                    "demo-lb",
                    110,
                )
            )

    def test_observed_schema_and_denial_markers_cannot_be_borrowed(self):
        fixture = json.loads(
            (Path(__file__).parent / "fixtures/demo_security_events.json").read_text()
        )
        for raw, control in zip(
            fixture["events"][1:], ["schema", "endpoint-denial"], strict=True
        ):
            event = evaluation.decode_event(raw)
            probe = fixtures.probe(control)
            probe.update(
                path=event["req_path"],
                method=event["method"],
                user=event["user"][len("Header-X-Mud-User-") :],
                sent_at=evaluation.stamp("2026-10-01T05:23:00Z"),
            )
            end = evaluation.stamp("2026-10-01T05:29:59Z")
            bad = copy.deepcopy(event)
            if control == "schema":
                bad["violations"][0]["field"] = "other"
                ensure(not evaluation.attributed(bad, probe, "demo", "demo-lb", end))
                bad = copy.deepcopy(event)
                bad["violations"][0]["context"] = "Response"
            else:
                bad["policy_hits"]["policy_hits"][0]["policy_rule"] += "-other"
                ensure(not evaluation.attributed(bad, probe, "demo", "demo-lb", end))
                bad = copy.deepcopy(event)
                bad["policy_hits"] = bad["policy_hits"]["policy_hits"][0]
            ensure(not evaluation.attributed(bad, probe, "demo", "demo-lb", end))

    def test_documented_waf_join(self):
        ensure(
            bool(
                evaluation.attributed(
                    fixtures.event(), fixtures.probe(), "demo", "demo-lb", 110
                )
            )
        )

    def test_wrong_join_keys_and_stale(self):
        for key, value in (
            ("time", 99),
            ("time", 111),
            ("vh_name", "other-lb"),
            ("user", "real-user"),
            ("domain", DOMAINS[1]),
            ("method", "POST"),
            ("req_path", "/other"),
            ("sec_event_type", "bot_defense_sec_event"),
            ("action", "allow"),
            ("namespace", "other"),
        ):
            event = fixtures.event()
            event[key] = value
            with self.subTest(key=key, value=value):
                ensure(
                    not evaluation.attributed(
                        event, fixtures.probe(), "demo", "demo-lb", 110
                    )
                )

    def test_generic_block_opaque_records_and_missing(self):
        for event in (
            {"rsp_code": "403"},
            {"message": json.dumps(fixtures.event())},
            "opaque",
            {},
            None,
        ):
            ensure(
                not evaluation.attributed(
                    event, fixtures.probe(), "demo", "demo-lb", 110
                )
            )
        ensure(
            not evaluation.telemetry_ready(
                [], [fixtures.probe()], "demo", "demo-lb", 110
            )
        )
        ensure(
            not evaluation.telemetry_ready(
                [fixtures.event()], [], "demo", "demo-lb", 110
            )
        )

    def test_control_specific_markers(self):
        schema = {
            "oas_req_status": "OpenAPIViolation",
            "violations": [
                {"context": "Request", "field": "demo_id", "property": "HTTP Body"}
            ],
        }
        denial = {
            "policy_hits": {
                "policy_hits": [
                    {
                        "result": "deny",
                        "policy_namespace": "demo",
                        "policy": "ves-io-http-loadbalancer-api-protection-demo-lb",
                        "policy_rule": "ves-io-service-policy-ves-io-http-loadbalancer-api-protection-demo-lb-api-protection-0",
                    }
                ]
            }
        }
        for control, name, path, method, extra in (
            ("schema", "OpenAPI Validation Failure", "/httpbin/post", "POST", schema),
            (
                "endpoint-denial",
                "API Protection Rule",
                "/httpbin/anything/admin",
                "POST",
                denial,
            ),
        ):
            probe = fixtures.probe(control)
            probe.update(path=path, method=method)
            event = fixtures.event()
            event.update(
                sec_event_type="api_sec_event",
                sec_event_name=name,
                req_path=path,
                method=method,
                **extra,
            )
            ensure(bool(evaluation.attributed(event, probe, "demo", "demo-lb", 110)))
            event["user"] = evaluation.identified_user(
                "showcase-" + "c" * 32 + "-unrelated"
            )
            ensure(not evaluation.attributed(event, probe, "demo", "demo-lb", 110))

    def test_rate_identity_cannot_be_borrowed(self):
        event = fixtures.event()
        event.update(
            sec_event_type="api_sec_event",
            sec_event_name="API Rate Limiting",
            policy_hits={
                "policy_hits": [
                    {"rate_limiter_action": "fail", "rate_limiter_user_id": "other"}
                ]
            },
        )
        ensure(
            not evaluation.attributed(
                event, fixtures.probe("rate-limit"), "demo", "demo-lb", 110
            )
        )

    def test_missing_each_control_is_not_success(self):
        ensure(
            not evaluation.telemetry_ready(
                [fixtures.event()],
                [fixtures.probe(), fixtures.probe("mud")],
                "demo",
                "demo-lb",
                110,
            )
        )

    def test_each_replica_failure_propagates(self):
        for failed in range(3):
            checks = [
                {"name": "replica-" + str(i), "ready": i != failed} for i in range(3)
            ]
            ensure(
                not evaluation.guest_ready(
                    {"schema_version": 1, "ready": True, "checks": checks}
                )
            )
            checks[failed]["ready"] = True
            ensure(
                bool(
                    evaluation.guest_ready(
                        {"schema_version": 1, "ready": True, "checks": checks}
                    )
                )
            )
        for report in (
            {"ready": True},
            {"ready": True, "checks": []},
            {"ready": True, "checks": [{"name": "db", "ready": False}]},
            {
                "ready": True,
                "checks": [{"name": "service", "ready": True, "skipped": True}],
            },
        ):
            ensure(not evaluation.guest_ready(report))

    def test_fresh_failed_scheduled_history_cannot_be_hidden_by_later_pair(self):
        status, since = fixtures.runs()
        failed = dict(
            status["history"][0],
            run_id="c" * 32,
            status="failed",
            failures=["SECRET"],
            error_class="configuration",
        )
        status["history"].insert(0, failed)
        ensure_equal(
            evaluation.traffic_failure(status, DOMAINS, since)["error_class"],
            "configuration",
        )
        ensure(not evaluation.traffic_ready(status, DOMAINS, since))
        ensure(
            "SECRET"
            not in json.dumps(evaluation.traffic_failure(status, DOMAINS, since))
        )
        failed["started_epoch"] = since - 1
        ensure(evaluation.traffic_failure(status, DOMAINS, since) is None)
        ensure(bool(evaluation.traffic_ready(status, DOMAINS, since)))
        failed.update(started_epoch=since, trigger="manual")
        ensure(evaluation.traffic_failure(status, DOMAINS, since) is None)

    def test_fresh_genuine_metric_failure_aborts_even_if_marked_verified(self):
        status, since = fixtures.runs()
        status["history"][0]["benign_success"] = 0.98
        failure = evaluation.traffic_failure(status, DOMAINS, since)
        ensure_equal(failure["error_class"], "metrics_failed")
        ensure("benign_success" in failure["metric_failures"])
        ensure(not evaluation.traffic_ready(status, DOMAINS, since))

    def test_pending_running_and_stale_history_are_not_terminal_failures(self):
        for state in ("pending", "running"):
            status = {
                "history": [
                    {"trigger": "scheduled", "status": state, "started_epoch": 100}
                ]
            }
            ensure(evaluation.traffic_failure(status, DOMAINS, 99) is None)
            ensure(not evaluation.traffic_ready(status, DOMAINS, 99))
        status = {
            "history": [
                {"trigger": "scheduled", "status": "failed", "started_epoch": 98}
            ]
        }
        ensure(evaluation.traffic_failure(status, DOMAINS, 99) is None)

    def test_measured_pair_accepts_1499_to_1501_requests_with_actual_rate(self):
        for count in (1499, 1500, 1501):
            status, since = fixtures.runs()
            for run in status["history"]:
                run.update(count=count, rate=count / 30)
                run["class_counts"]["benign"] += count - 1500
            ensure(bool(evaluation.traffic_ready(status, DOMAINS, since)))
        status, since = fixtures.runs()
        status["history"][0]["trigger"] = "manual"
        ensure(not evaluation.traffic_ready(status, DOMAINS, since))

    def test_scheduled_traffic_valid(self):
        status, since = fixtures.runs()
        ensure(bool(evaluation.traffic_ready(status, DOMAINS, since)))

    def test_traffic_incomplete_stale_transport_and_bad_metrics(self):
        for key, value in (
            ("trigger", "manual"),
            ("count", 1400),
            ("benign_success", 0.9),
            ("transport_errors", 1),
            ("rate", 52),
            ("domains", DOMAINS[:1]),
            ("rate", float("nan")),
            ("class_counts", {}),
            ("started_epoch", 1),
            ("status", "failed"),
            ("sequence", 3),
            ("run_id", USER),
            ("duration_seconds", 28),
            ("latencies", {"50th": 5, "95th": -1, "99th": 10}),
        ):
            status, since = fixtures.runs()
            status["history"][-1][key] = value
            with self.subTest(key=key):
                ensure(not evaluation.traffic_ready(status, DOMAINS, since))
        status, since = fixtures.runs()
        status["history"] = status["history"][:1]
        ensure(not evaluation.traffic_ready(status, DOMAINS, since))


class RiskReadinessEvidenceTests(unittest.TestCase):
    def test_mud_mitigation_requires_actual_matching_action(self):
        probe = fixtures.probe("mud")
        event = fixtures.mud_fixture()["mitigation_event"]
        event["user"] = evaluation.identified_user(USER)
        ensure(bool(evaluation.attributed(event, probe, "demo", "demo-lb", 110)))
        for key, value in (
            ("vh_name", "other-lb"),
            ("user", "mud-" + "b" * 32),
            ("time", 99),
            ("time", 111),
            ("time", None),
            ("action", "allow"),
            ("policy_hits", {"malicious_user_mitigation_action": "MUM_NONE"}),
            (
                "policy_hits",
                {"malicious_user_mitigation_action": "MUM_CAPTCHA_CHALLENGE"},
            ),
            ("policy_hits", None),
            ("sec_event_type", "waf_sec_event"),
            ("sec_event_type", "api_sec_event"),
            ("sec_event_name", "WAF"),
            ("sec_event_name", "API Protection Rule"),
        ):
            changed = dict(event, **{key: value})
            with self.subTest(key=key, value=value):
                ensure(
                    not evaluation.attributed(changed, probe, "demo", "demo-lb", 110)
                )

    def test_generator_identities_are_exact_synthetic_values(self):
        for user in (
            "mud-" + "a" * 32,
            "rate-limit-" + "a" * 32,
            "waf-" + "a" * 32 + "-42",
            USER,
        ):
            ensure(evaluation.SYNTHETIC.fullmatch(user) is not None)
        for user in (
            "mud-real-user",
            "mud-" + "a" * 31,
            "real-user",
            "mud-" + "a" * 32 + "-untrusted",
        ):
            ensure(evaluation.SYNTHETIC.fullmatch(user) is None)

    def test_observed_mud_detection_contract(self):
        raw, probe, event = fixtures.mud_evidence()
        ensure(
            bool(
                evaluation.detection_attributed(
                    raw, probe, [event], "demo", "demo-lb", 110
                )
            )
        )
        ensure(
            bool(
                evaluation.detection_ready(
                    [raw], [probe], [event], "demo", "demo-lb", 110
                )
            )
        )
        ensure(
            not evaluation.detection_ready([raw], [], [event], "demo", "demo-lb", 110)
        )

    def test_mud_detection_rejects_wrong_scores_states_identity_and_units(self):
        raw, probe, event = fixtures.mud_evidence()
        for key, value in (
            ("threat_level", "HIGH"),
            ("threat_level", None),
            ("suspicion_log_type", "mitigation"),
            ("suspicion_log_type", "no_critical_activity"),
            ("suspicion_score", 0),
            ("suspicion_score", True),
            ("suspicion_score", "1.0"),
            ("suspicion_score", None),
            ("waf_suspicion_score", 0),
            ("waf_suspicion_score", float("nan")),
            ("namespace", "other"),
            ("vh_name", "demo-lb"),
            ("user", USER),
            ("start_time", 99),
            ("start_time", -1),
            ("start_time", None),
            ("start_time", "100"),
            ("start_time", 100000),
            ("end_time", 99),
            ("end_time", 111),
            ("end_time", float("inf")),
            ("mitigation_activity_info", None),
            ("mitigation_activity_info", "{}"),
            ("incremental_activity_info", "malformed"),
            ("incremental_activity_info", {}),
        ):
            changed = dict(evaluation.decode_event(raw), **{key: value})
            with self.subTest(key=key, value=value):
                ensure(
                    not evaluation.detection_attributed(
                        json.dumps(changed), probe, [event], "demo", "demo-lb", 110
                    )
                )

    def test_mud_detection_requires_positive_nested_waf_counts(self):
        raw, probe, event = fixtures.mud_evidence()
        for key, value in (
            ("waf_sec_event_count", 0),
            ("req_count", 0),
            ("waf_sec_event_count", True),
            ("err_count", -1),
        ):
            log = evaluation.decode_event(raw)
            activity = evaluation.decode_event(log["incremental_activity_info"])
            activity[key] = value
            log["incremental_activity_info"] = json.dumps(activity)
            ensure(
                not evaluation.detection_attributed(
                    json.dumps(log), probe, [event], "demo", "demo-lb", 110
                )
            )

    def test_mud_detection_requires_same_fresh_waf_attack(self):
        raw, probe, event = fixtures.mud_evidence()
        for key, value in (
            ("user", evaluation.identified_user(USER)),
            ("time", "1970-01-01T00:01:39Z"),
            ("time", "1970-01-01T00:01:43Z"),
            ("signatures", []),
            ("action", "allow"),
        ):
            ensure(
                not evaluation.detection_attributed(
                    raw, probe, [dict(event, **{key: value})], "demo", "demo-lb", 110
                )
            )
        ensure(
            not evaluation.detection_attributed(raw, probe, [], "demo", "demo-lb", 110)
        )
        ensure(
            not evaluation.detection_attributed(
                None, probe, [event], "demo", "demo-lb", 110
            )
        )
        ensure(
            not evaluation.detection_attributed(
                "opaque", probe, [event], "demo", "demo-lb", 110
            )
        )

    def test_mud_mitigation_requires_exact_policy_context(self):
        event = fixtures.mud_fixture()["mitigation_event"]
        probe = fixtures.mud_evidence()[1]
        for key in (
            "policy",
            "policy_namespace",
            "policy_set",
            "malicious_user_mitigate_action",
        ):
            changed = copy.deepcopy(event)
            changed["policy_hits"]["policy_hits"][0][key] = "other"
            ensure(not evaluation.attributed(changed, probe, "demo", "demo-lb", 110))

    def test_guest_actual_ready_field(self):
        report: dict[str, Any] = {
            "schema_version": 1,
            "ready": True,
            "checks": [{"name": "service:nginx", "ready": True}],
        }
        ensure(bool(evaluation.guest_ready(report)))
        report["checks"][0] = {"name": "service:nginx", "ok": True}
        ensure(not evaluation.guest_ready(report))

    def test_cadence_freshness_identity_and_legacy_fail(self):
        for mutate in (
            lambda s: s["history"][-1].update(
                started_epoch=s["history"][0]["started_epoch"] + 290
            ),
            lambda s: s["history"][-1].update(run_id=s["history"][0]["run_id"]),
            lambda s: s.update(run_id="c" * 32),
            lambda s: s["history"].append({"trigger": "scheduled", "status": "failed"}),
            lambda s: s.update(history=[None, None]),
            lambda s: s.update(timer_active=False),
        ):
            status, since = fixtures.runs()
            mutate(status)
            ensure(not evaluation.traffic_ready(status, DOMAINS, since))
        status, _ = fixtures.runs()
        ensure(not evaluation.traffic_ready(status, DOMAINS, time.time()))
        ensure(
            not evaluation.traffic_ready(
                {"timer_active": True, "runs": status["history"]}, DOMAINS, 0
            )
        )

    def test_cloud_init_exact_recovered_warning_remains_degraded(self):
        result = evaluation.cloud_init_state(fixtures.azure_retry_status())
        ensure_equal(result["status"], "degraded_done")
        ensure_equal(result["warnings_accepted"], 4)
        ensure_equal(result["fatal_errors"], 0)
        ensure(bool(result["sources"]))

    def test_cloud_init_warning_policy_fail_closed(self):
        for field, value in (
            ("datasource", "ec2"),
            ("stage", "modules-final"),
            ("errors", ["module failed"]),
            (
                "recoverable_errors",
                {"ERROR": [evaluation.AZURE_REPROVISION_WARNING] * 4},
            ),
            ("recoverable_errors", {"WARNING": ["apt HTTP 404"]}),
            (
                "recoverable_errors",
                {
                    "WARNING": [
                        evaluation.AZURE_REPROVISION_WARNING.replace("404", "500")
                    ]
                    * 4
                },
            ),
            ("modules-final", {"errors": ["init failure"]}),
        ):
            report = fixtures.azure_retry_status()
            report[field] = value
            with (
                self.subTest(field=field, value=value),
                expect_error(contracts.EvidenceError),
            ):
                evaluation.cloud_init_state(report)
        for finish in (None, 0, -1, True, float("nan")):
            report = fixtures.azure_retry_status()
            report["modules-final"]["finished"] = finish
            with self.subTest(finish=finish), expect_error(contracts.EvidenceError):
                evaluation.cloud_init_state(report)

    def test_rate_attribution_matches_observed_action_not_documented_enum(self):
        probe = dict(
            fixtures.probe("rate-limit"),
            path="/httpbin/anything/rate-limit",
            status=429,
            burst_end=105,
        )
        event = fixtures.rate_event(probe)
        ensure(bool(evaluation.attributed(event, probe, "demo", "demo-lb", 110)))
        for key, value in (
            ("rate_limiter_action", "RATE_LIMITED"),
            ("rate_limiter_action", "pass"),
            ("result", "deny"),
            (
                "rate_limiter_user_id",
                evaluation.identified_user("rate-limit-" + "b" * 32),
            ),
            ("policy_namespace", "other"),
            ("policy_set", "other"),
            ("policy", "other"),
            (
                "policy_rule",
                "ves-io-http-loadbalancer-rate-limiting-demo-lb-api-endpoint-rule-1",
            ),
        ):
            mutated = copy.deepcopy(event)
            mutated["policy_hits"]["policy_hits"][0][key] = value
            ensure(not evaluation.attributed(mutated, probe, "demo", "demo-lb", 110))
        for key, value in (
            ("sec_event_type", "waf_sec_event"),
            ("sec_event_type", "svc_policy_sec_event"),
            ("sec_event_name", "Malicious User Mitigation"),
            ("rsp_code", "403"),
            ("rsp_code", "200"),
            ("user", evaluation.identified_user("rate-limit-" + "b" * 32)),
            ("domain", DOMAINS[1]),
            ("req_path", "/httpbin/get"),
            ("method", "POST"),
            ("action", "allow"),
            ("time", "1970-01-01T00:01:39Z"),
            ("time", "1970-01-01T00:01:51Z"),
            ("policy_hits", []),
        ):
            ensure(
                not evaluation.attributed(
                    dict(event, **{key: value}), probe, "demo", "demo-lb", 110
                )
            )
        ensure(
            not evaluation.attributed(
                event, dict(probe, status=200), "demo", "demo-lb", 110
            )
        )
        # Observed event emission follows the HTTP response, but remains in this run's polling window.
        delayed = dict(event, time="1970-01-01T00:01:46Z")
        ensure(bool(evaluation.attributed(delayed, probe, "demo", "demo-lb", 110)))
