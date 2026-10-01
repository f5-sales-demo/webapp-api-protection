# ruff: noqa: PT009, PT027
"""Synthetic evaluator failure-path tests; never live security acceptance proof."""

import copy
import importlib.util
import json
import sys
import tempfile
import time
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "demo_verify", Path(__file__).parents[1] / "scripts/demo_verify.py"
)
v = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(v)
USER = "showcase-" + "a" * 32 + "-waf"
DOMAINS = ["www.example.test", "api.example.test"]


class VerifierTests(unittest.TestCase):
    def probe(self, control="waf"):
        return {
            "host": DOMAINS[0],
            "path": "/httpbin/get",
            "method": "GET",
            "user": USER,
            "sent_at": 100,
            "control": control,
        }

    def event(self):
        return {
            "namespace": "demo",
            "vh_name": v.virtual_host("demo-lb"),
            "domain": DOMAINS[0],
            "req_path": "/httpbin/get",
            "method": "GET",
            "user": v.identified_user(USER),
            "time": "1970-01-01T00:01:41Z",
            "sec_event_type": "waf_sec_event",
            "sec_event_name": "WAF",
            "app_firewall_name": "demo-lb-waf",
            "action": "block",
            "signatures": [{"id": "200002883", "state": "Enabled"}],
        }

    def test_observed_sanitized_records(self):
        fixture = json.loads(
            (Path(__file__).parent / "fixtures/demo_security_events.json").read_text()
        )
        events = [v.decode_event(raw) for raw in fixture["events"]]
        self.assertEqual(len(events), int(fixture["total_hits"]))
        for event, control, suffix in zip(
            events,
            ["waf", "schema", "endpoint-denial"],
            ["waf", "wrong", "deny-post"],
            strict=True,
        ):
            probe = self.probe(control)
            probe.update(
                user="showcase-" + "a" * 32 + "-d0-" + suffix,
                path=event["req_path"],
                method=event["method"],
                sent_at=v.stamp("2026-10-01T05:23:00Z"),
            )
            self.assertTrue(
                v.attributed(
                    event, probe, "demo", "demo-lb", v.stamp("2026-10-01T05:29:59Z")
                )
            )
            self.assertFalse(
                v.attributed(event, self.probe("mud"), "demo", "demo-lb", 110)
            )

    def test_wire_records_fail_closed(self):
        for raw in (
            {},
            "opaque",
            "[]",
            "null",
            json.dumps(json.dumps(self.event())),
            "x" * 100001,
        ):
            with (
                self.subTest(raw_type=type(raw).__name__),
                self.assertRaises(v.EvidenceError),
            ):
                v.decode_event(raw)

    def test_exact_event_query_uses_local_user_join(self):
        client = self.client()
        client.api = Mock(return_value=(200, {"events": [], "total_hits": "0"}))
        client.pages("demo", "demo-lb", 100, 110, user=USER)
        self.assertEqual(
            client.api.call_args.args[1]["query"],
            '{vh_name="ves-io-http-loadbalancer-demo-lb"}',
        )

    def test_full_count_with_live_scroll_token_is_complete(self):
        client = self.client()
        client.api = Mock(
            return_value=(
                200,
                {
                    "events": [json.dumps(self.event())],
                    "total_hits": "1",
                    "scroll_id": "retained",
                },
            )
        )
        self.assertEqual(client.pages("demo", "demo-lb", 100, 110), [self.event()])
        self.assertEqual(client.api.call_count, 1)

    def test_object_wire_item_is_not_legacy_success(self):
        client = self.client()
        client.api = Mock(
            return_value=(200, {"events": [self.event()], "total_hits": "1"})
        )
        with self.assertRaises(v.EvidenceError):
            client.pages("demo", "demo-lb", 100, 110)

    def test_wrong_waf_profile_signature_name_and_identity_prefix(self):
        for key, value in (
            ("app_firewall_name", "other"),
            ("signatures", [{"id": "1", "state": "Enabled"}]),
            ("sec_event_name", "Other"),
            ("user", USER),
            ("user", "Header-x-mud-user-" + USER),
            ("time", "1970-01-01 00:01:41+00:00"),
        ):
            event = dict(self.event(), **{key: value})
            self.assertFalse(v.attributed(event, self.probe(), "demo", "demo-lb", 110))

    def test_config_uid_is_not_virtual_host_identity(self):
        event = self.event()
        event["vhost_id"] = "not-the-config-uid"
        self.assertTrue(v.attributed(event, self.probe(), "demo", "demo-lb", 110))
        event["vh_name"] = "demo-lb"
        self.assertFalse(v.attributed(event, self.probe(), "demo", "demo-lb", 110))

    def test_identification_header_case_from_verified_policy(self):
        self.assertEqual(
            v.identified_user(USER, "X-MUD-User"), v.identified_user(USER, "x-mud-user")
        )
        with self.assertRaises(v.EvidenceError):
            v.identified_user(USER, "Other-Header")

    def test_rfc3339_outside_probe_window_fails(self):
        for value in ("1970-01-01T00:01:39Z", "1970-01-01T00:01:51Z"):
            self.assertFalse(
                v.attributed(
                    dict(self.event(), time=value), self.probe(), "demo", "demo-lb", 110
                )
            )

    def test_observed_schema_and_denial_markers_cannot_be_borrowed(self):
        fixture = json.loads(
            (Path(__file__).parent / "fixtures/demo_security_events.json").read_text()
        )
        for raw, control in zip(
            fixture["events"][1:], ["schema", "endpoint-denial"], strict=True
        ):
            event = v.decode_event(raw)
            probe = self.probe(control)
            probe.update(
                path=event["req_path"],
                method=event["method"],
                user=event["user"][len("Header-X-Mud-User-") :],
                sent_at=v.stamp("2026-10-01T05:23:00Z"),
            )
            end = v.stamp("2026-10-01T05:29:59Z")
            bad = copy.deepcopy(event)
            if control == "schema":
                bad["violations"][0]["field"] = "other"
                self.assertFalse(v.attributed(bad, probe, "demo", "demo-lb", end))
                bad = copy.deepcopy(event)
                bad["violations"][0]["context"] = "Response"
            else:
                bad["policy_hits"]["policy_hits"][0]["policy_rule"] += "-other"
                self.assertFalse(v.attributed(bad, probe, "demo", "demo-lb", end))
                bad = copy.deepcopy(event)
                bad["policy_hits"] = bad["policy_hits"]["policy_hits"][0]
            self.assertFalse(v.attributed(bad, probe, "demo", "demo-lb", end))

    def runs(self):
        start = time.time() - 400
        run = {
            "run_id": "a" * 32,
            "sequence": 0,
            "trigger": "scheduled",
            "status": "verified",
            "failures": [],
            "started_epoch": start,
            "started_at": datetime.fromtimestamp(start, UTC).isoformat(),
            "completed_at": datetime.fromtimestamp(start + 30, UTC).isoformat(),
            "domains": DOMAINS,
            "count": 1500,
            "rate": 50,
            "duration_seconds": 30,
            "transport_errors": 0,
            "benign_success": 1,
            "latencies": {
                "min": 1_000_000,
                "mean": 6_000_000,
                "50th": 5_000_000,
                "90th": 9_000_000,
                "95th": 10_000_000,
                "99th": 20_000_000,
                "max": 25_000_000,
            },
            "class_counts": {
                "benign": 1350,
                "waf": 30,
                "schema": 30,
                "endpoint-denial": 30,
                "rate-limit": 30,
                "mud": 30,
            },
            "security_evidence_scope": 'measurement only; fresh control attribution required',
            "rate_outcomes": {domain: {'status_counts': {'200': 15}, '429_count': 0,
                                       'rate_denial_observed': False} for domain in DOMAINS},
        }
        later = copy.deepcopy(run)
        later.update(
            run_id="b" * 32,
            sequence=1,
            started_epoch=start + 300,
            started_at=datetime.fromtimestamp(start + 300, UTC).isoformat(),
            completed_at=datetime.fromtimestamp(start + 330, UTC).isoformat(),
        )
        return {**later, "timer_active": True, "history": [run, later]}, start - 1

    def test_documented_waf_join(self):
        self.assertTrue(
            v.attributed(self.event(), self.probe(), "demo", "demo-lb", 110)
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
            event = self.event()
            event[key] = value
            with self.subTest(key=key, value=value):
                self.assertFalse(
                    v.attributed(event, self.probe(), "demo", "demo-lb", 110)
                )

    def test_generic_block_opaque_records_and_missing(self):
        for event in (
            {"rsp_code": "403"},
            {"message": json.dumps(self.event())},
            "opaque",
            {},
            None,
        ):
            self.assertFalse(v.attributed(event, self.probe(), "demo", "demo-lb", 110))
        self.assertFalse(v.telemetry_ready([], [self.probe()], "demo", "demo-lb", 110))
        self.assertFalse(v.telemetry_ready([self.event()], [], "demo", "demo-lb", 110))

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
            probe = self.probe(control)
            probe.update(path=path, method=method)
            event = self.event()
            event.update(
                sec_event_type="api_sec_event",
                sec_event_name=name,
                req_path=path,
                method=method,
                **extra,
            )
            self.assertTrue(v.attributed(event, probe, "demo", "demo-lb", 110))
            event["user"] = v.identified_user("showcase-" + "c" * 32 + "-unrelated")
            self.assertFalse(v.attributed(event, probe, "demo", "demo-lb", 110))

    def test_rate_identity_cannot_be_borrowed(self):
        event = self.event()
        event.update(
            sec_event_type="api_sec_event",
            sec_event_name="API Rate Limiting",
            policy_hits={
                "policy_hits": [
                    {"rate_limiter_action": "fail", "rate_limiter_user_id": "other"}
                ]
            },
        )
        self.assertFalse(
            v.attributed(event, self.probe("rate-limit"), "demo", "demo-lb", 110)
        )

    def test_missing_each_control_is_not_success(self):
        self.assertFalse(
            v.telemetry_ready(
                [self.event()],
                [self.probe(), self.probe("mud")],
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
            self.assertFalse(
                v.guest_ready({"schema_version": 1, "ready": True, "checks": checks})
            )
            checks[failed]["ready"] = True
            self.assertTrue(
                v.guest_ready({"schema_version": 1, "ready": True, "checks": checks})
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
            self.assertFalse(v.guest_ready(report))

    def test_fresh_failed_scheduled_history_cannot_be_hidden_by_later_pair(self):
        status, since = self.runs()
        failed = dict(status['history'][0], run_id='c' * 32, status='failed',
                      failures=['SECRET'], error_class='configuration')
        status['history'].insert(0, failed)
        self.assertEqual(v.traffic_failure(status, DOMAINS, since)['error_class'], 'configuration')
        self.assertFalse(v.traffic_ready(status, DOMAINS, since))
        self.assertNotIn('SECRET', json.dumps(v.traffic_failure(status, DOMAINS, since)))
        failed['started_epoch'] = since - 1
        self.assertIsNone(v.traffic_failure(status, DOMAINS, since))
        self.assertTrue(v.traffic_ready(status, DOMAINS, since))
        failed.update(started_epoch=since, trigger='manual')
        self.assertIsNone(v.traffic_failure(status, DOMAINS, since))

    def test_first_of_seven_hard_scheduled_failures_ends_polling_immediately(self):
        for error in ('configuration', 'tool_missing', 'metrics_unavailable', 'metrics_failed', 'SECRET'):
            history = [{'run_id': format(i, '032x'), 'started_epoch': 101 + i * 300,
                        'trigger': 'scheduled', 'status': 'failed', 'error_class': error,
                        'failures': ['SECRET']} for i in range(7)]
            client = self.client()
            client.deadline = time.monotonic() + 2400
            client.ssh = Mock(return_value=json.dumps({'timer_active': False, 'history': history}))
            client.pages = Mock()
            out = {'namespace': 'demo', 'loadbalancer_name': 'demo-lb', 'domains': DOMAINS, 'generator': {}}
            with self.subTest(error=error), patch.object(v, 'effective'), \
                    patch.object(v, 'probes', return_value=(USER, [self.probe('mud')], [])), \
                    patch.object(v.time, 'time', return_value=100), patch.object(v.time, 'sleep') as sleep:
                code, report = v.acceptance(client, out, Mock(poll_seconds=10))
            self.assertEqual(code, v.FAILURE)
            self.assertEqual(report['traffic_failure']['run_id'], '0' * 32)
            self.assertFalse(report['scheduled_traffic'])
            self.assertNotIn('SECRET', json.dumps(report))
            client.ssh.assert_called_once()
            client.pages.assert_not_called()
            sleep.assert_not_called()

    def test_fresh_genuine_metric_failure_aborts_even_if_marked_verified(self):
        status, since = self.runs()
        status['history'][0]['benign_success'] = .98
        failure = v.traffic_failure(status, DOMAINS, since)
        self.assertEqual(failure['error_class'], 'metrics_failed')
        self.assertIn('benign_success', failure['metric_failures'])
        self.assertFalse(v.traffic_ready(status, DOMAINS, since))

    def test_pending_running_and_stale_history_are_not_terminal_failures(self):
        for state in ('pending', 'running'):
            status = {'history': [{'trigger': 'scheduled', 'status': state, 'started_epoch': 100}]}
            self.assertIsNone(v.traffic_failure(status, DOMAINS, 99))
            self.assertFalse(v.traffic_ready(status, DOMAINS, 99))
        status = {'history': [{'trigger': 'scheduled', 'status': 'failed', 'started_epoch': 98}]}
        self.assertIsNone(v.traffic_failure(status, DOMAINS, 99))

    def test_measured_pair_accepts_1499_to_1501_requests_with_actual_rate(self):
        for count in (1499, 1500, 1501):
            status, since = self.runs()
            for run in status['history']:
                run.update(count=count, rate=count / 30)
                run['class_counts']['benign'] += count - 1500
            self.assertTrue(v.traffic_ready(status, DOMAINS, since))
        status, since = self.runs()
        status['history'][0]['trigger'] = 'manual'
        self.assertFalse(v.traffic_ready(status, DOMAINS, since))


    def test_scheduled_traffic_valid(self):
        status, since = self.runs()
        self.assertTrue(v.traffic_ready(status, DOMAINS, since))

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
            status, since = self.runs()
            status["history"][-1][key] = value
            with self.subTest(key=key):
                self.assertFalse(v.traffic_ready(status, DOMAINS, since))
        status, since = self.runs()
        status["history"] = status["history"][:1]
        self.assertFalse(v.traffic_ready(status, DOMAINS, since))

    def client(self):
        with patch.dict(
            v.os.environ,
            {
                "XCSH_API_URL": "https://console.example.test",
                "XCSH_API_TOKEN": "SECRET",
            },
        ):
            return v.Client(time.monotonic() + 2)

    def test_pagination_complete(self):
        client = self.client()
        client.api = Mock(
            side_effect=[
                (
                    200,
                    {
                        "events": [json.dumps(self.event())],
                        "total_hits": "2",
                        "scroll_id": "one",
                    },
                ),
                (
                    200,
                    {
                        "events": [json.dumps(self.event())],
                        "total_hits": "2",
                        "scroll_id": "",
                    },
                ),
            ]
        )
        self.assertEqual(len(client.pages("demo", "demo-lb", 100, 110)), 2)

    def test_truncated_malformed_repeated_and_unavailable_pages(self):
        for pages in (
            [(200, {"events": [], "total_hits": "1"})],
            [(200, {"events": {}, "total_hits": "0"})],
            [(200, {"events": [], "total_hits": "0", "truncated": True})],
            [(200, {"events": []})],
            [(404, {})],
            [(200, {"events": [self.event()], "total_hits": "3", "scroll_id": "same"})]
            * 2,
        ):
            client = self.client()
            client.api = Mock(side_effect=pages)
            with self.assertRaises(v.EvidenceError):
                client.pages("demo", "demo-lb", 100, 110)

    def test_commands_fail_closed(self):
        client = self.client()
        with (
            patch.object(
                v.subprocess, "run", return_value=Mock(returncode=1, stdout=b"SECRET")
            ),
            self.assertRaises(v.EvidenceError) as error,
        ):
            client.command(["false"])
        self.assertNotIn("SECRET", str(error.exception))

    def test_report_redaction_and_missing_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            with patch.dict(
                v.os.environ, {"XCSH_API_URL": "", "XCSH_API_TOKEN": "SECRET"}
            ):
                code = v.main(
                    [
                        "--outputs-json",
                        "/missing",
                        "--phase",
                        "readiness",
                        "--report",
                        str(path),
                    ]
                )
            self.assertEqual(code, v.FAILURE)
            text = path.read_text()
            self.assertNotIn("SECRET", text)
            self.assertFalse(json.loads(text)["verified"])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_absence_missing_manifest_rejected(self):
        with self.assertRaises(v.EvidenceError):
            v.absence(Mock(), {"schema_version": 1})

    def test_absence_and_preservation(self):
        sub = "11111111-1111-1111-1111-111111111111"
        owned = f"/subscriptions/{sub}/resourceGroups/demo/providers/Microsoft.Compute/virtualMachines/demo"
        manifest = {
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
        self.assertTrue(v.absence(client, manifest))
        client.azure_exists.assert_called_once_with(sub, owned, "2024-03-01")
        client.azure_exists.side_effect = [False]
        client.api.side_effect = [
            (404, {}),
            (200, {"system_metadata": {"uid": "changed-namespace-uid"}}),
        ]
        self.assertFalse(v.absence(client, manifest))
        obsolete = dict(
            manifest,
            azure_preserved=[f"/subscriptions/{sub}/resourceGroups/old-backend"],
        )
        with self.assertRaises(v.EvidenceError):
            v.absence(Mock(), obsolete)
        incomplete = dict(manifest)
        incomplete.pop("azure_preserved")
        with self.assertRaises(v.EvidenceError):
            v.absence(Mock(), incomplete)

    def test_mud_mitigation_requires_actual_matching_action(self):
        probe = self.probe("mud")
        event = self.mud_fixture()["mitigation_event"]
        event["user"] = v.identified_user(USER)
        self.assertTrue(v.attributed(event, probe, "demo", "demo-lb", 110))
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
                self.assertFalse(v.attributed(changed, probe, "demo", "demo-lb", 110))

    def test_generator_identities_are_exact_synthetic_values(self):
        for user in (
            "mud-" + "a" * 32,
            "rate-limit-" + "a" * 32,
            "waf-" + "a" * 32 + "-42",
            USER,
        ):
            self.assertIsNotNone(v.SYNTHETIC.fullmatch(user))
        for user in (
            "mud-real-user",
            "mud-" + "a" * 31,
            "real-user",
            "mud-" + "a" * 32 + "-untrusted",
        ):
            self.assertIsNone(v.SYNTHETIC.fullmatch(user))

    def test_suspicious_logs_pagination_requires_complete_envelope(self):
        client = self.client()
        client.api = Mock(
            side_effect=[
                (200, {"logs": ["opaque"], "total_hits": "2", "scroll_id": "first"}),
                (200, {"logs": ["opaque"], "total_hits": "2", "scroll_id": ""}),
            ]
        )
        user = "mud-" + "a" * 32
        self.assertEqual(
            client.pages("demo", "demo-lb", 100, 110, True, user), ["opaque", "opaque"]
        )
        self.assertIn(
            'user="' + v.identified_user(user) + '"',
            client.api.call_args_list[0].args[1]["query"],
        )
        client.api = Mock(return_value=(200, {"logs": [], "total_hits": "1"}))
        with self.assertRaises(v.EvidenceError):
            client.pages("demo", "demo-lb", 100, 110, True, user)

    def test_mitigation_without_documented_detection_remains_pending(self):
        client = self.client()
        client.deadline = time.monotonic() + 0.001
        event = self.event()
        event.update(
            sec_event_type="api_sec_event",
            policy_hits={
                "policy_hits": [
                    {"malicious_user_mitigate_action": "MUM_BLOCK_TEMPORARILY"}
                ]
            },
        )
        # Plausible but undocumented log fields MUST NOT become security proof.
        client.pages = Mock(
            side_effect=[
                [event],
                [
                    {
                        "namespace": "demo",
                        "vh_name": "demo-lb",
                        "user": USER,
                        "threat_level": "HIGH",
                        "first_event_time": 100,
                        "last_event_time": 101,
                        "detected_actions": ["block_temporarily"],
                    }
                ],
            ]
        )
        client.ssh = Mock(return_value=json.dumps({}))
        out = {
            "namespace": "demo",
            "loadbalancer_name": "demo-lb",
            "domains": DOMAINS,
            "generator": {},
        }
        with (
            patch.object(v, "effective"),
            patch.object(v, "probes", return_value=(USER, [self.probe("mud")], [])),
            patch.object(v, "traffic_ready", return_value=True),
        ):
            client.ssh.return_value = json.dumps({"history": []})
            code, report = v.acceptance(client, out, Mock(poll_seconds=1))
        self.assertEqual(code, v.PENDING)
        self.assertFalse(report["mud_mitigation"])
        self.assertFalse(report["mud_detection"])
        self.assertEqual(report["suspicious_log_count"], 1)
        self.assertIn("mud_detection", report["pending"])

    def test_opaque_mud_detection_always_pending(self):
        client = self.client()
        client.deadline = time.monotonic() + 0.001
        client.pages = Mock(return_value=[self.event()])
        client.ssh = Mock(
            return_value=json.dumps({"timer_active": False, "history": []})
        )
        args = Mock(poll_seconds=1)
        out = {
            "namespace": "demo",
            "loadbalancer_name": "demo-lb",
            "domains": DOMAINS,
            "generator": {},
        }
        with (
            patch.object(v, "effective"),
            patch.object(v, "probes", return_value=(USER, [self.probe("mud")], [])),
        ):
            code, report = v.acceptance(client, out, args)
        self.assertEqual(code, v.PENDING)
        self.assertFalse(report["mud_detection"])

    def mud_fixture(self):
        return json.loads(
            (Path(__file__).parent / "fixtures/demo_mud_detection.json").read_text()
        )

    def mud_evidence(self):
        fixture = self.mud_fixture()
        probe = self.probe("mud")
        probe.update(user="showcase-" + "a" * 32 + "-d0-mud", attack_started_at=100)
        event = dict(self.event(), user=v.identified_user(probe["user"]))
        return fixture["logs"][0], probe, event

    def test_observed_mud_detection_contract(self):
        raw, probe, event = self.mud_evidence()
        self.assertTrue(
            v.detection_attributed(raw, probe, [event], "demo", "demo-lb", 110)
        )
        self.assertTrue(
            v.detection_ready([raw], [probe], [event], "demo", "demo-lb", 110)
        )
        self.assertFalse(v.detection_ready([raw], [], [event], "demo", "demo-lb", 110))

    def test_mud_detection_rejects_wrong_scores_states_identity_and_units(self):
        raw, probe, event = self.mud_evidence()
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
            changed = dict(v.decode_event(raw), **{key: value})
            with self.subTest(key=key, value=value):
                self.assertFalse(
                    v.detection_attributed(
                        json.dumps(changed), probe, [event], "demo", "demo-lb", 110
                    )
                )

    def test_mud_detection_requires_positive_nested_waf_counts(self):
        raw, probe, event = self.mud_evidence()
        for key, value in (
            ("waf_sec_event_count", 0),
            ("req_count", 0),
            ("waf_sec_event_count", True),
            ("err_count", -1),
        ):
            log = v.decode_event(raw)
            activity = v.decode_event(log["incremental_activity_info"])
            activity[key] = value
            log["incremental_activity_info"] = json.dumps(activity)
            self.assertFalse(
                v.detection_attributed(
                    json.dumps(log), probe, [event], "demo", "demo-lb", 110
                )
            )

    def test_mud_detection_requires_same_fresh_waf_attack(self):
        raw, probe, event = self.mud_evidence()
        for key, value in (
            ("user", v.identified_user(USER)),
            ("time", "1970-01-01T00:01:39Z"),
            ("time", "1970-01-01T00:01:43Z"),
            ("signatures", []),
            ("action", "allow"),
        ):
            self.assertFalse(
                v.detection_attributed(
                    raw, probe, [dict(event, **{key: value})], "demo", "demo-lb", 110
                )
            )
        self.assertFalse(v.detection_attributed(raw, probe, [], "demo", "demo-lb", 110))
        self.assertFalse(
            v.detection_attributed(None, probe, [event], "demo", "demo-lb", 110)
        )
        self.assertFalse(
            v.detection_attributed("opaque", probe, [event], "demo", "demo-lb", 110)
        )

    def test_mud_mitigation_requires_exact_policy_context(self):
        event = self.mud_fixture()["mitigation_event"]
        probe = self.mud_evidence()[1]
        for key in (
            "policy",
            "policy_namespace",
            "policy_set",
            "malicious_user_mitigate_action",
        ):
            changed = copy.deepcopy(event)
            changed["policy_hits"]["policy_hits"][0][key] = "other"
            self.assertFalse(v.attributed(changed, probe, "demo", "demo-lb", 110))

    def test_mud_propagation_pending_then_blocked_with_good_control(self):
        client = Mock()
        client.request.side_effect = [(200, {}), (200, {}), (403, {}), (200, {})]
        probe = self.mud_evidence()[1]
        with patch.object(v.time, "time", side_effect=[103, 104]):
            self.assertFalse(v.mitigation_probe(client, probe))
            self.assertTrue(v.mitigation_probe(client, probe))
        self.assertEqual(probe["mitigation_sent_at"], 103)
        self.assertEqual(client.request.call_args.args[3], probe["user"] + "-negative")

    def test_mud_propagation_fails_if_independent_user_blocked(self):
        client = Mock()
        client.request.side_effect = [(403, {}), (403, {})]
        with self.assertRaises(v.EvidenceError):
            v.mitigation_probe(client, self.mud_evidence()[1])

    def test_two_measurements_without_fresh_control_attribution_cannot_pass(self):
        status, since = self.runs()
        raw, mud, waf = self.mud_evidence()
        mud.update(mitigation_sent_at=104, mitigation_blocked=True)
        required = [mud] + [dict(self.probe('rate-limit'), host=domain) for domain in DOMAINS]
        client = Mock(deadline=time.monotonic())
        client.ssh.return_value = json.dumps(status)
        client.pages.side_effect = [[waf, self.mud_fixture()['mitigation_event']], [raw]]
        out = {'namespace': 'demo', 'loadbalancer_name': 'demo-lb',
               'domains': DOMAINS, 'generator': {}}
        now = time.time()
        with patch.object(v, 'effective'), patch.object(v, 'probes', return_value=(USER, required, [])), \
                patch.object(v.time, 'time', side_effect=[since, now, now, now]):
            code, report = v.acceptance(client, out, Mock(poll_seconds=1))
        self.assertEqual(code, v.PENDING)
        self.assertTrue(report['scheduled_traffic'])
        self.assertFalse(report['controls_attributed'])
        self.assertTrue(report['mud_detection'])
        self.assertTrue(report['mud_mitigation'])
        self.assertEqual(len(report['traffic_runs']), 2)
        self.assertTrue(all(not outcome['rate_denial_observed'] for run in report['traffic_runs']
                            for outcome in run['rate_outcomes'].values()))


    def test_complete_fresh_mud_acceptance_after_delayed_poll(self):
        raw, probe, waf = self.mud_evidence()
        mitigation = self.mud_fixture()["mitigation_event"]
        other = self.probe()
        events = [waf, self.event(), mitigation]
        client = Mock(deadline=time.monotonic() + 100)
        client.pages.side_effect = [events, [raw], events, [raw], events, [raw]]
        client.request.side_effect = [(200, {}), (200, {}), (403, {}), (200, {})]
        client.ssh.return_value = json.dumps({"history": []})
        out = {
            "namespace": "demo",
            "loadbalancer_name": "demo-lb",
            "domains": DOMAINS,
            "generator": {},
        }
        # RFC3339 MUM event at 105 must be queried after its probe time.
        with (
            patch.object(v, "effective"),
            patch.object(v, "probes", return_value=(USER, [probe, other], [])),
            patch.object(v, "traffic_ready", return_value=True),
            patch.object(v.time, "sleep"),
            patch.object(v.time, "time", side_effect=[100, 104, 104, 106, 106, 107]),
        ):
            code, report = v.acceptance(client, out, Mock(poll_seconds=1))
        self.assertEqual(code, v.VERIFIED)
        self.assertTrue(report["mud_detection"])
        self.assertTrue(report["mud_mitigation"])
        self.assertEqual(client.request.call_count, 4)

    def test_final_acceptance_report_resolves_only_complete_fresh_evidence(self):
        for scenario in ("success", "missing-controls", "timeout", "failed-schedule"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                status, since = self.runs()
                raw, mud, waf = self.mud_evidence()
                mud.update(mitigation_sent_at=104, mitigation_blocked=True)
                events = [waf, self.event(), self.mud_fixture()["mitigation_event"]]
                required = [mud, self.probe()]
                if scenario == "missing-controls":
                    required.append(self.probe("unknown"))
                if scenario == "timeout":
                    status = {"history": []}
                elif scenario == "failed-schedule":
                    status["history"][-1].update(status="failed", error_class="metrics_failed")
                client = Mock(deadline=100, read_retries=[])
                client.ssh.side_effect = [json.dumps({"history": []}), json.dumps(status)]
                client.pages.side_effect = [events, [raw], events, [raw]]
                out = {"namespace": "demo", "loadbalancer_name": "demo-lb",
                       "domains": DOMAINS, "generator": {}}
                path = Path(tmp) / "report.json"
                now = time.time()
                clock = iter([since])
                with (
                    patch.object(v, "Client", return_value=client),
                    patch.object(v, "outputs", return_value=out),
                    patch.object(v, "effective"),
                    patch.object(v, "probes", return_value=(USER, required, [{"control": "waf", "request_count": 3}])),
                    patch.object(v.time, "time", side_effect=lambda clock=clock, now=now: next(clock, now)),
                    patch.object(v.time, "monotonic", side_effect=[0, 0, 100]),
                    patch.object(v.time, "sleep") as sleep,
                    patch("builtins.print"),
                ):
                    code = v.main(["--outputs-json", "synthetic", "--phase", "acceptance",
                                   "--poll-seconds", "1", "--report", str(path)])
                report = json.loads(path.read_text())
                evidence = report["evidence"]
                sleep.assert_called_once_with(1)
                self.assertEqual(report["exit_code"], code)
                self.assertEqual(report["verified"], scenario == "success")
                if scenario == "success":
                    self.assertEqual(code, v.VERIFIED)
                    self.assertNotIn("pending", evidence)
                    self.assertNotIn("failure", evidence)
                    self.assertNotIn("awaiting fresh evidence", path.read_text())
                    for gate in ("controls_attributed", "scheduled_traffic",
                                 "mud_detection", "mud_mitigation"):
                        self.assertTrue(evidence[gate])
                    self.assertEqual(len(evidence["traffic_runs"]), 2)
                    self.assertEqual(evidence["probe_count"], 3)
                    self.assertGreater(evidence["suspicious_log_count"], 0)
                    self.assertTrue(all(not outcome["rate_denial_observed"]
                                        for run in evidence["traffic_runs"]
                                        for outcome in run["rate_outcomes"].values()))
                elif scenario == "failed-schedule":
                    self.assertEqual(code, v.FAILURE)
                    self.assertEqual(evidence["failure"], "fresh scheduled traffic failed")
                    self.assertIn("pending", evidence)
                    self.assertIn("traffic_failure", evidence)
                else:
                    self.assertEqual(code, v.PENDING)
                    missing = "controls_attributed" if scenario == "missing-controls" else "scheduled_traffic"
                    self.assertIn(missing, evidence["pending"])
                    self.assertEqual(evidence["scheduled_traffic"], scenario == "missing-controls")


    def test_guest_actual_ready_field(self):
        report = {
            "schema_version": 1,
            "ready": True,
            "checks": [{"name": "service:nginx", "ready": True}],
        }
        self.assertTrue(v.guest_ready(report))
        report["checks"][0] = {"name": "service:nginx", "ok": True}
        self.assertFalse(v.guest_ready(report))

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
            status, since = self.runs()
            mutate(status)
            self.assertFalse(v.traffic_ready(status, DOMAINS, since))
        status, _ = self.runs()
        self.assertFalse(v.traffic_ready(status, DOMAINS, time.time()))
        self.assertFalse(
            v.traffic_ready(
                {"timer_active": True, "runs": status["history"]}, DOMAINS, 0
            )
        )

    def test_azure_rest_exact_status_and_redaction(self):
        sub = "11111111-1111-1111-1111-111111111111"
        rid = f"/subscriptions/{sub}/resourceGroups/demo"
        client = self.client()
        for status in (401, 403, 500, 404):
            result = Mock(
                returncode=1,
                stdout=b"",
                stderr=(
                    f"INFO: Response status: {status}\nERROR: "
                    + json.dumps(
                        {"error": {"code": "ResourceNotFound", "message": "SECRET"}}
                    )
                ).encode(),
            )
            with patch.object(v.subprocess, "run", return_value=result) as command:
                if status == 404:
                    self.assertFalse(client.azure_exists(sub, rid, "2021-04-01"))
                else:
                    with self.assertRaises(v.EvidenceError) as error:
                        client.azure_exists(sub, rid, "2021-04-01")
                    self.assertNotIn("SECRET", str(error.exception))
                argv = command.call_args.args[0]
                self.assertEqual(argv[:4], ["az", "rest", "--method", "get"])
                self.assertNotIn("get-access-token", argv)
                self.assertIn(
                    "https://management.azure.com" + rid + "?api-version=2021-04-01",
                    argv,
                )
        result = Mock(returncode=1, stdout=b"", stderr=b"ERROR: ResourceNotFound")
        with (
            patch.object(v.subprocess, "run", return_value=result),
            self.assertRaises(v.EvidenceError),
        ):
            client.azure_exists(sub, rid, "2021-04-01")
        result = Mock(returncode=0, stdout=json.dumps({"id": rid}).encode(), stderr=b"")
        with patch.object(v.subprocess, "run", return_value=result):
            self.assertTrue(client.azure_exists(sub, rid, "2021-04-01"))
        result.stdout = b'{"id":"other"}'
        with (
            patch.object(v.subprocess, "run", return_value=result),
            self.assertRaises(v.EvidenceError),
        ):
            client.azure_exists(sub, rid, "2021-04-01")

    def test_azure_transient_retry_requires_fresh_typed_absence(self):
        sub = "11111111-1111-1111-1111-111111111111"
        rid = f"/subscriptions/{sub}/resourceGroups/demo"
        absent = Mock(
            returncode=1,
            stdout=b"",
            stderr=(
                'INFO: Response status: 404\nERROR: Not Found({"error":'
                '{"code":"ResourceGroupNotFound","message":"gone"}})'
            ).encode(),
        )
        for reason, transient in (
            ("timeout", v.subprocess.TimeoutExpired("SECRET", 20)),
            ("transport", Mock(returncode=1, stdout=b"", stderr=b"ERROR: requests.exceptions.ConnectionError: SECRET")),
            ("http-429", Mock(returncode=1, stdout=b"", stderr=b"INFO: Response status: 429\nERROR: SECRET")),
            ("http-503", Mock(returncode=1, stdout=b"", stderr=b"INFO: Response status: 503\nERROR: SECRET")),
        ):
            with self.subTest(reason=reason):
                client = self.client()
                client.deadline = time.monotonic() + 60
                with (
                    patch.object(v.subprocess, "run", side_effect=[transient, absent]) as command,
                    patch.object(v.time, "sleep") as sleep,
                ):
                    # No absence is returned by the transient attempt: only the
                    # second, typed ARM response can establish it.
                    sleep.side_effect = lambda seconds: self.assertEqual(
                        client.read_retries, [{"reason": reason, "attempt": 1}]
                    )
                    self.assertFalse(client.azure_exists(sub, rid, "2021-04-01"))
                    self.assertEqual(command.call_count, 2)
                    self.assertEqual(command.call_args_list[0].args, command.call_args_list[1].args)
                    self.assertTrue(all(0 < call.kwargs["timeout"] <= 20 for call in command.call_args_list))
                    sleep.assert_called_once_with(1)
                self.assertEqual(client.read_retries, [{"reason": reason, "attempt": 1}])

    def test_azure_repeated_timeout_and_deadline_fail_closed(self):
        sub = "11111111-1111-1111-1111-111111111111"
        rid = f"/subscriptions/{sub}/resourceGroups/demo"
        for budget, expected_calls in ((60, 2), (0.5, 1)):
            client = self.client()
            client.deadline = time.monotonic() + budget
            with (
                patch.object(v.subprocess, "run", side_effect=v.subprocess.TimeoutExpired("SECRET", 20)) as command,
                patch.object(v.time, "sleep") as sleep,
                self.assertRaises(v.EvidenceError) as error,
            ):
                client.azure_exists(sub, rid, "2021-04-01")
            self.assertEqual(command.call_count, expected_calls)
            self.assertEqual(sleep.call_count, expected_calls - 1)
            self.assertNotIn("SECRET", str(error.exception))
        client = self.client()
        with (
            patch.object(v.subprocess, "run", side_effect=v.subprocess.TimeoutExpired("SECRET", 20)) as command,
            patch.object(v.time, "sleep", side_effect=lambda seconds: setattr(client, "deadline", 0)),
            self.assertRaises(v.EvidenceError),
        ):
            client.azure_exists(sub, rid, "2021-04-01")
        self.assertEqual(command.call_count, 1)

    def test_azure_permanent_failures_never_retry(self):
        sub = "11111111-1111-1111-1111-111111111111"
        rid = f"/subscriptions/{sub}/resourceGroups/demo"
        for failure in (
            FileNotFoundError("SECRET"),
            Mock(returncode=1, stdout=b"", stderr=b"INFO: Response status: 401\nERROR: SECRET"),
            Mock(returncode=1, stdout=b"", stderr=b"INFO: Response status: 403\nERROR: SECRET"),
            Mock(returncode=1, stdout=b"", stderr=b"INFO: Response status: 404\nERROR: SECRET"),
            Mock(returncode=1, stdout=b"", stderr=b'INFO: Response status: 404\nERROR: {"error":{"code":"InvalidApiVersionParameter"}}'),
            Mock(returncode=1, stdout=b"", stderr=b'INFO: Response status: 404\nERROR: {"wrapper":{"error":{"code":"ResourceNotFound"}}}'),
            Mock(returncode=1, stdout=b"", stderr=b'INFO: Response status: 404\nERROR: {invalid{"error":{"code":"ResourceNotFound"}}'),
            Mock(returncode=1, stdout=b"", stderr=b'INFO: Response status: 404\nERROR: {"error":"ResourceNotFound"}'),
            Mock(returncode=1, stdout=b"", stderr=b'INFO: Response status: 404\nERROR: {"error":{"code":"ResourceNotFound","message":42}}'),
            Mock(returncode=1, stdout=b"", stderr=b'INFO: Response status: 404\nERROR: {"error":{"code":"ResourceNotFound","target":"/wrong"}}'),
            Mock(returncode=1, stdout=b"", stderr=b'INFO: Response status: 404\nERROR: {"error":{"code":"ResourceNotFound","message":"/subscriptions/other/resourceGroups/other"}}'),
            Mock(returncode=0, stdout=b"[]", stderr=b""),
            Mock(returncode=0, stdout=b"invalid", stderr=b""),
            Mock(returncode=0, stdout=b'{"id":42}', stderr=b""),
        ):
            client = self.client()
            with (
                patch.object(v.subprocess, "run", side_effect=[failure]) as command,
                patch.object(v.time, "sleep") as sleep,
                self.assertRaises(v.EvidenceError) as error,
            ):
                client.azure_exists(sub, rid, "2021-04-01")
            self.assertEqual(command.call_count, 1)
            sleep.assert_not_called()
            self.assertEqual(client.read_retries, [])
            self.assertNotIn("SECRET", str(error.exception))

    def test_azure_transient_then_present_never_means_absent(self):
        sub = "11111111-1111-1111-1111-111111111111"
        rid = f"/subscriptions/{sub}/resourceGroups/demo"
        client = self.client()
        with (
            patch.object(v.subprocess, "run", side_effect=[
                v.subprocess.TimeoutExpired("az", 20),
                Mock(returncode=0, stdout=json.dumps({"id": rid}).encode(), stderr=b""),
            ]),
            patch.object(v.time, "sleep"),
        ):
            self.assertTrue(client.azure_exists(sub, rid, "2021-04-01"))


    def test_azure_retry_diagnostics_report_success_and_failure(self):
        sub = "11111111-1111-1111-1111-111111111111"
        rid = f"/subscriptions/{sub}/resourceGroups/demo"
        for succeeds in (True, False):
            with self.subTest(succeeds=succeeds), tempfile.TemporaryDirectory() as tmp:
                client = self.client()
                client.deadline = time.monotonic() + 60
                result = Mock(
                    returncode=1, stdout=b"",
                    stderr=b'INFO: Response status: 404\nERROR: {"error":{"code":"ResourceNotFound","message":"SECRET"}}',
                )
                attempts = [v.subprocess.TimeoutExpired("SECRET", 20)]
                attempts.append(result if succeeds else v.subprocess.TimeoutExpired("SECRET", 20))
                report_path = Path(tmp) / "report.json"
                with (
                    patch.object(v, "Client", return_value=client),
                    patch.object(v, "absence", side_effect=lambda c, m: not c.azure_exists(sub, rid, "2021-04-01")),
                    patch.object(Path, "read_text", return_value="{}"),
                    patch.object(v.subprocess, "run", side_effect=attempts),
                    patch.object(v.time, "sleep"),
                    patch("builtins.print"),
                ):
                    code = v.main([
                        "--outputs-json", "unused", "--phase", "absence",
                        "--run-manifest", "unused", "--report", str(report_path),
                    ])
                report_text = report_path.read_text()
                report = json.loads(report_text)
                self.assertEqual(code, v.VERIFIED if succeeds else v.FAILURE)
                self.assertEqual(report["verified"], succeeds)
                self.assertEqual(report["read_retries"], [{"reason": "timeout", "attempt": 1}])
                self.assertNotIn("SECRET", report_text)
                self.assertNotIn(rid, report_text)


    def readiness_client(
        self, cloud_status="done", returned_host=None, returned_path="/get"
    ):
        client = Mock()
        client.ssh.side_effect = [
            json.dumps(
                {"status": cloud_status, "errors": [], "recoverable_errors": {}}
            ),
            "Result=success\nExecMainStatus=0\n",
            json.dumps({"status": "done", "errors": [], "recoverable_errors": {}}),
            "Result=success\nExecMainStatus=0\n",
            json.dumps(
                {
                    "schema_version": 1,
                    "ready": True,
                    "checks": [{"name": "httpbin-1", "ready": True}],
                }
            ),
        ]
        client.request.side_effect = [
            (200, {"url": "http://" + (returned_host or domain) + returned_path})
            for domain in DOMAINS
        ]
        return client

    def test_readiness_actual_rewritten_url_and_cloud_done(self):
        out = {"domains": DOMAINS, "origin": {}, "generator": {}}
        with patch.object(v, "effective"):
            result = v.readiness(self.readiness_client(), out, Mock())
            self.assertEqual(result["application_domains"], 2)
            for status in ("done (degraded)", "error", "disabled"):
                with self.assertRaises(v.EvidenceError):
                    v.readiness(self.readiness_client(status), out, Mock())
            for host, path in (
                ("other.example.test", "/get"),
                (None, "/httpbin/get"),
                (None, "/get?x=/get"),
            ):
                with self.assertRaises(v.EvidenceError):
                    v.readiness(
                        self.readiness_client(returned_host=host, returned_path=path),
                        out,
                        Mock(),
                    )

    def test_readiness_poll_exceeds_short_budget_then_done(self):
        client = self.readiness_client()
        done = json.dumps({"status": "done", "errors": [], "recoverable_errors": {}})
        running = json.dumps({"status": "running", "errors": []})
        client.ssh.side_effect = [
            running,
            running,
            running,
            done,
            "Result=success\nExecMainStatus=0\n",
            done,
            "Result=success\nExecMainStatus=0\n",
            json.dumps(
                {
                    "ready": True,
                    "schema_version": 1,
                    "checks": [{"name": "replica", "ready": True}],
                }
            ),
        ]
        clock = [0]
        real = self.client()
        real.deadline = 60
        client.remaining.side_effect = real.remaining
        args = Mock(poll_seconds=10)
        with (
            patch.object(v, "effective"),
            patch.object(v.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(
                v.time,
                "sleep",
                side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
            ),
        ):
            self.assertEqual(
                v.readiness(
                    client, {"domains": DOMAINS, "origin": {}, "generator": {}}, args
                )["origin_checks"],
                1,
            )
        self.assertEqual(clock[0], 30)
        self.assertNotIn("--wait", client.ssh.call_args_list[0].args[2])

    def test_cloud_init_deadline_and_ssh_fail_fast(self):
        out = {"domains": DOMAINS, "origin": {}, "generator": {}}
        for failure in (
            v.EvidenceError("required command failed"),
            v.EvidenceError("deadline exceeded"),
        ):
            client = self.readiness_client()
            client.ssh.side_effect = failure
            with patch.object(v, "effective"), self.assertRaises(v.EvidenceError):
                v.readiness(client, out, Mock(poll_seconds=10))
            self.assertEqual(client.ssh.call_count, 1)
            client.request.assert_not_called()

    def test_cloud_init_running_deadline_expires(self):
        client = self.readiness_client()
        client.ssh.side_effect = None
        client.ssh.return_value = json.dumps({"status": "running"})
        clock = [0]
        real = self.client()
        real.deadline = 25
        client.remaining.side_effect = real.remaining
        with (
            patch.object(v, "effective"),
            patch.object(v.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(
                v.time,
                "sleep",
                side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
            ),
            self.assertRaisesRegex(v.EvidenceError, "deadline exceeded"),
        ):
            v.readiness(
                client,
                {"domains": DOMAINS, "origin": {}, "generator": {}},
                Mock(poll_seconds=10),
            )
        self.assertEqual(clock[0], 25)
        client.request.assert_not_called()

    def test_cloud_init_degraded_and_stage_errors_fail(self):
        for report in (
            {"status": "done", "extended_status": "degraded done"},
            {"status": "done", "modules-final": {"errors": ["SECRET"]}},
            {"status": "done", "recoverable_errors": {"WARNING": ["SECRET"]}},
        ):
            client = self.readiness_client()
            client.ssh.side_effect = [json.dumps(report)]
            with (
                patch.object(v, "effective"),
                self.assertRaises(v.EvidenceError) as error,
            ):
                v.readiness(
                    client, {"domains": DOMAINS, "origin": {}, "generator": {}}, Mock()
                )
            self.assertNotIn("SECRET", str(error.exception))
            client.request.assert_not_called()

    @staticmethod
    def azure_retry_status():
        # Sanitized current origin capture: one retained warning per stage.
        warning = (
            "Polling IMDS failed attempt 1 with exception: UrlError('404 Client Error: "
            "Not Found for url: http://169.254.169.254/metadata/reprovisiondata?"
            "api-version=2019-06-01')"
        )
        report = {
            "datasource": "azure",
            "status": "done",
            "extended_status": "degraded done",
            "stage": None,
            "errors": [],
            "recoverable_errors": {"WARNING": [warning] * 4},
        }
        for name, start, finish in (
            ("init", 1886.32, 1890.04),
            ("init-local", 7.11, 1883.94),
            ("modules-config", 1890.69, 1891.2),
            ("modules-final", 1892.26, 2979.35),
        ):
            report[name] = {
                "errors": [],
                "start": start,
                "finished": finish,
                "recoverable_errors": {"WARNING": [warning]},
            }
        return report

    def test_cloud_init_exact_recovered_warning_remains_degraded(self):
        result = v.cloud_init_state(self.azure_retry_status())
        self.assertEqual(result["status"], "degraded_done")
        self.assertEqual(result["warnings_accepted"], 4)
        self.assertEqual(result["fatal_errors"], 0)
        self.assertTrue(result["sources"])

    def test_cloud_init_running_warning_then_terminal_and_unit_success(self):
        client = self.readiness_client()
        client.remaining.return_value = 30
        tail = list(client.ssh.side_effect)[2:]
        running = self.azure_retry_status()
        running.update(status="running", extended_status="degraded running")
        running["modules-final"]["finished"] = None
        client.ssh.side_effect = [
            json.dumps(running),
            json.dumps(self.azure_retry_status()),
            "Result=success\nExecMainStatus=0\n",
            *tail,
        ]
        with patch.object(v, "effective"), patch.object(v.time, "sleep"):
            report = v.readiness(
                client,
                {"domains": DOMAINS, "origin": {}, "generator": {}},
                Mock(poll_seconds=1),
            )
        self.assertTrue(report["cloud_init"])
        self.assertEqual(report["cloud_init_info"]["origin"]["warnings_accepted"], 4)
        self.assertEqual(report["cloud_init_info"]["generator"]["warnings_accepted"], 0)

    def test_cloud_init_warning_policy_fail_closed(self):
        for field, value in (
            ("datasource", "ec2"),
            ("stage", "modules-final"),
            ("errors", ["module failed"]),
            ("recoverable_errors", {"ERROR": [v.AZURE_REPROVISION_WARNING] * 4}),
            ("recoverable_errors", {"WARNING": ["apt HTTP 404"]}),
            (
                "recoverable_errors",
                {"WARNING": [v.AZURE_REPROVISION_WARNING.replace("404", "500")] * 4},
            ),
            ("modules-final", {"errors": ["init failure"]}),
        ):
            report = self.azure_retry_status()
            report[field] = value
            with (
                self.subTest(field=field, value=value),
                self.assertRaises(v.EvidenceError),
            ):
                v.cloud_init_state(report)
        for finish in (None, 0, -1, True, float("nan")):
            report = self.azure_retry_status()
            report["modules-final"]["finished"] = finish
            with self.subTest(finish=finish), self.assertRaises(v.EvidenceError):
                v.cloud_init_state(report)

    def test_cloud_init_completion_requires_successful_final_unit(self):
        for status in (
            self.azure_retry_status(),
            {"status": "done", "errors": [], "recoverable_errors": {}},
        ):
            client = self.readiness_client()
            client.ssh.side_effect = [
                json.dumps(status),
                "Result=exit-code\nExecMainStatus=1\n",
            ]
            with patch.object(v, "effective"), self.assertRaises(v.EvidenceError):
                v.readiness(
                    client, {"domains": DOMAINS, "origin": {}, "generator": {}}, Mock()
                )
            client.request.assert_not_called()

    def test_cloud_init_pending_warnings_timeout_and_fatal_running(self):
        client = self.readiness_client()
        running = self.azure_retry_status()
        running.update(status="running", extended_status="degraded running")
        client.ssh.side_effect = [json.dumps(running)]
        client.remaining.side_effect = [1, v.EvidenceError("deadline exceeded")]
        with (
            patch.object(v, "effective"),
            self.assertRaisesRegex(v.EvidenceError, "deadline"),
        ):
            v.readiness(
                client, {"domains": DOMAINS, "origin": {}, "generator": {}}, Mock()
            )
        running["modules-final"]["errors"] = ["fatal"]
        with self.assertRaises(v.EvidenceError):
            v.cloud_init_state(running)
        for status in ("unknown", "disabled", "error"):
            with self.assertRaises(v.EvidenceError):
                v.cloud_init_state({"status": status})

    def test_phase_command_budget_and_process_group_cleanup(self):
        client = self.client()
        client.deadline = time.monotonic() + 100
        self.assertLessEqual(client.remaining(), 20)
        self.assertGreater(client.remaining(phase_budget=True), 20)
        self.assertEqual(
            client.command([sys.executable, "-c", "print('ready')"], phase_budget=True),
            "ready\n",
        )
        client.deadline = time.monotonic() + 0.1
        with self.assertRaises(v.EvidenceError):
            client.command(
                [sys.executable, "-c", "import time; time.sleep(30)"], phase_budget=True
            )

    def effective_fixture(self, challenge="enable_challenge"):
        # Allowlisted shape observed on the rebuilt LB, not provider HCL nesting.
        def ref(name):
            return {"tenant": "demo-tenant", "namespace": "demo", "name": name}

        spec = {
            "domains": DOMAINS,
            "enable_api_discovery": {"default_api_auth_discovery": {}},
            "enable_malicious_user_detection": {},
            challenge: {"malicious_user_mitigation": ref("demo-mud")},
            "user_identification": ref("demo-userid"),
            "app_firewall": ref("demo-waf"),
            "api_specification": {
                "api_definition": ref("demo-api"),
                "validation_all_spec_endpoints": {
                    "validation_mode": {
                        "validation_mode_active": {"enforcement_block": {}},
                        "skip_response_validation": {},
                    }
                },
            },
            "api_rate_limit": {
                "no_ip_allowed_list": {},
                "server_url_rules": [],
                "api_endpoint_rules": [
                    {
                        "any_domain": {},
                        "base_path": "",
                        "api_endpoint_path": "/httpbin/anything/rate-limit",
                        "api_endpoint_method": {
                            "methods": ["GET"],
                            "invert_matcher": False,
                        },
                        "request_matcher": None,
                        "client_matcher": None,
                        "inline_rate_limiter": {
                            "threshold": 20,
                            "unit": "MINUTE",
                            "use_http_lb_user_id": {},
                        },
                    }
                ],
            },
        }
        responses = [
            (200, {"metadata": {"name": "demo-lb", "namespace": "demo"}, "spec": spec}),
            (200, {"spec": {"blocking": {}}}),
            (200, {"spec": {"rules": [{"http_header_name": "X-MUD-User"}]}}),
            (
                200,
                {
                    "spec": {
                        "mitigation_type": {
                            "rules": [
                                {
                                    "threat_level": {level: {}},
                                    "mitigation_action": {"block_temporarily": {}},
                                }
                                for level in ("low", "medium", "high")
                            ]
                        }
                    }
                },
            ),
        ]
        client = Mock()
        client.api.side_effect = responses
        out = {"namespace": "demo", "loadbalancer_name": "demo-lb", "domains": DOMAINS}
        return client, out, spec, responses

    def test_effective_actual_top_level_empty_markers_and_policy_arms(self):
        for challenge in ("enable_challenge", "policy_based_challenge"):
            client, out, _, _ = self.effective_fixture(challenge)
            v.effective(client, out)
            self.assertEqual(client.api.call_count, 4)
            self.assertEqual(
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
            client, out, spec, _ = self.effective_fixture()
            mutate(spec)
            with self.subTest(mutate=mutate), self.assertRaises(v.EvidenceError):
                v.effective(client, out)

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
            client, out, _, responses = self.effective_fixture()
            mutate(responses[target][1])
            with (
                self.subTest(target=target, mutate=mutate),
                self.assertRaises(v.EvidenceError),
            ):
                v.effective(client, out)
        client, out, _, responses = self.effective_fixture()
        responses[3] = (404, {})
        with self.assertRaises(v.EvidenceError):
            v.effective(client, out)

    def test_readiness_rejects_generator_cloud_init_failure(self):
        client = self.readiness_client()
        client.ssh.side_effect = [
            json.dumps({"status": "done", "errors": [], "recoverable_errors": {}}),
            "Result=success\nExecMainStatus=0\n",
            json.dumps({"status": "error", "errors": ["install failed"]}),
        ]
        out = {"domains": DOMAINS, "origin": {}, "generator": {}}
        with patch.object(v, "effective"), self.assertRaises(v.EvidenceError):
            v.readiness(client, out, Mock())
        client.request.assert_not_called()

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
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "outputs.json"
            path.write_text(json.dumps({"showcase": {"value": out}}))
            self.assertEqual(v.outputs(path), out)
            protection["mud_user_id"] = "header"
            path.write_text(json.dumps(out))
            with self.assertRaises(v.EvidenceError):
                v.outputs(path)

    def rate_event(self, probe):
        policy_set = "ves-io-http-loadbalancer-rate-limiting-demo-lb"
        return dict(
            self.event(),
            req_path=probe["path"],
            user=v.identified_user(probe["user"]),
            sec_event_type="api_sec_event",
            sec_event_name="API Rate Limiting",
            rsp_code="429",
            policy_hits={
                "policy_hits": [
                    {
                        "rate_limiter_action": "fail",
                        "rate_limiter_user_id": v.identified_user(probe["user"]),
                        "result": "rate_limiter_drop",
                        "policy_namespace": "demo",
                        "policy_set": policy_set,
                        "policy": policy_set + "-api-endpoint",
                        "policy_rule": policy_set + "-api-endpoint-rule-0",
                    }
                ]
            },
        )

    def rate_client(self, statuses):
        client = Mock(deadline=time.monotonic() + 100)
        codes = iter(statuses)

        def respond(host, path, method, user):
            code = next(codes)
            return code, {
                "url": "http://" + host + path.removeprefix("/httpbin"),
                "headers": {"X-Mud-User": user},
            } if code == 200 else None

        client.request.side_effect = respond
        return client

    def test_rate_burst_observed_late_denial_and_refill(self):
        for statuses in (
            [200] * 23 + [429] * 7,
            [200] * 22 + [429] * 8,
            [200] * 21 + [429] * 8 + [200],
        ):
            client = self.rate_client([*statuses, 200, 200])
            deadline = client.deadline
            probe, summary = v.rate_burst(client, DOMAINS[0], USER)
            self.assertEqual(client.deadline, deadline)
            self.assertEqual(summary["request_count"], 30)
            self.assertEqual(summary["status_counts"]["429"], statuses.count(429))
            self.assertEqual(summary["status_counts"]["200"], statuses.count(200))
            self.assertEqual(summary["first_denial_request"], statuses.index(429) + 1)
            self.assertEqual(summary["threshold"], 20)
            self.assertEqual(summary["unit"], "MINUTE")
            self.assertEqual(summary["bucket_semantics_source"], v.RATE_BUCKET_SOURCE)
            self.assertEqual(len(probe["denial_requests"]), statuses.count(429))
            self.assertEqual(probe["sent_at"], probe["denial_requests"][0]["sent_at"])
            self.assertLessEqual(summary["duration_seconds"], 30)
            self.assertEqual(client.request.call_count, 32)
            self.assertEqual(
                client.request.call_args_list[-2].args[3], USER + "-independent"
            )
            self.assertEqual(
                client.request.call_args_list[-1].args[1:],
                ("/httpbin/get", "GET", USER),
            )
            self.assertTrue(summary["independent_user_allowed"])
            self.assertTrue(summary["same_user_unrelated_path_allowed"])

    def test_rate_burst_all_200_is_diagnostic_failure(self):
        client = self.rate_client([200] * 30)
        with self.assertRaisesRegex(v.EvidenceError, "no HTTP 429") as caught:
            v.rate_burst(client, DOMAINS[0], USER)
        summary = json.loads(str(caught.exception).split(": ", 1)[1])
        self.assertEqual(summary["status_counts"], {"200": 30})
        self.assertEqual(summary["request_count"], 30)
        self.assertIn("duration_seconds", summary)
        self.assertEqual(client.request.call_count, 30)

    def test_rate_burst_wrong_denial_and_origin_pages_fail(self):
        for code, body in (
            (403, None),
            (503, None),
            (200, None),
            (200, {"url": "http://other.example.test/anything/rate-limit"}),
            (200, {"url": "http://" + DOMAINS[0] + "/get"}),
        ):
            client = self.rate_client([200] * 30)
            client.request.side_effect = None
            client.request.return_value = (code, body)
            with self.assertRaises(v.EvidenceError):
                v.rate_burst(client, DOMAINS[0], USER)
        for code in (403, 503):
            client = self.rate_client([200] * 21 + [code])
            with self.assertRaisesRegex(v.EvidenceError, "only HTTP 429"):
                v.rate_burst(client, DOMAINS[0], USER)

    def test_rate_burst_isolation_controls_must_reach_origin(self):
        for controls in ([403, 200], [200, 429]):
            client = self.rate_client([200] * 22 + [429] * 8 + controls)
            with self.assertRaisesRegex(v.EvidenceError, "positive origin"):
                v.rate_burst(client, DOMAINS[0], USER)

    def test_rate_burst_deadline_and_transport_bound(self):
        client = self.rate_client([200] * 30)
        client.deadline = 102
        with (
            patch.object(v.time, "monotonic", side_effect=[100, 100, 102, 102]),
            self.assertRaisesRegex(v.EvidenceError, "duration budget exhausted"),
        ):
            v.rate_burst(client, DOMAINS[0], USER)
        self.assertEqual(client.request.call_count, 1)
        self.assertEqual(client.deadline, 102)
        client = self.rate_client([200] * 30)
        client.request.side_effect = v.EvidenceError("application transport failure")
        deadline = client.deadline
        with self.assertRaisesRegex(
            v.EvidenceError, "application transport failure"
        ) as caught:
            v.rate_burst(client, DOMAINS[0], USER)
        self.assertIn('"request_count": 0', str(caught.exception))
        self.assertEqual(client.deadline, deadline)

    def test_rate_attribution_matches_observed_action_not_documented_enum(self):
        probe = dict(
            self.probe("rate-limit"),
            path="/httpbin/anything/rate-limit",
            status=429,
            burst_end=105,
        )
        event = self.rate_event(probe)
        self.assertTrue(v.attributed(event, probe, "demo", "demo-lb", 110))
        for key, value in (
            ("rate_limiter_action", "RATE_LIMITED"),
            ("rate_limiter_action", "pass"),
            ("result", "deny"),
            ("rate_limiter_user_id", v.identified_user("rate-limit-" + "b" * 32)),
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
            self.assertFalse(v.attributed(mutated, probe, "demo", "demo-lb", 110))
        for key, value in (
            ("sec_event_type", "waf_sec_event"),
            ("sec_event_type", "svc_policy_sec_event"),
            ("sec_event_name", "Malicious User Mitigation"),
            ("rsp_code", "403"),
            ("rsp_code", "200"),
            ("user", v.identified_user("rate-limit-" + "b" * 32)),
            ("domain", DOMAINS[1]),
            ("req_path", "/httpbin/get"),
            ("method", "POST"),
            ("action", "allow"),
            ("time", "1970-01-01T00:01:39Z"),
            ("time", "1970-01-01T00:01:51Z"),
            ("policy_hits", []),
        ):
            self.assertFalse(
                v.attributed(dict(event, **{key: value}), probe, "demo", "demo-lb", 110)
            )
        self.assertFalse(
            v.attributed(event, dict(probe, status=200), "demo", "demo-lb", 110)
        )
        # Observed event emission follows the HTTP response, but remains in this run's polling window.
        delayed = dict(event, time="1970-01-01T00:01:46Z")
        self.assertTrue(v.attributed(delayed, probe, "demo", "demo-lb", 110))

    def test_rate_rule_must_be_effective_endpoint_index_zero(self):
        client, out, spec, _ = self.effective_fixture()
        rule = spec["api_rate_limit"]["api_endpoint_rules"][0]
        spec["api_rate_limit"]["api_endpoint_rules"].insert(
            0, dict(rule, api_endpoint_path="/other")
        )
        with self.assertRaisesRegex(
            v.EvidenceError, "rate limit configuration mismatch"
        ):
            v.effective(client, out)

    def test_paired_probes_use_separate_fresh_rate_users_and_late_denials(self):
        client = Mock(deadline=time.monotonic() + 100)
        counts = {}

        def respond(host, path, method, user, body=None):
            code = 200
            if path == "/httpbin/anything/rate-limit" and user.endswith("-rate"):
                counts[user] = counts.get(user, 0) + 1
                allowed = 23 if host == DOMAINS[0] else 22
                code = 200 if counts[user] <= allowed else 429
            elif (
                (host in DOMAINS and path == "/httpbin/anything/admin")
                or user.endswith(("-missing", "-wrong", "-waf"))
                or (user.endswith("-mud") and "?" in path)
            ):
                code = 403
            return code, {
                "url": "http://" + host + path.removeprefix("/httpbin"),
                "headers": {"X-Mud-User": user},
            }

        client.request.side_effect = respond
        run, required, results = v.probes(
            client,
            {
                "domains": DOMAINS,
                "origin": {"public_ip": "192.0.2.1"},
            },
        )
        rate_probes = [p for p in required if p["control"] == "rate-limit"]
        bursts = [r for r in results if r["control"] == "rate-burst"]
        self.assertEqual(
            [p["user"] for p in rate_probes], [run + "-d0-rate", run + "-d1-rate"]
        )
        self.assertEqual(
            [r["status_counts"] for r in bursts],
            [{"200": 23, "429": 7}, {"200": 22, "429": 8}],
        )
        self.assertEqual(client.request.call_count, 148)


if __name__ == "__main__":
    unittest.main()
