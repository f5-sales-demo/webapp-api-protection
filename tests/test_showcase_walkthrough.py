# Ruff's pytest preferences do not apply to the repository's unittest runner.
# ruff: noqa: PT009, PT027
"""Failure tests for matched configuration phases; never live acceptance."""

import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import showcase_walkthrough as runner
from demo_verify_types import EvidenceError
from showcase_walkthrough_evidence import bind_ordered_requests, schema_report

from scripts.showcase_walkthrough_config import Configuration
from scripts.showcase_walkthrough_evidence import access_pages, blocked, matched
from tests.demo_verify_fixtures import event, probe


class FakeClient:
    def __init__(self):
        self.deadline = 0
        self.form: dict = {
            "metadata": {"name": "synthetic", "annotations": {"preserve": "yes"}},
            "spec": {"blocking": {}, "routing": {"preserve": "yes"}},
            "resource_version": "1",
        }
        self.fail_put = False

    def api(self, _path, _payload=None):
        return 200, {"replace_form": copy.deepcopy(self.form)}


class Transactions(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(self.temporary.cleanup)
        self.client = FakeClient()
        self.config = Configuration(self.client, Path(self.temporary.name))
        self.config.capture("/api/config/synthetic")

    def test_configuration_writes_are_prohibited(self):
        original = copy.deepcopy(self.client.form)
        for method in (self.config.put, self.config.update):
            with self.assertRaises(EvidenceError):
                method("/api/config/synthetic", original)
        self.assertEqual(self.client.form, original)
        self.assertTrue(self.config.restore())

    def test_concurrent_change_is_detected_without_repair(self):
        self.client.form["spec"]["routing"]["preserve"] = "concurrent"
        self.assertFalse(self.config.restore())
        self.assertEqual(self.client.form["spec"]["routing"]["preserve"], "concurrent")

    def test_failed_read_is_incomplete(self):
        with patch.object(
            self.config, "read", side_effect=EvidenceError("read failed")
        ):
            self.assertFalse(self.config.restore())


class ReadOnlyControlSampling(unittest.TestCase):
    def test_missing_legitimate_get_is_retried_with_exact_origin_echo(self):
        with tempfile.TemporaryDirectory() as directory:
            client = Mock()
            client.walkthrough_directory = Path(directory)
            client.clock_bounds = (-1, 3)
            original: dict = {
                "host": "www.example.test",
                "path": "/httpbin/get",
                "request_target": "/httpbin/get",
                "method": "GET",
                "user": "showcase-" + "a" * 32 + "-legitimate",
                "sent_at": 100,
                "received_at": 101,
                "status": 200,
                "body": {},
                "control": "",
                "label": "legitimate",
                "clock_offset_min": -1,
                "clock_offset_max": 3,
            }
            probes = [original]
            retry = {
                **original,
                "user": original["user"] + "-sample-1",
                "sent_at": 200,
                "received_at": 201,
            }
            with (
                patch("showcase_walkthrough_evidence.matched", return_value=None),
                patch.object(runner, "send", return_value=retry) as send,
                patch.object(runner, "rate_origin") as echo,
                patch("showcase_walkthrough_evidence.time.monotonic", return_value=61),
            ):
                runner.resample_legitimate(
                    client,
                    probes,
                    [],
                    "example",
                    "example",
                    {"started": 0, "attempts": 0},
                )
            self.assertEqual(probes, [retry])
            self.assertEqual(send.call_args.args[3], "GET")
            self.assertEqual(
                echo.call_args.args,
                (200, {}, retry["host"], "/httpbin/get", retry["user"]),
            )
            journal = __import__("json").loads(
                (Path(directory) / "legitimate-sample-retries.json").read_text()
            )
            self.assertEqual(journal[0]["original"], original)
            self.assertEqual(journal[0]["retry"], retry)

    def test_mutation_denial_and_rate_burst_are_never_resampled(self):
        client = Mock()
        probes = [
            {
                "method": "POST",
                "path": "/httpbin/post",
                "status": 200,
                "control": "",
                "label": "valid",
            },
            {
                "method": "GET",
                "path": "/httpbin/get",
                "status": 403,
                "control": "mud",
                "label": "later-benign",
            },
            {
                "method": "GET",
                "path": "/httpbin/anything/rate-limit",
                "status": 200,
                "control": "rate-limit",
                "label": "burst",
            },
        ]
        original = copy.deepcopy(probes)
        with (
            patch.object(runner, "send") as send,
            patch("showcase_walkthrough_evidence.time.monotonic", return_value=61),
        ):
            runner.resample_legitimate(
                client, probes, [], "example", "example", {"started": 0, "attempts": 0}
            )
        send.assert_not_called()
        self.assertEqual(probes, original)


class RateSampleEvidence(unittest.TestCase):
    def test_successful_burst_uses_exact_echo_without_inventing_access(self):
        with tempfile.TemporaryDirectory() as directory:
            client = Mock()
            client.walkthrough_directory = Path(directory)
            probe = {
                "host": "before.example.test",
                "path": "/httpbin/anything/rate-limit",
                "request_target": "/httpbin/anything/rate-limit",
                "method": "GET",
                "user": "showcase-" + "a" * 32 + "-burst",
                "sent_at": 100.0,
                "received_at": 100.2,
                "status": 200,
                "control": "rate-limit",
                "label": "burst",
                "body": {
                    "url": "http://before.example.test/httpbin/anything/rate-limit",
                    "headers": {"X-Mud-User": "showcase-" + "a" * 32 + "-burst"},
                },
            }
            with (
                patch("showcase_walkthrough_evidence.access_pages", return_value=[]),
                patch.object(client, "pages", return_value=[]),
            ):
                records, events = __import__("showcase_walkthrough_evidence").collect(
                    client, "example", "example", [probe]
                )
            self.assertEqual(records, [])
            self.assertEqual(events, [])
            bad = {
                **probe,
                "body": {"url": "http://wrong.example.test/", "headers": {}},
            }
            with (
                patch("showcase_walkthrough_evidence.access_pages", return_value=[]),
                patch.object(client, "pages", return_value=[]),
                self.assertRaises(EvidenceError),
            ):
                __import__("showcase_walkthrough_evidence").collect(
                    client, "example", "example", [bad]
                )

    def test_denials_bind_separately_from_sampled_successful_burst(self):
        first = probe()
        first.update(
            status=429,
            control="rate-limit",
            label="burst",
            received_at=first["sent_at"] + 0.1,
        )
        second = {
            **first,
            "sent_at": first["sent_at"] + 1.5,
            "received_at": first["sent_at"] + 1.6,
        }
        success = {
            **first,
            "status": 200,
            "sent_at": first["sent_at"] + 0.5,
            "received_at": first["sent_at"] + 0.6,
        }
        row = event()
        row.update(
            req_id="first-denial", rsp_code="429", time="1970-01-01T00:01:40.050Z"
        )
        other = {**row, "req_id": "second-denial", "time": "1970-01-01T00:01:41.550Z"}
        namespace, lb = (
            row["namespace"],
            row["vh_name"].removeprefix("ves-io-http-loadbalancer-"),
        )
        bind_ordered_requests([row, other], [first, success, second], namespace, lb)
        self.assertEqual(first.get("server_request_id"), "first-denial")
        self.assertEqual(second.get("server_request_id"), "second-denial")
        self.assertIsNone(success.get("server_request_id"))
        missing_first, missing_second = (
            {k: v for k, v in first.items() if k != "server_request_id"},
            {k: v for k, v in second.items() if k != "server_request_id"},
        )
        bind_ordered_requests(
            [row], [missing_first, success, missing_second], namespace, lb
        )
        self.assertIsNone(missing_first.get("server_request_id"))
        self.assertIsNone(missing_second.get("server_request_id"))


class LogPages(unittest.TestCase):
    def client(self, pages):
        class Pages:
            def api(self, _path, _payload=None):
                return 200, pages.pop(0)

        return Pages()

    def test_complete_pages(self):
        pages = [
            {"logs": ['{"req_id":"a"}'], "total_hits": "2", "scroll_id": "next"},
            {"logs": ['{"req_id":"b"}'], "total_hits": "2", "scroll_id": ""},
        ]
        self.assertEqual(
            len(access_pages(self.client(pages), "synthetic", "synthetic", 1, 2)), 2
        )

    def test_incomplete_changed_repeated_and_timeout(self):
        for pages in [
            [{"logs": ["{}"], "total_hits": "2", "scroll_id": ""}],
            [
                {"logs": ["{}"], "total_hits": "2", "scroll_id": "next"},
                {"logs": ["{}"], "total_hits": "3", "scroll_id": "other"},
            ],
            [
                {"logs": ["{}"], "total_hits": "3", "scroll_id": "next"},
                {"logs": ["{}"], "total_hits": "3", "scroll_id": "other"},
            ],
        ]:
            with self.subTest(pages=pages), self.assertRaises(EvidenceError):
                access_pages(self.client(pages), "synthetic", "synthetic", 1, 2)
        client = self.client([])
        with (
            patch.object(client, "api", side_effect=EvidenceError("deadline")),
            self.assertRaises(EvidenceError),
        ):
            access_pages(client, "synthetic", "synthetic", 1, 2)


class Attribution(unittest.TestCase):
    def test_exact_join_sampling_ambiguity_and_wrong_request_id(self):
        p = probe()
        p.update(status=403, received_at=p["sent_at"] + 2)
        e = event()
        e.update(req_id="synthetic-request", rsp_code="403", sample_rate=1)
        record = matched([e], p, "waap-test", "webapp-api-protection")
        # Use fixture scope directly; altered fields must never create a match.
        namespace, lb = (
            e["namespace"],
            e["vh_name"].removeprefix("ves-io-http-loadbalancer-"),
        )
        record = matched([e], p, namespace, lb)
        self.assertIsNotNone(record)
        for key, value in [
            ("method", "DELETE"),
            ("user", "different"),
            ("domain", "example.com"),
            ("req_path", "/different"),
            ("rsp_code", "200"),
        ]:
            bad = {**e, key: value}
            self.assertIsNone(matched([bad], p, namespace, lb))
        self.assertIsNone(matched([e, {**e, "req_id": "second"}], p, namespace, lb))
        self.assertFalse(blocked([{**e, "req_id": "wrong"}], e, p, namespace, lb))


class RequestFailures(unittest.TestCase):
    def test_request_timeout_preserves_completed_request_journal(self):
        with tempfile.TemporaryDirectory() as directory:
            client = Mock(spec=["request", "walkthrough_directory"])
            client.walkthrough_directory = Path(directory)
            client.request.side_effect = [
                (200, {"synthetic": True}),
                EvidenceError("timeout"),
            ]
            runner.send(
                client, "www.example.test", "/httpbin/get", "GET", "benign-" + "a" * 32
            )
            with self.assertRaises(EvidenceError):
                runner.send(
                    client,
                    "www.example.test",
                    "/httpbin/get",
                    "GET",
                    "benign-" + "b" * 32,
                )
            self.assertEqual(
                len((Path(directory) / "requests.jsonl").read_text().splitlines()), 1
            )

    def test_signal_enters_failure_path(self):
        with self.assertRaises(EvidenceError):
            runner.interrupted(15, None)

    def test_schema_missing_and_type_are_distinct(self):
        base = {
            "req_id": "synthetic",
            "sec_event_name": "OpenAPI Validation Failure",
            "oas_req_status": "OpenAPIViolation",
            "action": "report",
            "violations": [
                {
                    "field": "demo_id",
                    "context": "Request",
                    "property": "HTTP Body",
                    "description": "value must be a string",
                }
            ],
        }
        self.assertTrue(schema_report([base], {"req_id": "synthetic"}, "type"))
        self.assertFalse(schema_report([base], {"req_id": "synthetic"}, "missing"))
        self.assertFalse(
            schema_report(
                [{**base, "action": "block"}], {"req_id": "synthetic"}, "type"
            )
        )


class PhaseScopeTests(unittest.TestCase):
    def test_rate_requests_are_spaced_and_keep_one_limiter_identity(self):
        client = Mock(spec=["request"])

        def reply(host, path, method, user, body=None):
            return 200, {
                "url": "http://" + host + path,
                "headers": {"X-Mud-User": user},
            }

        client.request.side_effect = reply
        with patch.object(runner.time, "sleep") as sleep:
            probes = runner.requests(
                client, "rate.example.test", "rate-limit", "synthetic", False
            )
        burst = [probe for probe in probes if probe["label"] == "burst"]
        self.assertEqual(len(burst), runner.RATE_BURST_REQUESTS)
        self.assertEqual(len({probe["user"] for probe in burst}), 1)
        self.assertEqual(
            {probe["path"] for probe in burst}, {"/httpbin/anything/rate-limit"}
        )
        self.assertEqual(sleep.call_count, runner.RATE_BURST_REQUESTS)
        self.assertTrue(
            all(
                call.args == (runner.RATE_BURST_SPACING,)
                for call in sleep.call_args_list
            )
        )

    def test_mud_rejects_ambiguous_200_before_detection_polling(self):
        client = Mock(spec=["request"])
        client.request.return_value = (200, {})
        with self.assertRaisesRegex(EvidenceError, "explicit WAF enforcement"):
            runner.requests(client, "mud.example.test", "mud", "synthetic", True)

    def test_endpoint_get_stays_allowed_on_exact_admin_path(self):
        client = Mock(spec=["request"])

        def reply(host, path, method, user, body=None):
            if method in ("POST", "DELETE"):
                return 403, {}
            return 200, {
                "url": "http://" + host + path,
                "headers": {"X-Mud-User": user},
                "json": body,
            }

        client.request.side_effect = reply
        result = runner.requests(
            client, "after.example.test", "endpoint-denial", "synthetic", True
        )
        admin_get = next(probe for probe in result if probe["label"] == "admin-get")
        self.assertEqual(admin_get["path"], "/httpbin/anything/admin")
        self.assertEqual(admin_get["method"], "GET")
        self.assertEqual(admin_get["status"], 200)
        self.assertEqual(admin_get["control"], "")

    def test_waf_preparation_retains_each_declared_host_session(self):
        sessions = {"before.example.test": "a" * 16, "after.example.test": "b" * 16}
        client = Mock()
        client.ssh.side_effect = [
            "/opt/traffic-generator/fixtures.json",
            __import__("json").dumps({"dvwa_sessions": sessions}),
        ]
        args = Mock(category="waf")
        configuration = Mock()
        out = {
            "generator": {},
            "domains": ["www.example.test"],
            "loadbalancer_name": "example",
        }
        selected, _ = runner.prepare_category(
            client, args, out, configuration, "/api/config/", "/api/config/lb"
        )
        self.assertEqual(selected, sessions)

    def test_schema_legitimate_get_is_not_checked_as_json_post(self):
        client = Mock(spec=["request"])

        def reply(host, path, method, user, body=None):
            return 200, {
                "url": "http://" + host + path,
                "headers": {"X-Mud-User": user},
                "json": body,
            }

        client.request.side_effect = reply
        result = runner.requests(
            client,
            "www.example.test",
            "schema",
            "showcase-" + "a" * 32 + "-before",
            False,
        )
        self.assertEqual(result[-1]["path"], "/httpbin/get")
        self.assertEqual(len(result), 4)


class FreshGuestFixtures(unittest.TestCase):
    def test_waf_exports_declared_fixtures_after_stop_before_preparation(self):
        """A stopped rebuilt guest has no export until the ownership helper runs."""
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            (state / "outputs.json").write_text(
                '{"use_cases":{"value":{"waf":{"before":{},"after":{}}}}}'
            )
            lifecycle = Mock()
            lifecycle.context.paths.state = state
            lifecycle.context.paths.key = state / "key"
            lifecycle.context.paths.known_hosts = state / "known_hosts"
            client = Mock()
            client.command.return_value = "synthetic-source"
            client.ssh.side_effect = [
                '{"source_commit":"synthetic-origin"}',
                '{"source_commit":"synthetic-generator"}',
                '{"service_active":false}',
            ]
            configuration = Mock()
            configuration.original = {}
            events: list[str] = []
            lifecycle.ownership.traffic.side_effect = events.append

            def fixtures():
                events.append("fixtures")

            lifecycle.ownership.catalog_fixtures.side_effect = fixtures

            def preparation(*_args):
                events.append("prepare")
                message = "synthetic stop after fixture preparation"
                raise EvidenceError(message)

            out = {
                "origin": {},
                "generator": {},
                "namespace": "example",
                "loadbalancer_name": "synthetic",
                "domains": ["synthetic.example.test"],
            }
            args = Mock(category="waf", timeout_seconds=1800)
            with (
                patch.object(runner, "Lifecycle", return_value=lifecycle),
                patch.object(runner, "outputs", return_value=out),
                patch.object(runner, "Client", return_value=client),
                patch.object(runner, "Configuration", return_value=configuration),
                patch.object(runner, "effective"),
                patch.object(runner, "readiness", return_value={}),
                patch.object(runner, "prepare_category", side_effect=preparation),
                patch.object(
                    runner,
                    "send",
                    return_value={
                        "status": 200,
                        "body": {},
                        "host": "synthetic.example.test",
                        "path": "/httpbin/get",
                        "user": "synthetic",
                    },
                ),
                patch.object(runner, "rate_origin"),
            ):
                self.assertEqual(runner.run(args), 2)
            self.assertEqual(events, ["stop", "fixtures", "prepare", "start"])
            receipt = next(state.glob("walkthrough-*/receipt.json"))
            report = __import__("json").loads(receipt.read_text())
            self.assertFalse(report["complete"])
            self.assertTrue(report["restored"])
            self.assertTrue(report["traffic_restarted"])


class ReplacementEnvelopeTests(unittest.TestCase):
    def test_outer_version_used_when_replacement_version_is_empty(self):
        with tempfile.TemporaryDirectory() as directory:
            client = Mock()
            client.api.return_value = (
                200,
                {
                    "resource_version": "27",
                    "replace_form": {
                        "metadata": {"name": "synthetic"},
                        "spec": {"blocking": {}},
                        "resource_version": "",
                    },
                },
            )
            config = Configuration(client, Path(directory))
            self.assertEqual(
                config.read("/api/config/synthetic")["resource_version"], "27"
            )
            client.api.return_value[1]["resource_version"] = ""
            with self.assertRaises(EvidenceError):
                config.read("/api/config/synthetic")


class MinimumLogWindowTests(unittest.TestCase):
    def test_short_phase_queries_minimum_window_without_widening_request_join(self):
        client = Mock()
        client.api.return_value = (
            200,
            {"logs": [], "total_hits": "0", "scroll_id": ""},
        )
        access_pages(client, "synthetic", "synthetic", 100.1, 100.3)
        query = client.api.call_args.args[1]
        self.assertGreaterEqual(int(query["end_time"]) - int(query["start_time"]), 10)


class RetainedScrollTokenTests(unittest.TestCase):
    def test_same_token_with_distinct_pages_completes(self):
        client = Mock()
        client.api.side_effect = [
            (
                200,
                {
                    "logs": ['{"req_id":"a"}'],
                    "total_hits": "3",
                    "scroll_id": "retained",
                },
            ),
            (
                200,
                {
                    "logs": ['{"req_id":"b"}'],
                    "total_hits": "3",
                    "scroll_id": "retained",
                },
            ),
            (
                200,
                {
                    "logs": ['{"req_id":"c"}'],
                    "total_hits": "3",
                    "scroll_id": "retained",
                },
            ),
        ]
        self.assertEqual(
            len(access_pages(client, "synthetic", "synthetic", 100, 120)), 3
        )


class CalibratedClockTests(unittest.TestCase):
    def test_measured_bounds_required_and_stale_time_rejected(self):
        p = probe()
        p.update(
            status=403, received_at=100.2, clock_offset_min=0.8, clock_offset_max=1.2
        )
        e = event()
        e.update(req_id="synthetic-clock", rsp_code="403", sample_rate=1)
        namespace, lb = (
            e["namespace"],
            e["vh_name"].removeprefix("ves-io-http-loadbalancer-"),
        )
        self.assertIsNotNone(matched([e], p, namespace, lb))
        self.assertTrue(blocked([e], e, p, namespace, lb))
        self.assertIsNone(
            matched([{**e, "time": "1970-01-01T00:01:45Z"}], p, namespace, lb)
        )
        p.pop("clock_offset_min")
        p.pop("clock_offset_max")
        self.assertIsNone(matched([e], p, namespace, lb))


class ObservedSchemaTextTests(unittest.TestCase):
    def test_missing_message_is_required_field_evidence(self):
        event = {
            "req_id": "synthetic",
            "sec_event_name": "OpenAPI Validation Failure",
            "oas_req_status": "OpenAPIViolation",
            "action": "allow",
            "violations": [
                {
                    "field": "demo_id",
                    "context": "Request",
                    "property": "HTTP Body",
                    "description": 'property "demo_id" is missing',
                }
            ],
        }
        self.assertTrue(schema_report([event], {"req_id": "synthetic"}, "missing"))
        self.assertFalse(schema_report([event], {"req_id": "synthetic"}, "type"))


class OrderedBurstTests(unittest.TestCase):
    def test_full_sequential_group_binds_distinct_server_ids(self):
        p = probe()
        p.update(status=403, received_at=101, clock_offset_min=0, clock_offset_max=2)
        second = {**p, "sent_at": 100.5, "received_at": 101.5}
        first = event()
        first.update(req_id="first", rsp_code="403", sample_rate=1)
        last = {**first, "req_id": "second", "time": "1970-01-01T00:01:42Z"}
        ns, lb = (
            first["namespace"],
            first["vh_name"].removeprefix("ves-io-http-loadbalancer-"),
        )
        requests = [p, second]
        bind_ordered_requests([first, last], requests, ns, lb)
        self.assertEqual(
            [r["server_request_id"] for r in requests], ["first", "second"]
        )
        self.assertEqual((matched([first, last], p, ns, lb) or {})["req_id"], "first")
        missing = [
            {k: v for k, v in r.items() if k != "server_request_id"} for r in requests
        ]
        bind_ordered_requests([first], missing, ns, lb)
        self.assertTrue(all("server_request_id" not in r for r in missing))


class XssAttributionTests(unittest.TestCase):
    def test_xss_signature_is_distinct_from_sql_signature(self):
        p = probe()
        p.update(label="xss", received_at=102, status=403)
        e = event()
        e.update(
            req_id="synthetic-xss", signatures=[{"id": "200000098", "state": "Enabled"}]
        )
        ns, lb = e["namespace"], e["vh_name"].removeprefix("ves-io-http-loadbalancer-")
        self.assertTrue(blocked([e], e, p, ns, lb))
        self.assertFalse(
            blocked(
                [{**e, "signatures": [{"id": "200002883", "state": "Enabled"}]}],
                e,
                p,
                ns,
                lb,
            )
        )
