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
from showcase_walkthrough_config import fail
from showcase_walkthrough_evidence import schema_report

from scripts.showcase_walkthrough_config import Configuration, focused
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
        # addCleanup runs even when setup or an assertion fails.
        self.addCleanup(self.temporary.cleanup)
        self.client = FakeClient()
        self.config = Configuration(self.client, Path(self.temporary.name))
        self.config.capture("/api/config/synthetic")
        patcher = patch.object(self.config, "put", side_effect=self.put)
        patcher.start()
        self.addCleanup(patcher.stop)

    def put(self, _path, form):
        self.client.form = copy.deepcopy(form)
        self.client.form["resource_version"] = str(int(form["resource_version"]) + 1)
        if self.client.fail_put:
            self.client.fail_put = False
            fail("timed out after write")

    def test_full_fields_and_competing_choice_preserved(self):
        desired = focused(self.client.form, "waf", False, firewall=True)
        self.config.update("/api/config/synthetic", desired)
        self.assertEqual(self.client.form["spec"]["routing"], {"preserve": "yes"})
        self.assertNotIn("blocking", self.client.form["spec"])
        self.assertIn("monitoring", self.client.form["spec"])
        self.assertTrue(self.config.restore())
        self.assertEqual(
            self.client.form["metadata"]["annotations"], {"preserve": "yes"}
        )
        self.assertIn("blocking", self.client.form["spec"])

    def test_concurrent_change_rejects_update_and_restore(self):
        self.client.form["spec"]["routing"]["preserve"] = "concurrent"
        with self.assertRaises(EvidenceError):
            self.config.update(
                "/api/config/synthetic", self.config.original["/api/config/synthetic"]
            )
        self.assertFalse(self.config.restore())
        self.assertEqual(self.client.form["spec"]["routing"]["preserve"], "concurrent")

    def test_timeout_after_write_restores_with_separate_budget(self):
        self.client.fail_put = True
        with self.assertRaises(EvidenceError):
            self.config.update(
                "/api/config/synthetic",
                focused(self.client.form, "waf", False, firewall=True),
            )
        self.assertTrue(self.config.restore())
        self.assertEqual(self.client.deadline, 0)

    def test_unexpected_readback_does_not_overwrite(self):
        def mutate(_path, form):
            self.client.form = copy.deepcopy(form)
            self.client.form["spec"]["routing"] = {"unexpected": True}

        with (
            patch.object(self.config, "put", side_effect=mutate),
            self.assertRaises(EvidenceError),
        ):
            self.config.update(
                "/api/config/synthetic",
                focused(self.client.form, "waf", False, firewall=True),
            )
        self.assertFalse(self.config.restore())

    def test_restore_failure_is_incomplete(self):
        self.config.update(
            "/api/config/synthetic",
            focused(self.client.form, "waf", False, firewall=True),
        )
        with patch.object(
            self.config, "put", side_effect=EvidenceError("restore failed")
        ):
            self.assertFalse(self.config.restore())


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
            ("sample_rate", 0.5),
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
