"""Operator evidence collection preserves exact request and configured host scope."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from demo_catalog_clock import calibrate_clock
from demo_catalog_evidence import evidence_bundle, grouped_records, identity_records
from demo_lifecycle_fixtures import TEST_SCOPE
from demo_test_support import ensure, ensure_equal, expect_error
from demo_verify_evidence import identified_user, virtual_host
from demo_verify_types import EvidenceError


def data():
    out = {
        "namespace": TEST_SCOPE["namespace"],
        "loadbalancer_name": "webapp-api-protection",
        "domains": ["www.example.test", "api.example.test"],
    }
    row = {
        "scenario": "synthetic/action",
        "domain": "www.example.test",
        "path": "/httpbin/post",
        "method": "POST",
        "synthetic_identity": "showcase-" + "a" * 32 + "-synthetic",
        "status": 403,
        "sent_at": 10,
        "received_at": 11,
    }
    pending = {
        "pass": "pass-" + "a" * 32,
        "request_sha256": "b" * 64,
        "request": {
            "scenario": "synthetic/action",
            "source_commit": "c" * 40,
            "artifact_sha256": "d" * 64,
            "requests": [row],
        },
    }
    event = {
        "req_id": "exact",
        "namespace": TEST_SCOPE["namespace"],
        "vh_name": "ves-io-http-loadbalancer-webapp-api-protection",
        "domain": "www.example.test",
        "req_path": "/httpbin/post",
        "method": "POST",
        "user": "Header-X-Mud-User-showcase-" + "a" * 32 + "-synthetic",
        "rsp_code": "403",
        "time": "1970-01-01T00:00:10.500Z",
    }
    client = Mock()
    client.pages.return_value = [event]
    client.api.return_value = (
        200,
        {"metadata": {"name": "webapp-api-protection-waf"}, "spec": {"blocking": {}}},
    )
    return out, pending, event, client


def test_bundle_requires_exact_access_record_and_preserves_provenance():
    out, pending, event, client = data()
    with patch("demo_catalog_evidence.access_by_user", return_value=[event]):
        result = evidence_bundle(client, pending, out, [-1, 1])
    ensure(result is not None)
    ensure_equal(
        result["evidence"]["checks"][0]["response"], pending["request"]["requests"][0]
    )
    ensure_equal(
        result["evidence"]["source_commit"], pending["request"]["source_commit"]
    )


def test_foreign_request_or_absent_access_never_produces_bundle():
    out, pending, _event, client = data()
    with patch("demo_catalog_evidence.access_by_user", return_value=[]):
        ensure(evidence_bundle(client, pending, out, [-1, 1]) is None)
    pending["request"]["requests"][0]["domain"] = "foreign.example.test"
    with expect_error(EvidenceError, "outside declared scope"):
        evidence_bundle(client, pending, out, [-1, 1])


class CatalogEvidenceTests(unittest.TestCase):
    def test_exact_join(self):
        test_bundle_requires_exact_access_record_and_preserves_provenance()

    def test_scope_and_absence(self):
        test_foreign_request_or_absent_access_never_produces_bundle()


class UniqueCatalogJoins(unittest.TestCase):
    def test_one_server_id_cannot_satisfy_two_requests(self):
        out, pending, event, client = data()
        pending["request"]["requests"] *= 2
        with patch("demo_catalog_evidence.access_by_user", return_value=[event]):
            ensure(evidence_bundle(client, pending, out, [-1, 1]) is None)

    def test_ambiguous_security_time_join_is_rejected(self):
        out, pending, event, client = data()
        second = {**event, "req_id": "other"}
        client.pages.return_value = [event, second]
        with patch(
            "demo_catalog_evidence.access_by_user", return_value=[event, second]
        ):
            ensure(evidence_bundle(client, pending, out, [-1, 1]) is None)


class ClockQueryScope(unittest.TestCase):
    def test_clock_calibration_queries_only_each_fresh_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            self.verify_identity_queries(Path(directory))

    def verify_identity_queries(self, tmp_path):
        client = SimpleNamespace(walkthrough_directory=tmp_path)
        probes = [
            {
                "host": "www.example.com",
                "path": "/httpbin/get",
                "method": "GET",
                "user": "showcase-" + "a" * 32 + "-clock-" + str(i),
                "sent_at": 100.0 + i,
                "received_at": 100.2 + i,
                "status": 200,
                "body": {},
            }
            for i in range(3)
        ]
        out = {
            "domains": ["www.example.com"],
            "namespace": TEST_SCOPE["namespace"],
            "loadbalancer_name": TEST_SCOPE["namespace"],
        }
        calls = []

        def query(_client, namespace, lb, user, _start, _end):
            calls.append(user)
            probe = next(p for p in probes if p["user"] == user)
            return [
                {
                    "user": identified_user(user),
                    "domain": probe["host"],
                    "req_path": probe["path"],
                    "namespace": namespace,
                    "vh_name": virtual_host(lb),
                    "method": "GET",
                    "rsp_code": "200",
                    "time": "1970-01-01T00:01:"
                    + str(41 + probes.index(probe)).zfill(2)
                    + ".000Z",
                }
            ]

        with (
            patch("demo_catalog_clock.clock_probe", side_effect=probes),
            patch("demo_catalog_clock.rate_origin"),
            patch("demo_catalog_clock.access_by_user", side_effect=query),
        ):
            calibrate_clock(client, out, "showcase-test")
        ensure_equal(calls, [p["user"] for p in probes])
        ensure_equal(client.clock_bounds, (-1, 2))


class ParallelIdentityCollection(unittest.TestCase):
    def test_every_identity_keeps_both_exact_query_results(self):
        client = Mock()
        client.pages.side_effect = lambda _namespace, _lb, _start, _end, user: [
            {"user": user, "security": True}
        ]
        with patch(
            "demo_catalog_evidence.access_by_user",
            side_effect=lambda _client, _namespace, _lb, user, _start, _end: [
                {"user": user, "access": True}
            ],
        ):
            records, events = identity_records(
                client,
                TEST_SCOPE["namespace"],
                "synthetic-lb",
                ["first", "second"],
                100,
                110,
            )
        ensure_equal(
            records,
            [{"user": "first", "access": True}, {"user": "second", "access": True}],
        )
        ensure_equal(
            events,
            [{"user": "first", "security": True}, {"user": "second", "security": True}],
        )

    def test_failed_exact_query_cannot_return_partial_evidence(self):
        client = Mock()
        with (
            patch(
                "demo_catalog_evidence.access_by_user",
                side_effect=EvidenceError("failed exact query"),
            ),
            expect_error(EvidenceError, "failed exact query"),
        ):
            identity_records(
                client,
                TEST_SCOPE["namespace"],
                "synthetic-lb",
                ["first", "second"],
                100,
                110,
            )


class GroupedIdentityCollection(unittest.TestCase):
    def test_complete_group_filters_prefix_collisions_and_preserves_ids(self):
        users = [
            "showcase-" + "a" * 32 + "-request",
            "showcase-" + "b" * 32 + "-request",
        ]
        events = [
            {"user": identified_user(user), "req_id": str(i)}
            for i, user in enumerate(users)
        ]
        events.append(
            {"user": identified_user(users[0]) + "-foreign", "req_id": "foreign"}
        )
        client = Mock()
        client.api.return_value = (
            200,
            {"logs": [json.dumps(row) for row in events], "total_hits": 3},
        )
        result = grouped_records(
            client, TEST_SCOPE["namespace"], "synthetic-lb", users, 100, 110, False
        )
        ensure_equal(result, events[:2])
        query = client.api.call_args.args[1]["query"]
        ensure("user=~" in query and "^" not in query and "$" not in query)
