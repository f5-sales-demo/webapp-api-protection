"""Operator evidence collection preserves exact request and configured host scope."""

from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from demo_catalog_evidence import evidence_bundle
from demo_lifecycle_fixtures import TEST_SCOPE
from demo_test_support import ensure, ensure_equal, expect_error
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
