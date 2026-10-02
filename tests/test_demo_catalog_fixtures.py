"""Repeatable seeded fixture export is private and fails on missing origin prerequisites."""

import unittest
from unittest.mock import patch

from demo_test_support import expect_error

from scripts import demo_catalog_fixtures as fixtures


class FixtureExportTests(unittest.TestCase):
    def test_export_uses_real_seeded_database_ids_and_origin_issued_tokens(self):
        with (
            patch.object(
                fixtures,
                "seeded_ids",
                return_value={
                    "crapi_vehicle_uuid": "seeded-vehicle",
                    "crapi_video_id": 3,
                    "crapi_order_id": 7,
                },
            ),
            patch.object(fixtures, "login", side_effect=["token-a", "token-b"]),
        ):
            result = fixtures.collect()
        assert result["crapi_tokens"] == ["token-a", "token-b"]
        assert result["crapi_order_id"] == 7
        assert result["fixture_type"] == "seeded-synthetic-origin-accounts"

    def test_missing_fixture_cannot_be_exported_as_ready(self):
        with (
            patch.object(
                fixtures,
                "seeded_ids",
                return_value={
                    "crapi_vehicle_uuid": None,
                    "crapi_video_id": 3,
                    "crapi_order_id": 7,
                },
            ),
            expect_error(ValueError, "missing"),
        ):
            fixtures.collect()
