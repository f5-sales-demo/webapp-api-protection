"""Repeatable seeded fixture export is private and fails on missing origin prerequisites."""

import json
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
            patch.object(
                fixtures, "login", side_effect=["video", "otp", "token-a", "token-b"]
            ),
            patch.object(fixtures, "restaurant_fixtures", return_value={}),
            patch.object(fixtures.Path, "is_file", return_value=True),
            patch.object(
                fixtures.Path,
                "stat",
                return_value=__import__("types").SimpleNamespace(st_mode=0o600),
            ),
            patch.object(
                fixtures.Path,
                "read_text",
                return_value='{"dvwa_sessions":{},"dvwa_csrf_sessions":{}}',
            ),
            patch.object(fixtures, "urlopen") as opened,
        ):
            opened.return_value.__enter__.return_value.read.return_value = b'{"auth_token":"synthetic","config":{"application":{"domain":"example.test"}}}'
            result = fixtures.collect()
        assert result["crapi_tokens"] == ["token-a", "token-b"]
        assert result["crapi_order_id"] == 7
        assert result["fixture_type"] == "seeded-synthetic-origin-accounts"

    def test_default_fixture_read_does_not_seed_database(self):
        with patch.object(fixtures.subprocess, "run") as command:
            command.return_value.stdout = json.dumps({"crapi_order_id": 1})
            fixtures.seeded_ids()
        statement = command.call_args.kwargs["input"]
        assert "INSERT" not in statement
        assert "BEGIN" not in statement

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
