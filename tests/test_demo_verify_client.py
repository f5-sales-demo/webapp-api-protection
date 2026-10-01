"""Synthetic verifier checks; not live security acceptance proof."""

from __future__ import annotations

import json
import sys
import time
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

from tests import demo_verify_fixtures as fixtures
from tests.demo_test_support import ensure, ensure_equal, expect_error

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
import demo_verify_client as transport
import demo_verify_evidence as evaluation
import demo_verify_types as contracts

USER = fixtures.USER
DOMAINS = fixtures.DOMAINS


class ScopedTransportTests(unittest.TestCase):
    def test_exact_event_query_uses_local_user_join(self):
        client = fixtures.client()
        client.api = Mock(return_value=(200, {"events": [], "total_hits": "0"}))
        client.pages("demo", "demo-lb", 100, 110, user=USER)
        ensure_equal(
            client.api.call_args.args[1]["query"],
            '{vh_name="ves-io-http-loadbalancer-demo-lb"}',
        )

    def test_full_count_with_live_scroll_token_is_complete(self):
        client = fixtures.client()
        client.api = Mock(
            return_value=(
                200,
                {
                    "events": [json.dumps(fixtures.event())],
                    "total_hits": "1",
                    "scroll_id": "retained",
                },
            )
        )
        ensure_equal(client.pages("demo", "demo-lb", 100, 110), [fixtures.event()])
        ensure_equal(client.api.call_count, 1)

    def test_object_wire_item_is_not_legacy_success(self):
        client = fixtures.client()
        client.api = Mock(
            return_value=(200, {"events": [fixtures.event()], "total_hits": "1"})
        )
        with expect_error(contracts.EvidenceError):
            client.pages("demo", "demo-lb", 100, 110)

    def test_pagination_complete(self):
        client = fixtures.client()
        client.api = Mock(
            side_effect=[
                (
                    200,
                    {
                        "events": [json.dumps(fixtures.event())],
                        "total_hits": "2",
                        "scroll_id": "one",
                    },
                ),
                (
                    200,
                    {
                        "events": [json.dumps(fixtures.event())],
                        "total_hits": "2",
                        "scroll_id": "",
                    },
                ),
            ]
        )
        ensure_equal(len(client.pages("demo", "demo-lb", 100, 110)), 2)

    def test_truncated_malformed_repeated_and_unavailable_pages(self):
        malformed_pages: tuple[list[tuple[int, dict[str, Any]]], ...] = (
            [(200, {"events": [], "total_hits": "1"})],
            [(200, {"events": {}, "total_hits": "0"})],
            [(200, {"events": [], "total_hits": "0", "truncated": True})],
            [(200, {"events": []})],
            [(404, {})],
            [
                (
                    200,
                    {
                        "events": [fixtures.event()],
                        "total_hits": "3",
                        "scroll_id": "same",
                    },
                )
            ]
            * 2,
        )
        for pages in malformed_pages:
            client = fixtures.client()
            client.api = Mock(side_effect=pages)
            with expect_error(contracts.EvidenceError):
                client.pages("demo", "demo-lb", 100, 110)

    def test_commands_fail_closed(self):
        client = fixtures.client()
        with (
            patch.object(
                transport.subprocess,
                "run",
                return_value=Mock(returncode=1, stdout=b"SECRET"),
            ),
            expect_error(contracts.EvidenceError) as error,
        ):
            client.command(["false"])
        ensure("SECRET" not in str(error.exception))

    def test_suspicious_logs_pagination_requires_complete_envelope(self):
        client = fixtures.client()
        client.api = Mock(
            side_effect=[
                (200, {"logs": ["opaque"], "total_hits": "2", "scroll_id": "first"}),
                (200, {"logs": ["opaque"], "total_hits": "2", "scroll_id": ""}),
            ]
        )
        user = "mud-" + "a" * 32
        ensure_equal(
            client.pages("demo", "demo-lb", 100, 110, True, user), ["opaque", "opaque"]
        )
        ensure(
            'user="' + evaluation.identified_user(user) + '"'
            in client.api.call_args_list[0].args[1]["query"]
        )
        client.api = Mock(return_value=(200, {"logs": [], "total_hits": "1"}))
        with expect_error(contracts.EvidenceError):
            client.pages("demo", "demo-lb", 100, 110, True, user)

    def test_azure_rest_exact_status_and_redaction(self):
        sub = "11111111-1111-1111-1111-111111111111"
        rid = f"/subscriptions/{sub}/resourceGroups/demo"
        client = fixtures.client()
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
            with patch.object(
                transport.subprocess, "run", return_value=result
            ) as command:
                if status == 404:
                    ensure(not client.azure_exists(sub, rid, "2021-04-01"))
                else:
                    with expect_error(contracts.EvidenceError) as error:
                        client.azure_exists(sub, rid, "2021-04-01")
                    ensure("SECRET" not in str(error.exception))
                argv = command.call_args.args[0]
                ensure_equal(argv[:4], ["az", "rest", "--method", "get"])
                ensure("get-access-token" not in argv)
                ensure(
                    "https://management.azure.com" + rid + "?api-version=2021-04-01"
                    in argv
                )
        result = Mock(returncode=1, stdout=b"", stderr=b"ERROR: ResourceNotFound")
        with (
            patch.object(transport.subprocess, "run", return_value=result),
            expect_error(contracts.EvidenceError),
        ):
            client.azure_exists(sub, rid, "2021-04-01")
        result = Mock(returncode=0, stdout=json.dumps({"id": rid}).encode(), stderr=b"")
        with patch.object(transport.subprocess, "run", return_value=result):
            ensure(bool(client.azure_exists(sub, rid, "2021-04-01")))
        result.stdout = b'{"id":"other"}'
        with (
            patch.object(transport.subprocess, "run", return_value=result),
            expect_error(contracts.EvidenceError),
        ):
            client.azure_exists(sub, rid, "2021-04-01")

    def test_azure_transient_retry_requires_fresh_typed_absence(self):
        sub = "11111111-1111-1111-1111-111111111111"
        rid = f"/subscriptions/{sub}/resourceGroups/demo"
        absent = Mock(
            returncode=1,
            stdout=b"",
            stderr=(
                b'INFO: Response status: 404\nERROR: Not Found({"error":'
                b'{"code":"ResourceGroupNotFound","message":"gone"}})'
            ),
        )
        for reason, transient in (
            ("timeout", transport.subprocess.TimeoutExpired("SECRET", 20)),
            (
                "transport",
                Mock(
                    returncode=1,
                    stdout=b"",
                    stderr=b"ERROR: requests.exceptions.ConnectionError: SECRET",
                ),
            ),
            (
                "http-429",
                Mock(
                    returncode=1,
                    stdout=b"",
                    stderr=b"INFO: Response status: 429\nERROR: SECRET",
                ),
            ),
            (
                "http-503",
                Mock(
                    returncode=1,
                    stdout=b"",
                    stderr=b"INFO: Response status: 503\nERROR: SECRET",
                ),
            ),
        ):
            with self.subTest(reason=reason):
                client = fixtures.client()
                client.deadline = time.monotonic() + 60
                with (
                    patch.object(
                        transport.subprocess, "run", side_effect=[transient, absent]
                    ) as command,
                    patch.object(transport.time, "sleep") as sleep,
                ):
                    # No absence is returned by the transient attempt: only the
                    # second, typed ARM response can establish it.
                    sleep.side_effect = lambda _seconds, client=client, reason=reason: (
                        ensure_equal(
                            client.read_retries, [{"reason": reason, "attempt": 1}]
                        )
                    )
                    ensure(not client.azure_exists(sub, rid, "2021-04-01"))
                    ensure_equal(command.call_count, 2)
                    ensure_equal(
                        command.call_args_list[0].args, command.call_args_list[1].args
                    )
                    ensure(
                        bool(
                            all(
                                0 < call.kwargs["timeout"] <= 20
                                for call in command.call_args_list
                            )
                        )
                    )
                    sleep.assert_called_once_with(1)
                ensure_equal(client.read_retries, [{"reason": reason, "attempt": 1}])

    def test_azure_repeated_timeout_and_deadline_fail_closed(self):
        sub = "11111111-1111-1111-1111-111111111111"
        rid = f"/subscriptions/{sub}/resourceGroups/demo"
        for budget, expected_calls in ((60, 2), (0.5, 1)):
            client = fixtures.client()
            client.deadline = time.monotonic() + budget
            with (
                patch.object(
                    transport.subprocess,
                    "run",
                    side_effect=transport.subprocess.TimeoutExpired("SECRET", 20),
                ) as command,
                patch.object(transport.time, "sleep") as sleep,
                expect_error(contracts.EvidenceError) as error,
            ):
                client.azure_exists(sub, rid, "2021-04-01")
            ensure_equal(command.call_count, expected_calls)
            ensure_equal(sleep.call_count, expected_calls - 1)
            ensure("SECRET" not in str(error.exception))
        client = fixtures.client()
        with (
            patch.object(
                transport.subprocess,
                "run",
                side_effect=transport.subprocess.TimeoutExpired("SECRET", 20),
            ) as command,
            patch.object(
                transport.time,
                "sleep",
                side_effect=lambda _seconds: setattr(client, "deadline", 0),
            ),
            expect_error(contracts.EvidenceError),
        ):
            client.azure_exists(sub, rid, "2021-04-01")
        ensure_equal(command.call_count, 1)

    def test_azure_permanent_failures_never_retry(self):
        sub = "11111111-1111-1111-1111-111111111111"
        rid = f"/subscriptions/{sub}/resourceGroups/demo"
        for failure in (
            FileNotFoundError("SECRET"),
            Mock(
                returncode=1,
                stdout=b"",
                stderr=b"INFO: Response status: 401\nERROR: SECRET",
            ),
            Mock(
                returncode=1,
                stdout=b"",
                stderr=b"INFO: Response status: 403\nERROR: SECRET",
            ),
            Mock(
                returncode=1,
                stdout=b"",
                stderr=b"INFO: Response status: 404\nERROR: SECRET",
            ),
            Mock(
                returncode=1,
                stdout=b"",
                stderr=b'INFO: Response status: 404\nERROR: {"error":{"code":"InvalidApiVersionParameter"}}',
            ),
            Mock(
                returncode=1,
                stdout=b"",
                stderr=b'INFO: Response status: 404\nERROR: {"wrapper":{"error":{"code":"ResourceNotFound"}}}',
            ),
            Mock(
                returncode=1,
                stdout=b"",
                stderr=b'INFO: Response status: 404\nERROR: {invalid{"error":{"code":"ResourceNotFound"}}',
            ),
            Mock(
                returncode=1,
                stdout=b"",
                stderr=b'INFO: Response status: 404\nERROR: {"error":"ResourceNotFound"}',
            ),
            Mock(
                returncode=1,
                stdout=b"",
                stderr=b'INFO: Response status: 404\nERROR: {"error":{"code":"ResourceNotFound","message":42}}',
            ),
            Mock(
                returncode=1,
                stdout=b"",
                stderr=b'INFO: Response status: 404\nERROR: {"error":{"code":"ResourceNotFound","target":"/wrong"}}',
            ),
            Mock(
                returncode=1,
                stdout=b"",
                stderr=b'INFO: Response status: 404\nERROR: {"error":{"code":"ResourceNotFound","message":"/subscriptions/other/resourceGroups/other"}}',
            ),
            Mock(returncode=0, stdout=b"[]", stderr=b""),
            Mock(returncode=0, stdout=b"invalid", stderr=b""),
            Mock(returncode=0, stdout=b'{"id":42}', stderr=b""),
        ):
            client = fixtures.client()
            with (
                patch.object(
                    transport.subprocess, "run", side_effect=[failure]
                ) as command,
                patch.object(transport.time, "sleep") as sleep,
                expect_error(contracts.EvidenceError) as error,
            ):
                client.azure_exists(sub, rid, "2021-04-01")
            ensure_equal(command.call_count, 1)
            sleep.assert_not_called()
            ensure_equal(client.read_retries, [])
            ensure("SECRET" not in str(error.exception))

    def test_azure_transient_then_present_never_means_absent(self):
        sub = "11111111-1111-1111-1111-111111111111"
        rid = f"/subscriptions/{sub}/resourceGroups/demo"
        client = fixtures.client()
        with (
            patch.object(
                transport.subprocess,
                "run",
                side_effect=[
                    transport.subprocess.TimeoutExpired("az", 20),
                    Mock(
                        returncode=0,
                        stdout=json.dumps({"id": rid}).encode(),
                        stderr=b"",
                    ),
                ],
            ),
            patch.object(transport.time, "sleep"),
        ):
            ensure(bool(client.azure_exists(sub, rid, "2021-04-01")))

    def test_phase_command_budget_and_process_group_cleanup(self):
        client = fixtures.client()
        client.deadline = time.monotonic() + 100
        ensure(client.remaining() <= 20)
        ensure(client.remaining(phase_budget=True) > 20)
        ensure_equal(
            client.command([sys.executable, "-c", "print('ready')"], phase_budget=True),
            "ready\n",
        )
        client.deadline = time.monotonic() + 0.1
        with expect_error(contracts.EvidenceError):
            client.command(
                [sys.executable, "-c", "import time; time.sleep(30)"], phase_budget=True
            )
