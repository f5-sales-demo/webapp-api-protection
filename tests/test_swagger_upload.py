"""Offline failure-path tests; these do not constitute live XC security proof."""

import base64
import fcntl
import http.client
import json
import re
import socket
import tempfile
import unittest
import urllib.error
from collections.abc import Iterator
from contextlib import contextmanager
from email.message import Message
from pathlib import Path
from typing import Any
from unittest.mock import patch

from scripts import swagger_upload as s

TEXT = json.dumps(
    {
        "openapi": "3.0.0",
        "info": {"title": "demo", "version": "1"},
        "paths": {"/httpbin/post": {}},
    }
)
BASE = "https://tenant.example"
PREFIX = "/api/object_store/namespaces/demo/stored_objects/swagger"
PIN = PREFIX + "/spec/v1-26-09-30"


def check(condition: object) -> None:
    """Fail explicitly, including under optimized Python execution."""
    if not condition:
        msg = "test expectation failed"
        raise AssertionError(msg)


@contextmanager
def raises(exception: type[Exception], *, match: str | None = None) -> Iterator[None]:
    """Require the exception type and optional diagnostic without pytest."""
    try:
        yield
    except exception as exc:
        if match is not None:
            check(re.search(match, str(exc)) is not None)
    else:
        msg = f"expected {exception.__name__}"
        raise AssertionError(msg)


def meta(pinned: str = "v1-26-09-30", **extra: Any) -> dict[str, Any]:
    return {"name": "spec", "namespace": "demo", "version": pinned, **extra}


def versions(*values: str) -> dict[str, Any]:
    return (
        {
            "items": [
                {
                    "name": "demo/spec",
                    "versions": [{"version": value} for value in values],
                }
            ]
        }
        if values
        else {"items": []}
    )


def content(text: str = TEXT, pinned: str = "v1-26-09-30") -> dict[str, Any]:
    return {"metadata": meta(pinned), "string_value": text}


class FakeClient:
    base = BASE

    def __init__(self, *responses: dict[str, Any] | Exception) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, str, dict[str, Any] | None]] = []

    def request(
        self, method: str, path: str, body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        self.calls.append((method, path, body))
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    def remaining(self) -> float:
        return 30


@contextmanager
def temporary_directory() -> Iterator[str]:
    """Keep a fixture directory alive until unittest cleanup executes."""
    with tempfile.TemporaryDirectory() as directory:
        yield directory


class UploadTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = self.enterContext(temporary_directory())
        self.receipt = Path(directory) / "receipt.json"

    def run_upload(self, client: s.UploadClient) -> str:
        return s.upload(client, "spec", "demo", TEXT, self.receipt)

    def test_valid_supported_documents_preserve_exact_bytes(self) -> None:
        for v in ("3.0.0", "3.1.1"):
            text = TEXT.replace("3.0.0", v) + "\n"
            check(s.validate_content(text.encode(), ".json") == text)
        swagger = json.loads(TEXT)
        del swagger["openapi"]
        swagger["swagger"] = "2.0"
        s.validate_content(json.dumps(swagger).encode(), ".json")

    def test_invalid_content(self) -> None:
        for raw in (
            b"",
            b"\xff",
            b"{}",
            b"[]",
            b"{",
            b"x" * (s.MAX_CONTENT + 1),
            b'{"openapi":"3.0.0","openapi":"3.1.0"}',
            TEXT.replace('"demo"', "NaN").encode(),
            TEXT.replace('"/httpbin/post"', '"relative"').encode(),
        ):
            with self.subTest(raw=raw[:30]), raises(s.UploadError):
                s.validate_content(raw, ".json")
        with raises(s.UploadError, match="YAML"):
            s.validate_content(TEXT.encode(), ".yaml")

    def test_labels_versions_and_url_validation(self) -> None:
        for value in ("Bad", "-bad", "bad-", "$(touch /tmp/no)", "a" * 64, "../spec"):
            with raises(s.UploadError):
                s.label(value)
        for pinned in ("latest", "../1", "v1?token=x", "v1/x", None):
            with raises(s.UploadError):
                s.version(pinned)
        for url in (
            "http://tenant.example",
            "https://user:pass@tenant.example",
            "https://tenant.example/path",
            "https://tenant.example?token=x",
            "https://tenant.example\n",
        ):
            with raises(s.UploadError):
                s.api_base(url)
        check(s.api_base(BASE + "/") == BASE)

    def test_upload_metadata_pin_and_receipt_reuse(self) -> None:
        client = FakeClient(
            versions(), {"metadata": meta(), "status": "active"}, content()
        )
        check(self.run_upload(client) == PIN)
        check([c[0] for c in client.calls] == ["GET", "PUT", "GET"])
        check(
            "name=spec&query_type=EXACT_MATCH&latest_version_only=false"
            in client.calls[0][1]
        )
        put_body = client.calls[1][2]
        check(put_body is not None and put_body["string_value"] == TEXT)
        check(self.receipt.stat().st_mode & 0o777 == 0o600)
        saved = json.loads(self.receipt.read_text())
        check(saved["path"] == PIN)
        check(saved["content"] == TEXT)
        second = FakeClient(content())
        check(self.run_upload(second) == PIN)
        check([c[0] for c in second.calls] == ["GET"])

    def test_live_already_exists_response_pins_metadata(self) -> None:
        # Allowlisted fields observed on our authenticated fixture PUT.
        response = {
            "metadata": meta(),
            "status": "STORED_OBJECT_STATUS_ALREADY_EXISTS",
        }
        client = FakeClient(versions(), response, content())
        check(self.run_upload(client) == PIN)
        check(client.calls[-1][1] == PIN)

    def test_existing_exact_fixture_reuses_without_put(self) -> None:
        client = FakeClient(versions("v1-26-09-30"), content(), versions("v1-26-09-30"))
        check(self.run_upload(client) == PIN)
        check([call[0] for call in client.calls] == ["GET"] * 3)

    def test_existing_different_content_uploads_and_verifies(self) -> None:
        client = FakeClient(
            versions("v0"),
            content(TEXT + " ", "v0"),
            {"metadata": meta(), "status": "created"},
            content(),
        )
        check(self.run_upload(client) == PIN)
        check([call[0] for call in client.calls] == ["GET", "GET", "PUT", "GET"])

    def test_missing_metadata_ambiguity_and_races_fail(self) -> None:
        sequences = [
            [versions(), {}],
            [versions("v1", "v2")],
            [versions("v1-26-09-30"), content(), versions("v1-26-09-30", "v2")],
        ]
        for responses in sequences:
            with self.subTest(responses=responses), raises(s.UploadError):
                self.run_upload(FakeClient(*responses))
            check(not self.receipt.exists())

    def test_malformed_listing_fails_before_put(self) -> None:
        listing: dict[str, Any]
        for listing in (
            {},
            {"items": {}},
            {"items": [{"name": "other", "versions": []}]},
            {"items": [{"name": "spec"}]},
            versions("v1", "v1"),
            {"items": [versions("v1")["items"][0]] * 2},
            versions(*[f"v{i}" for i in range(65)]),
        ):
            client = FakeClient(listing)
            with self.subTest(listing=listing), raises(s.UploadError):
                self.run_upload(client)
            check(len(client.calls) == 1)

    def test_put_failure_status_metadata_and_presigned_fail(self) -> None:
        response: dict[str, Any] | s.UploadError
        for response in (
            s.UploadError("HTTP 500"),
            {"status": "failed"},
            {"status": {}},
            {"metadata": meta(), "status": {"unknown": "value"}},
            {"metadata": meta(), "status": "STORED_OBJECT_STATUS_FAILED"},
            {"metadata": meta(), "status": False},
            {"metadata": meta(), "status": ""},
            {"metadata": meta(), "code": 13},
            {"metadata": meta(), "error": {}},
            {"status": "STORED_OBJECT_STATUS_ALREADY_EXISTS"},
            {"metadata": {}},
            {"metadata": meta(namespace="other")},
            {"presigned_url": {"aws": {"url": "https://third-party.example"}}},
        ):
            with self.subTest(response=response), raises(s.UploadError):
                self.run_upload(FakeClient(versions(), response))
            check(not self.receipt.exists())

    def test_exact_get_content_and_version_failures(self) -> None:
        for result in (
            content(TEXT + " "),
            content(pinned="v2"),
            {},
            {"metadata": meta(), "presigned_url": {}},
            {"metadata": meta(), "bytes_value": "invalid!"},
            {**content(), "bytes_value": "YQ=="},
            s.UploadError("HTTP 503"),
        ):
            with self.subTest(result=result), raises(s.UploadError):
                self.run_upload(FakeClient(versions(), {"metadata": meta()}, result))
            check(not self.receipt.exists())

    def test_base64_exact_readback(self) -> None:
        client = FakeClient(
            versions(),
            {"metadata": meta()},
            {
                "metadata": meta(),
                "bytes_value": base64.b64encode(TEXT.encode()).decode(),
            },
        )
        check(self.run_upload(client) == PIN)

    def test_receipt_mismatch_and_insecure_receipt_fail(self) -> None:
        self.run_upload(FakeClient(versions(), {"metadata": meta()}, content()))
        client = FakeClient()
        with raises(s.UploadError):
            s.upload(client, "spec", "demo", TEXT + "\n", self.receipt)
        check(not client.calls)
        self.receipt.chmod(0o644)
        with raises(s.UploadError):
            self.run_upload(client)

    def test_receipt_lock_blocks_concurrent_upload(self) -> None:
        with Path(str(self.receipt) + ".lock").open("w") as lock:
            Path(lock.name).chmod(0o600)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with raises(s.UploadError, match="another upload"):
                self.run_upload(FakeClient())

    def test_redirect_auth_is_never_forwarded(self) -> None:
        with raises(s.UploadError):
            s.NoRedirect().redirect_request(
                None, None, None, None, None, "https://third-party.example"
            )

    def test_actual_http_response_completion_and_truncation(self) -> None:
        # Local socketpair exercises stdlib EOF semantics, not security acceptance.
        for advertised in (2, 3):
            with self.subTest(length=advertised):
                reader, writer = socket.socketpair()
                self.addCleanup(reader.close)
                self.addCleanup(writer.close)
                writer.sendall(
                    f"HTTP/1.1 200 OK\r\nContent-Length: {advertised}\r\n\r\n{{}}".encode()
                )
                writer.shutdown(socket.SHUT_WR)
                response = http.client.HTTPResponse(reader)
                response.begin()
                client = s.Client(BASE, "test-only", 2)
                with patch.object(client.opener, "open", return_value=response):
                    if advertised == 2:
                        check(client.request("GET", PIN) == {})
                    else:
                        with raises(s.UploadError, match="truncated"):
                            client.request("GET", PIN)

    def test_global_deadline_and_http_failure(self) -> None:
        client = s.Client(BASE, "test-only", 1)
        with (
            patch.object(s.time, "monotonic", return_value=client.deadline + 1),
            raises(s.UploadError, match="deadline"),
        ):
            client.request("GET", PIN)
        with (
            patch.object(
                client.opener,
                "open",
                side_effect=urllib.error.HTTPError(BASE, 403, "no", Message(), None),
            ),
            raises(s.UploadError, match="HTTP 403"),
        ):
            client.request("PUT", PIN, {})

    def test_transient_http_retries_only_get_once(self) -> None:
        for method in ("GET", "PUT"):
            for code in (429, 503):
                client = s.Client(BASE, "test-only", 30)
                failure = urllib.error.HTTPError(BASE, code, "no", Message(), None)
                with (
                    self.subTest(method=method, code=code),
                    patch.object(client.opener, "open", side_effect=failure) as opened,
                    patch.object(s.time, "sleep"),
                    raises(s.UploadError, match=f"HTTP {code}"),
                ):
                    client.request(method, PIN)
                check(opened.call_count == (2 if method == "GET" else 1))

    def test_malformed_http_json_and_read_deadline(self) -> None:
        class Response:
            status = 200

            def __init__(self, raw):
                self.raw = raw
                self.fp = type(
                    "FP",
                    (),
                    {
                        "raw": type(
                            "Raw",
                            (),
                            {
                                "_sock": type(
                                    "Socket",
                                    (),
                                    {"settimeout": lambda _self, _timeout: None},
                                )()
                            },
                        )()
                    },
                )()

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                pass

            def read1(self, _size):
                raw, self.raw = self.raw, b""
                return raw

        for raw in (
            b"invalid",
            b"[]",
            b'{"code":13}',
            b'{"items":[],"items":[]}',
            b"x" * (s.MAX_RESPONSE + 1),
        ):
            client = s.Client(BASE, "test-only", 30)
            with (
                patch.object(client.opener, "open", return_value=Response(raw)),
                raises(s.UploadError),
            ):
                client.request("GET", PIN)
        client = s.Client(BASE, "test-only", 30)
        with (
            patch.object(client.opener, "open", return_value=Response(b"{}")),
            patch.object(
                client, "remaining", side_effect=[30, 30, 30, s.UploadError("deadline")]
            ),
            raises(s.UploadError, match="deadline"),
        ):
            client.request("GET", PIN)


if __name__ == "__main__":
    unittest.main()
