# ruff: noqa: D101,D102,D103,D107,EM101,EM102,PLR2004,S310,SLF001,TRY003,TRY300,TRY301
"""Pin object-store swagger content to an exact verified version, never latest."""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import http.client
import json
import os
import re
import stat
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, NoReturn

MAX_CONTENT = 5 * 1024 * 1024
MAX_RESPONSE = 32 * 1024 * 1024
MAX_VERSIONS = 64


class UploadError(Exception):
    """Validation or verification failure; no successful path may be emitted."""


class ContentMismatchError(UploadError):
    """An exact version exists but holds different content."""


class HTTPFailureError(UploadError):
    def __init__(self, method: str, status: int) -> None:
        self.status = status
        super().__init__(f"{method} failed (HTTP {status})")


def strict_json(text: str) -> Any:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in values:
            if key in result:
                raise UploadError("duplicate JSON key")
            result[key] = value
        return result

    def constant(_value: str) -> NoReturn:
        raise UploadError("non-finite JSON value")

    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, RecursionError) as exc:
        raise UploadError("malformed JSON") from exc


def label(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 63
        or not re.fullmatch(r"[a-z](?:[-a-z0-9]*[a-z0-9])?", value)
    ):
        raise UploadError(
            "name and namespace must be DNS labels of at most 63 characters"
        )
    return value


def version(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 1024
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", value)
        or value in ("latest", ".", "..")
    ):
        raise UploadError("invalid or unpinned version")
    return value


def api_base(value: str) -> str:
    parts = urllib.parse.urlsplit(value)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
        or any(ord(c) <= 32 or ord(c) == 127 for c in value)
        or not re.fullmatch(r"[A-Za-z0-9.-]+|[A-Fa-f0-9:]+", parts.hostname)
    ):
        raise UploadError(
            "XCSH_API_URL must be an HTTPS tenant base URL without credentials, path or query"
        )
    try:
        _port = parts.port
    except ValueError as exc:
        raise UploadError("invalid tenant URL port") from exc
    return value.rstrip("/")


def validate_content(raw: bytes, suffix: str) -> str:
    if not raw or len(raw) > MAX_CONTENT:
        raise UploadError("document must be nonempty and no larger than 5 MiB")
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise UploadError("document must be UTF-8") from exc
    if suffix.lower() in (".yaml", ".yml"):
        # No implicit dependency installation or lossy JSON conversion.
        raise UploadError(
            "YAML validation is unsupported: provide an OpenAPI JSON document"
        )
    data = strict_json(text)
    if not isinstance(data, dict):
        raise UploadError("document must be an object")
    oas = data.get("openapi")
    if not (
        (
            isinstance(oas, str)
            and re.fullmatch(r"3\.[01]\.\d+", oas)
            and "swagger" not in data
        )
        or (data.get("swagger") == "2.0" and "openapi" not in data)
    ):
        raise UploadError("supported profiles are OpenAPI 3.0/3.1 or Swagger 2.0")
    info = data.get("info")
    if not isinstance(info, dict) or not all(
        isinstance(info.get(k), str) and info[k] for k in ("title", "version")
    ):
        raise UploadError("info.title and info.version are required strings")
    paths = data.get("paths")
    if not isinstance(paths, dict) or not all(
        isinstance(k, str) and k.startswith("/") and isinstance(v, dict)
        for k, v in paths.items()
    ):
        raise UploadError("paths must map absolute API paths to objects")
    return text


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: object, **_kwargs: object) -> NoReturn:
        raise UploadError("redirect refused; tenant authentication never follows URLs")


class Client:
    def __init__(self, base: str, token: str, timeout: float) -> None:
        self.base = api_base(base)
        if not token or any(ord(c) < 32 or ord(c) == 127 for c in token):
            raise UploadError(
                "XCSH_API_TOKEN must be present without control characters"
            )
        if not 0 < timeout <= 3600:
            raise UploadError("timeout must be between 0 and 3600 seconds")
        self.token = token
        self.deadline = time.monotonic() + timeout
        self.opener = urllib.request.build_opener(NoRedirect())

    def remaining(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise UploadError("upload verification deadline exceeded")
        return remaining

    def request(
        self, method: str, path: str, body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        try:
            return self._request_once(method, path, body)
        except HTTPFailureError as exc:
            if method != "GET" or exc.status not in (429, 503):
                raise
            time.sleep(min(1, self.remaining()))
            return self._request_once(method, path, body)

    def _request_once(
        self, method: str, path: str, body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        self.remaining()
        payload = (
            None
            if body is None
            else json.dumps(body, ensure_ascii=False).encode("utf-8")
        )
        req = urllib.request.Request(
            self.base + path,
            data=payload,
            method=method,
            headers={
                "Authorization": "APIToken " + self.token,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with self.opener.open(req, timeout=self.remaining()) as response:
                if response.status != 200:
                    raise HTTPFailureError(method, response.status)
                chunks = []
                size = 0
                while True:
                    if response.fp is None:
                        break
                    # Reapply the total deadline to each socket read, including slow drips.
                    response.fp.raw._sock.settimeout(self.remaining())
                    chunk = response.read1(65536)
                    self.remaining()
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > MAX_RESPONSE:
                        raise UploadError("API response exceeds bounded size")
                    chunks.append(chunk)
                if getattr(response, "length", None) not in (None, 0):
                    raise UploadError("truncated HTTP response")
            data = strict_json(b"".join(chunks).decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise HTTPFailureError(method, exc.code) from None
        except (
            OSError,
            UnicodeError,
            urllib.error.URLError,
            http.client.HTTPException,
        ) as exc:
            raise UploadError(f"{method} transport or UTF-8 failure") from exc
        if not isinstance(data, dict) or "error" in data or "code" in data:
            raise UploadError("malformed or error API response")
        return data


def metadata(
    data: dict[str, Any], name: str, namespace: str, expected: str | None = None
) -> str:
    meta = data.get("metadata")
    if (
        not isinstance(meta, dict)
        or meta.get("name") != name
        or meta.get("namespace") != namespace
    ):
        raise UploadError("response metadata identity mismatch")
    found = version(meta.get("version"))
    if expected is not None and found != expected:
        raise UploadError("response metadata version mismatch")
    return found


def listing(client: Client, prefix: str, name: str, namespace: str) -> set[str]:
    query = urllib.parse.urlencode(
        {"name": name, "query_type": "EXACT_MATCH", "latest_version_only": "false"}
    )
    data = client.request("GET", prefix + "?" + query)
    items = data.get("items")
    if not isinstance(items, list) or len(items) > 1:
        raise UploadError("malformed or ambiguous name-filtered listing")
    if not items:
        return set()
    item = items[0]
    if not isinstance(item, dict) or item.get("name") not in (
        name,
        namespace + "/" + name,
    ):
        raise UploadError("listing object identity mismatch")
    values = item.get("versions")
    if not isinstance(values, list) or not values or len(values) > MAX_VERSIONS:
        raise UploadError("missing or excessive versions in listing")
    result = []
    for value in values:
        if not isinstance(value, dict):
            raise UploadError("malformed listing version")
        result.append(version(value.get("version")))
    if len(set(result)) != len(result):
        raise UploadError("duplicate listing versions")
    return set(result)


def verify(
    client: Client, path: str, name: str, namespace: str, pinned: str, text: str
) -> None:
    data = client.request("GET", path)
    metadata(data, name, namespace, pinned)
    choices = [
        key for key in ("string_value", "bytes_value", "presigned_url") if key in data
    ]
    if choices == ["string_value"] and isinstance(data["string_value"], str):
        raw = data["string_value"].encode("utf-8")
    elif choices == ["bytes_value"] and isinstance(data["bytes_value"], str):
        try:
            raw = base64.b64decode(data["bytes_value"], validate=True)
        except ValueError as exc:
            raise UploadError("invalid base64 readback") from exc
    else:
        raise UploadError(
            "missing, ambiguous or presigned content; external URLs are never followed"
        )
    if (
        len(raw) > MAX_CONTENT
        or hashlib.sha256(raw).hexdigest()
        != hashlib.sha256(text.encode("utf-8")).hexdigest()
    ):
        raise ContentMismatchError("exact-version content SHA-256 mismatch")


def secure_open(path: str | Path, flags: int) -> int:
    fd = os.open(path, flags | os.O_NOFOLLOW, 0o600)
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
    ):
        os.close(fd)
        raise UploadError("receipt and lock must be owned private regular files (0600)")
    return fd


def upload(
    client: Client, name: str, namespace: str, text: str, receipt_path: str | Path
) -> str:
    label(name)
    label(namespace)
    prefix = f"/api/object_store/namespaces/{namespace}/stored_objects/swagger"
    object_path = prefix + "/" + name
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    identity = {
        "schema_version": 1,
        "api_url": client.base,
        "name": name,
        "namespace": namespace,
        "sha256": digest,
        "content": text,
    }
    receipt_path = Path(receipt_path).absolute()
    if not receipt_path.parent.is_dir():
        raise UploadError("receipt parent directory must exist")
    lockfd = secure_open(str(receipt_path) + ".lock", os.O_CREAT | os.O_RDWR)
    try:
        try:
            fcntl.flock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise UploadError("another upload holds the receipt lock") from exc
        if receipt_path.exists() or receipt_path.is_symlink():
            fd = secure_open(receipt_path, os.O_RDONLY)
            with os.fdopen(fd, "rb") as stream:
                raw = stream.read(MAX_RESPONSE + 1)
            if len(raw) > MAX_RESPONSE:
                raise UploadError("receipt exceeds bounded size")
            saved = strict_json(raw.decode("utf-8"))
            if not isinstance(saved, dict) or any(
                saved.get(k) != v for k, v in identity.items()
            ):
                raise UploadError(
                    "receipt identity/content differs; select a separate receipt for changed content"
                )
            pinned = version(saved.get("version"))
            path = object_path + "/" + pinned
            if saved.get("path") != path:
                raise UploadError("receipt path mismatch")
            verify(client, path, name, namespace, pinned, text)
            return path
        before = listing(client, prefix, name, namespace)
        pinned = None
        if before:
            if len(before) != 1:
                raise UploadError(
                    "existing object versions are ambiguous; refusing latest"
                )
            candidate = next(iter(before))
            try:
                verify(
                    client,
                    object_path + "/" + candidate,
                    name,
                    namespace,
                    candidate,
                    text,
                )
            except ContentMismatchError:
                pass
            else:
                if listing(client, prefix, name, namespace) != before:
                    raise UploadError("version race during readback")
                pinned = candidate
        if pinned is None:
            data = client.request(
                "PUT",
                object_path,
                {
                    "namespace": namespace,
                    "name": name,
                    "object_type": "swagger",
                    "string_value": text,
                    "content_format": "json",
                },
            )
            if "error" in data or "code" in data:
                raise UploadError("error API response")
            if "presigned_url" in data:
                raise UploadError(
                    "presigned upload unsupported; authentication stays on tenant"
                )
            # The schema documents a string, not an exhaustive success enum.
            # Status is diagnostic: metadata plus exact content establish success.
            status_value = data.get("status")
            if "status" in data and (
                not isinstance(status_value, str)
                or not status_value
                or any(word in status_value.lower() for word in ("fail", "error"))
            ):
                raise UploadError("malformed or failed upload status")
            pinned = metadata(data, name, namespace)
            verify(client, object_path + "/" + pinned, name, namespace, pinned, text)
        path = object_path + "/" + pinned
        client.remaining()
        identity.update(version=pinned, path=path)
        # Publish atomically only after complete verification. Existing receipts are never overwritten.
        fd, temporary = tempfile.mkstemp(
            prefix=".swagger-receipt-", dir=receipt_path.parent
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(identity, stream, ensure_ascii=False)
                stream.flush()
                os.fsync(stream.fileno())
            os.link(temporary, receipt_path)
        finally:
            Path(temporary).unlink()
        return path
    finally:
        os.close(lockfd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name")
    parser.add_argument("file", type=Path)
    parser.add_argument("namespace", nargs="?", default="webapp-api-protection")
    parser.add_argument("--timeout-seconds", type=float, default=120)
    args = parser.parse_args(argv)
    try:
        label(args.name)
        label(args.namespace)
        with args.file.open("rb") as stream:
            text = validate_content(stream.read(MAX_CONTENT + 1), args.file.suffix)
        client = Client(
            os.environ.get("XCSH_API_URL", ""),
            os.environ.get("XCSH_API_TOKEN", ""),
            args.timeout_seconds,
        )
        receipt = os.environ.get("SWAGGER_RECEIPT_PATH")
        if not receipt:
            directory = Path.home() / ".local/state/waap-swagger"
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            info = directory.stat()
            if (
                directory.is_symlink()
                or info.st_uid != os.getuid()
                or info.st_mode & 0o077
            ):
                raise UploadError(
                    "default receipt directory must be private and owned (0700)"
                )
            key = hashlib.sha256(
                (client.base + args.namespace + args.name + text).encode("utf-8")
            ).hexdigest()
            receipt = directory / (key + ".json")
        print(upload(client, args.name, args.namespace, text, receipt))
        return 0
    except (UploadError, OSError, UnicodeError, ValueError, RecursionError) as exc:
        # Never print transport exception contents: they may contain credentials or response data.
        message = (
            str(exc)
            if isinstance(exc, UploadError)
            else "local input/receipt processing failed"
        )
        print("swagger-upload: " + message, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
