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
from http import HTTPStatus
from pathlib import Path
from typing import Any, NoReturn, Protocol

MAX_LABEL = 63
MAX_VERSION = 1024
CONTROL_BOUNDARY = 32
DELETE_CHARACTER = 127
MAX_TIMEOUT = 3600
MAX_CONTENT = 5 * 1024 * 1024
MAX_RESPONSE = 32 * 1024 * 1024
MAX_VERSIONS = 64


class UploadClient(Protocol):
    """Tenant-bound transport supporting exact-version upload and verification."""

    base: str

    def request(
        self, method: str, path: str, body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Send one bounded request under the shared deadline."""
        raise NotImplementedError

    def remaining(self) -> float:
        """Return remaining total time or fail when exhausted."""
        raise NotImplementedError


class UploadError(Exception):
    """Validation or verification failure; no successful path may be emitted."""


class ContentMismatchError(UploadError):
    """An exact version exists but holds different content."""


class HTTPFailureError(UploadError):
    """Non-success HTTP result retaining only its status code."""

    def __init__(self, method: str, status: int) -> None:
        """Record a safe method/status diagnostic without response data."""
        self.status = status
        super().__init__(f"{method} failed (HTTP {status})")


def strict_json(text: str) -> Any:
    """Decode JSON while rejecting duplicates and nonfinite values."""

    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in values:
            if key in result:
                msg = "duplicate JSON key"
                raise UploadError(msg)
            result[key] = value
        return result

    def constant(_value: str) -> NoReturn:
        msg = "non-finite JSON value"
        raise UploadError(msg)

    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, RecursionError) as exc:
        msg = "malformed JSON"
        raise UploadError(msg) from exc


def label(value: object) -> str:
    """Validate a namespace or object name as a bounded DNS label."""
    if (
        not isinstance(value, str)
        or len(value) > MAX_LABEL
        or not re.fullmatch(r"[a-z](?:[-a-z0-9]*[a-z0-9])?", value)
    ):
        msg = "name and namespace must be DNS labels of at most 63 characters"
        raise UploadError(msg)
    return value


def version(value: object) -> str:
    """Validate an exact version, excluding latest and path delimiters."""
    if (
        not isinstance(value, str)
        or len(value) > MAX_VERSION
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", value)
        or value in ("latest", ".", "..")
    ):
        msg = "invalid or unpinned version"
        raise UploadError(msg)
    return value


def api_base(value: str) -> str:
    """Validate an HTTPS tenant origin without embedded credentials."""
    parts = urllib.parse.urlsplit(value)
    invalid_origin = (
        parts.scheme != "https"
        or not parts.hostname
        or bool(parts.username)
        or bool(parts.password)
    )
    invalid_suffix = (
        parts.path not in ("", "/") or bool(parts.query) or bool(parts.fragment)
    )
    if (
        invalid_origin
        or invalid_suffix
        or any(ord(c) <= CONTROL_BOUNDARY or ord(c) == DELETE_CHARACTER for c in value)
        or not re.fullmatch(r"[A-Za-z0-9.-]+|[A-Fa-f0-9:]+", parts.hostname or "")
    ):
        msg = "XCSH_API_URL must be an HTTPS tenant base URL without credentials, path or query"
        raise UploadError(msg)
    try:
        _port = parts.port
    except ValueError as exc:
        msg = "invalid tenant URL port"
        raise UploadError(msg) from exc
    return value.rstrip("/")


def validate_content(raw: bytes, suffix: str) -> str:
    """Validate supported JSON API documents without changing their bytes."""
    if not raw or len(raw) > MAX_CONTENT:
        msg = "document must be nonempty and no larger than 5 MiB"
        raise UploadError(msg)
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        msg = "document must be UTF-8"
        raise UploadError(msg) from exc
    if suffix.lower() in (".yaml", ".yml"):
        # No implicit dependency installation or lossy JSON conversion.
        msg = "YAML validation is unsupported: provide an OpenAPI JSON document"
        raise UploadError(msg)
    data = strict_json(text)
    if not isinstance(data, dict):
        msg = "document must be an object"
        raise UploadError(msg)
    oas = data.get("openapi")
    if not (
        (
            isinstance(oas, str)
            and re.fullmatch(r"3\.[01]\.\d+", oas)
            and "swagger" not in data
        )
        or (data.get("swagger") == "2.0" and "openapi" not in data)
    ):
        msg = "supported profiles are OpenAPI 3.0/3.1 or Swagger 2.0"
        raise UploadError(msg)
    info = data.get("info")
    if not isinstance(info, dict) or not all(
        isinstance(info.get(k), str) and info[k] for k in ("title", "version")
    ):
        msg = "info.title and info.version are required strings"
        raise UploadError(msg)
    paths = data.get("paths")
    if not isinstance(paths, dict) or not all(
        isinstance(k, str) and k.startswith("/") and isinstance(v, dict)
        for k, v in paths.items()
    ):
        msg = "paths must map absolute API paths to objects"
        raise UploadError(msg)
    return text


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Reject every redirect rather than forwarding tenant authentication."""

    def redirect_request(self, *_args: object, **_kwargs: object) -> NoReturn:
        """Refuse the stdlib redirect hook irrespective of destination."""
        msg = "redirect refused; tenant authentication never follows URLs"
        raise UploadError(msg)


class Client:
    """HTTPS tenant client with no redirects and one total upload deadline."""

    def __init__(self, base: str, token: str, timeout: float) -> None:
        """Validate credentials and establish the shared monotonic deadline."""
        self.base = api_base(base)
        if not token or any(
            ord(c) < CONTROL_BOUNDARY or ord(c) == DELETE_CHARACTER for c in token
        ):
            msg = "XCSH_API_TOKEN must be present without control characters"
            raise UploadError(msg)
        if not 0 < timeout <= MAX_TIMEOUT:
            msg = "timeout must be between 0 and 3600 seconds"
            raise UploadError(msg)
        self.token = token
        self.deadline = time.monotonic() + timeout
        self.opener = urllib.request.build_opener(NoRedirect())

    def remaining(self) -> float:
        """Return the unspent deadline or reject further work."""
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            msg = "upload verification deadline exceeded"
            raise UploadError(msg)
        return remaining

    def request(
        self, method: str, path: str, body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Retry only transient GET failures once, never a PUT."""
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
        # api_base validates HTTPS origin; internal paths cannot change its authority.
        # NoRedirect forbids sending the token onward to any redirect target.
        req = urllib.request.Request(  # noqa: S310
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
                if response.status != HTTPStatus.OK:
                    raise HTTPFailureError(method, response.status)
                chunks = []
                size = 0
                while True:
                    if response.fp is None:
                        break
                    # Reapply the total deadline to each socket read, including slow drips.
                    # urllib exposes no public API for shrinking read timeouts.
                    response.fp.raw._sock.settimeout(self.remaining())  # noqa: SLF001  # pylint: disable=protected-access
                    chunk = response.read1(65536)
                    self.remaining()
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > MAX_RESPONSE:
                        msg = "API response exceeds bounded size"
                        raise UploadError(msg)
                    chunks.append(chunk)
                if getattr(response, "length", None) not in (None, 0):
                    msg = "truncated HTTP response"
                    raise UploadError(msg)
            data = strict_json(b"".join(chunks).decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise HTTPFailureError(method, exc.code) from None
        except (
            OSError,
            UnicodeError,
            urllib.error.URLError,
            http.client.HTTPException,
        ) as exc:
            msg = f"{method} transport or UTF-8 failure"
            raise UploadError(msg) from exc
        if not isinstance(data, dict) or "error" in data or "code" in data:
            msg = "malformed or error API response"
            raise UploadError(msg)
        return data


def metadata(
    data: dict[str, Any], name: str, namespace: str, expected: str | None = None
) -> str:
    """Require matching object identity and return its exact version."""
    meta = data.get("metadata")
    if (
        not isinstance(meta, dict)
        or meta.get("name") != name
        or meta.get("namespace") != namespace
    ):
        msg = "response metadata identity mismatch"
        raise UploadError(msg)
    found = version(meta.get("version"))
    if expected is not None and found != expected:
        msg = "response metadata version mismatch"
        raise UploadError(msg)
    return found


def listing(client: UploadClient, prefix: str, name: str, namespace: str) -> set[str]:
    """Read the bounded exact-name version set, rejecting ambiguity."""
    query = urllib.parse.urlencode(
        {"name": name, "query_type": "EXACT_MATCH", "latest_version_only": "false"}
    )
    data = client.request("GET", prefix + "?" + query)
    items = data.get("items")
    if not isinstance(items, list) or len(items) > 1:
        msg = "malformed or ambiguous name-filtered listing"
        raise UploadError(msg)
    if not items:
        return set()
    item = items[0]
    if not isinstance(item, dict) or item.get("name") not in (
        name,
        namespace + "/" + name,
    ):
        msg = "listing object identity mismatch"
        raise UploadError(msg)
    values = item.get("versions")
    if not isinstance(values, list) or not values or len(values) > MAX_VERSIONS:
        msg = "missing or excessive versions in listing"
        raise UploadError(msg)
    result = []
    for value in values:
        if not isinstance(value, dict):
            msg = "malformed listing version"
            raise UploadError(msg)
        result.append(version(value.get("version")))
    if len(set(result)) != len(result):
        msg = "duplicate listing versions"
        raise UploadError(msg)
    return set(result)


def verify(
    client: UploadClient, path: str, name: str, namespace: str, pinned: str, text: str
) -> None:
    """Require exact-version identity and a matching content digest."""
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
            msg = "invalid base64 readback"
            raise UploadError(msg) from exc
    else:
        msg = (
            "missing, ambiguous or presigned content; external URLs are never followed"
        )
        raise UploadError(msg)
    if (
        len(raw) > MAX_CONTENT
        or hashlib.sha256(raw).hexdigest()
        != hashlib.sha256(text.encode("utf-8")).hexdigest()
    ):
        msg = "exact-version content SHA-256 mismatch"
        raise ContentMismatchError(msg)


def secure_open(path: str | Path, flags: int) -> int:
    """Open only private regular receipt files owned by this user."""
    fd = os.open(path, flags | os.O_NOFOLLOW, 0o600)
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
    ):
        os.close(fd)
        msg = "receipt and lock must be owned private regular files (0600)"
        raise UploadError(msg)
    return fd


def _saved_pin(receipt: Path, identity: dict[str, Any], object_path: str) -> str:
    fd = secure_open(receipt, os.O_RDONLY)
    with os.fdopen(fd, "rb") as stream:
        raw = stream.read(MAX_RESPONSE + 1)
    if len(raw) > MAX_RESPONSE:
        msg = "receipt exceeds bounded size"
        raise UploadError(msg)
    saved = strict_json(raw.decode("utf-8"))
    if not isinstance(saved, dict) or any(
        saved.get(k) != v for k, v in identity.items()
    ):
        msg = (
            "receipt identity/content differs; "
            "select a separate receipt for changed content"
        )
        raise UploadError(msg)
    pinned = version(saved.get("version"))
    if saved.get("path") != object_path + "/" + pinned:
        msg = "receipt path mismatch"
        raise UploadError(msg)
    return pinned


def _existing_pin(
    client: UploadClient, prefix: str, name: str, namespace: str, text: str
) -> str | None:
    before = listing(client, prefix, name, namespace)
    if not before:
        return None
    if len(before) != 1:
        msg = "existing object versions are ambiguous; refusing latest"
        raise UploadError(msg)
    candidate = next(iter(before))
    try:
        verify(
            client,
            prefix + "/" + name + "/" + candidate,
            name,
            namespace,
            candidate,
            text,
        )
    except ContentMismatchError:
        return None
    if listing(client, prefix, name, namespace) != before:
        msg = "version race during readback"
        raise UploadError(msg)
    return candidate


def _new_pin(
    client: UploadClient, object_path: str, name: str, namespace: str, text: str
) -> str:
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
        msg = "error API response"
        raise UploadError(msg)
    if "presigned_url" in data:
        msg = "presigned upload unsupported; authentication stays on tenant"
        raise UploadError(msg)
    # Status is diagnostic; exact metadata and content establish success.
    status_value = data.get("status")
    if "status" in data and (
        not isinstance(status_value, str)
        or not status_value
        or any(word in status_value.lower() for word in ("fail", "error"))
    ):
        msg = "malformed or failed upload status"
        raise UploadError(msg)
    pinned = metadata(data, name, namespace)
    verify(client, object_path + "/" + pinned, name, namespace, pinned, text)
    return pinned


def _publish_receipt(receipt: Path, identity: dict[str, Any]) -> None:
    # Publish atomically after verification; never overwrite existing receipts.
    fd, temporary = tempfile.mkstemp(prefix=".swagger-receipt-", dir=receipt.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(identity, stream, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, receipt)
    finally:
        Path(temporary).unlink()


def upload(
    client: UploadClient, name: str, namespace: str, text: str, receipt_path: str | Path
) -> str:
    """Verify exact content and publish a private receipt before returning its pin."""
    label(name)
    label(namespace)
    prefix = f"/api/object_store/namespaces/{namespace}/stored_objects/swagger"
    object_path = prefix + "/" + name
    identity = {
        "schema_version": 1,
        "api_url": client.base,
        "name": name,
        "namespace": namespace,
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "content": text,
    }
    receipt = Path(receipt_path).absolute()
    if not receipt.parent.is_dir():
        msg = "receipt parent directory must exist"
        raise UploadError(msg)
    lockfd = secure_open(str(receipt) + ".lock", os.O_CREAT | os.O_RDWR)
    try:
        try:
            fcntl.flock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            msg = "another upload holds the receipt lock"
            raise UploadError(msg) from exc
        if receipt.exists() or receipt.is_symlink():
            saved_pinned = _saved_pin(receipt, identity, object_path)
            saved_path = object_path + "/" + saved_pinned
            verify(client, saved_path, name, namespace, saved_pinned, text)
            return saved_path
        pinned = _existing_pin(client, prefix, name, namespace, text)
        if pinned is None:
            pinned = _new_pin(client, object_path, name, namespace, text)
        path = object_path + "/" + pinned
        client.remaining()
        identity.update(version=pinned, path=path)
        _publish_receipt(receipt, identity)
        return path
    finally:
        os.close(lockfd)


def _default_receipt(
    client: UploadClient, namespace: str, name: str, text: str
) -> Path:
    directory = Path.home() / ".local/state/waap-swagger"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.stat()
    if directory.is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o077:
        msg = "default receipt directory must be private and owned (0700)"
        raise UploadError(msg)
    key = hashlib.sha256(
        (client.base + namespace + name + text).encode("utf-8")
    ).hexdigest()
    return directory / (key + ".json")


def main(argv: list[str] | None = None) -> int:
    """Print one verified pin or a credential-safe failure diagnostic."""
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
        receipt_value = os.environ.get("SWAGGER_RECEIPT_PATH")
        receipt = (
            Path(receipt_value)
            if receipt_value
            else _default_receipt(client, args.namespace, args.name, text)
        )
        print(upload(client, args.name, args.namespace, text, receipt))
    except (UploadError, OSError, UnicodeError, ValueError, RecursionError) as exc:
        # Never print transport exception contents: they may contain credentials or response data.
        message = (
            str(exc)
            if isinstance(exc, UploadError)
            else "local input/receipt processing failed"
        )
        print("swagger-upload: " + message, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
