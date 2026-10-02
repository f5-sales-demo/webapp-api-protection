"""Bounded read and probe transports; no lifecycle mutation or ownership inference."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import signal
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import TYPE_CHECKING, Any

from demo_verify_evidence import decode_event, identified_user, virtual_host
from demo_verify_types import EvidenceError

if TYPE_CHECKING:
    from email.message import Message
    from typing import IO

    from demo_verify_types import ReadRetry, VerifyOptions, Vm

COMMAND_BOUND = 4_000_000
APPLICATION_BOUND = 1_000_000
SHORT_TIMEOUT = 20
BACKOFF = 1
PAGE_LIMIT = 500
MAX_PAGES = 20
MIN_TELEMETRY_WINDOW = 10
INITIAL_TELEMETRY_WINDOW = 30
OK = 200
NOT_FOUND = 404
TRANSIENT = (429, 503)
ARM_VERSION = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}(-preview)?")
ARM_STATUS = re.compile(
    r"^INFO:\s*(?:azure\.cli\.core\.util:\s*)?Response status:\s*(\d{3})\s*$",
    re.MULTILINE,
)
ARM_TRANSPORT = re.compile(
    r"(?:requests\.exceptions\.|urllib3\.exceptions\.)"
    r"(?:ConnectionError|ReadTimeout|ConnectTimeout|ProtocolError|"
    r"NewConnectionError|NameResolutionError|MaxRetryError)\b"
)


def _fail(message: str) -> EvidenceError:
    return EvidenceError(message)


def _query(lb: str, _suspicious: bool, user: str | None) -> str:
    query = "{vh_name=" + json.dumps(virtual_host(lb))
    if user is not None:
        identity = identified_user(user)
        query += ",user=" + json.dumps(identity)
    return query + "}"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Reject redirects before forwarding credentials or accepting probe proof."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: Message,
        newurl: str,
    ) -> None:
        """Deny every redirected request."""
        return


HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def _arm_absent(error: str, rid: str) -> bool:
    try:
        body, _ = json.JSONDecoder().raw_decode(error[error.index("{") :])
    except ValueError as exc:
        msg = "Azure not-found JSON failure"
        raise _fail(msg) from exc
    arm_error = body.get("error") if isinstance(body, dict) else None
    if (
        not isinstance(arm_error, dict)
        or arm_error.get("code") not in ("ResourceNotFound", "ResourceGroupNotFound")
        or ("target" in arm_error and arm_error["target"] != rid)
    ):
        msg = "Azure not-found response unproven"
        raise _fail(msg)
    message = arm_error.get("message", "")
    if not isinstance(message, str):
        msg = "Azure error response malformed"
        raise _fail(msg)
    referenced_ids = re.findall(r"/subscriptions/[A-Za-z0-9_./-]+", message)
    if any(value.lower() != rid.lower() for value in referenced_ids):
        msg = "Azure not-found identity mismatch"
        raise _fail(msg)
    return False


def _arm_result(process: subprocess.CompletedProcess[bytes], rid: str) -> bool | str:
    if len(process.stdout) + len(process.stderr) > COMMAND_BOUND:
        msg = "Azure response exceeded bound"
        raise _fail(msg)
    if not process.returncode:
        try:
            resource = json.loads(process.stdout)
        except ValueError as exc:
            msg = "Azure JSON failure"
            raise _fail(msg) from exc
        if (
            not isinstance(resource, dict)
            or not isinstance(resource.get("id"), str)
            or resource["id"].lower() != rid.lower()
        ):
            msg = "Azure identity response mismatch"
            raise _fail(msg)
        return True
    error = process.stderr.decode("utf-8", errors="replace")
    statuses = ARM_STATUS.findall(error)
    if statuses == [str(NOT_FOUND)]:
        return _arm_absent(error, rid)
    if statuses in ([str(value)] for value in TRANSIENT):
        return "http-" + statuses[0]
    if not statuses and ARM_TRANSPORT.search(error):
        return "transport"
    msg = "Azure access or service failure; absence unproven"
    raise _fail(msg)


def _page_batch(code: int, page: Any, key: str) -> tuple[list[Any], int, str]:
    if code != OK or not isinstance(page, dict) or not isinstance(page.get(key), list):
        msg = "malformed telemetry page"
        raise _fail(msg)
    batch = page[key]
    if len(batch) > PAGE_LIMIT or page.get("errors") or page.get("truncated"):
        msg = "incomplete telemetry"
        raise _fail(msg)
    try:
        total = int(page["total_hits"])
    except (KeyError, TypeError, ValueError) as exc:
        msg = "unknown telemetry coverage"
        raise _fail(msg) from exc
    token = page.get("scroll_id", "")
    if total < 0:
        msg = "inconsistent telemetry coverage"
        raise _fail(msg)
    if not isinstance(token, str):
        msg = "invalid telemetry coverage"
        raise _fail(msg)
    return batch, total, token


class Client:
    """Keep the existing phase deadline, exact read contracts and safe diagnostics."""

    def __init__(self, deadline: float) -> None:
        """Capture the deadline and authenticated HTTPS tenant endpoint."""
        self.deadline = deadline
        self.read_retries: list[ReadRetry] = []
        self.base = os.environ.get("XCSH_API_URL", "").rstrip("/")
        self.token = os.environ.get("XCSH_API_TOKEN", "")
        parsed = urllib.parse.urlsplit(self.base)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.query
            or parsed.fragment
        ):
            msg = "valid HTTPS XCSH_API_URL required"
            raise _fail(msg)
        if not self.token:
            msg = "XCSH_API_TOKEN required"
            raise _fail(msg)

    def remaining(self, *, phase_budget: bool = False) -> float:
        """Return bounded read time or the explicitly requested phase budget."""
        left = self.deadline - time.monotonic()
        if left <= 0:
            msg = "deadline exceeded"
            raise _fail(msg)
        return left if phase_budget else min(left, SHORT_TIMEOUT)

    def command(
        self,
        argv: list[str],
        *,
        phase_budget: bool = False,
        allowed: tuple[int, ...] = (0,),
    ) -> str:
        """Run trusted argv, reaping the entire phase process group on timeout."""
        try:
            timeout = self.remaining(phase_budget=phase_budget)
            if phase_budget:
                # Trusted operator argv, no shell; phase descendants share a new group.
                with subprocess.Popen(  # noqa: S603
                    argv,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                ) as child:
                    try:
                        stdout, _ = child.communicate(timeout=timeout)
                    except subprocess.TimeoutExpired:
                        os.killpg(child.pid, signal.SIGKILL)
                        child.communicate()
                        raise
                    returncode = child.returncode
            else:
                # Trusted CLI argv, no shell interpolation.
                completed = subprocess.run(  # noqa: S603
                    argv, capture_output=True, check=False, timeout=timeout
                )
                stdout, returncode = completed.stdout, completed.returncode
        except (OSError, subprocess.TimeoutExpired) as exc:
            msg = "command unavailable or timed out"
            raise _fail(msg) from exc
        if returncode not in allowed:
            msg = "required command failed"
            raise _fail(msg)
        if len(stdout) > COMMAND_BOUND:
            msg = "command output exceeded bound"
            raise _fail(msg)
        return stdout.decode("utf-8")

    def api(self, path: str, payload: dict[str, Any] | None = None) -> tuple[int, Any]:
        """Read scoped API JSON with the original per-request timeout and body bound."""
        headers = {"Authorization": "APIToken " + self.token}
        data = None
        if payload is not None:
            data = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        # The base is HTTPS-only; a path cannot replace its scheme or authority.
        if not path.startswith("/api/") or "#" in path:
            msg = "scoped API path required"
            raise _fail(msg)
        request = urllib.request.Request(  # noqa: S310 - validated HTTPS base and scoped path
            self.base + path, data=data, headers=headers
        )
        try:
            # HTTPS was validated above; redirects are disabled by HTTP.
            with HTTP.open(request, timeout=self.remaining()) as response:
                body = response.read(COMMAND_BOUND + 1)
                if len(body) > COMMAND_BOUND:
                    msg = "API response exceeded bound"
                    raise _fail(msg)
                result = response.status, json.loads(body)
        except urllib.error.HTTPError as exc:
            with exc:
                if exc.code == NOT_FOUND:
                    return NOT_FOUND, {}
                msg = "API access or service failure"
                raise _fail(msg) from exc
        except (OSError, ValueError) as exc:
            msg = "API transport or JSON failure"
            raise _fail(msg) from exc
        return result

    def azure_exists(self, subscription: str, rid: str, api_version: str) -> bool:
        """Read exact ARM identity; retry only one transient GET within budget."""
        if not ARM_VERSION.fullmatch(api_version):
            msg = "captured ARM API version required"
            raise _fail(msg)
        argv = [
            "az",
            "rest",
            "--method",
            "get",
            "--url",
            "https://management.azure.com" + rid + "?api-version=" + api_version,
            "--subscription",
            subscription,
            "--output",
            "json",
            "--verbose",
        ]
        for attempt in range(2):
            try:
                # Fixed az read argv and captured IDs; never evaluated by a shell.
                completed = subprocess.run(  # noqa: S603
                    argv, capture_output=True, check=False, timeout=self.remaining()
                )
            except subprocess.TimeoutExpired:
                outcome: bool | str = "timeout"
            except OSError as exc:
                msg = "Azure command unavailable"
                raise _fail(msg) from exc
            else:
                outcome = _arm_result(completed, rid)
            if isinstance(outcome, bool):
                return outcome
            if attempt or self.deadline - time.monotonic() <= BACKOFF:
                msg = "Azure transient read failed; absence unproven"
                raise _fail(msg)
            self.read_retries.append({"reason": outcome, "attempt": 1})
            time.sleep(BACKOFF)
        msg = "Azure read failed; absence unproven"
        raise _fail(msg)

    def pages(
        self,
        namespace: str,
        lb: str,
        since: float,
        end: float,
        suspicious: bool = False,
        user: str | None = None,
    ) -> list[Any]:
        """Require exact coverage; decode ordinary events once, retain opaque risk logs."""
        if not suspicious and user is None and end - since > INITIAL_TELEMETRY_WINDOW:
            return self._split_pages(namespace, lb, since, end, suspicious, user)
        resource, key = (
            ("suspicious_user_logs", "logs") if suspicious else ("events", "events")
        )
        path = f"/api/data/namespaces/{namespace}/app_security/{resource}"
        payload = {
            "query": _query(lb, suspicious, user),
            "start_time": str(min(int(since), int(end) - MIN_TELEMETRY_WINDOW)),
            "end_time": str(int(end) + 1),
            "limit": PAGE_LIMIT,
            "scroll": True,
        }
        code, page = self.api(path, payload)
        records: list[Any] = []
        seen_batches: set[str] = set()
        total = None
        for _ in range(MAX_PAGES):
            batch, page_total, token = _page_batch(code, page, key)
            if total is None:
                total = page_total
            if total != page_total:
                msg = "inconsistent telemetry coverage"
                raise _fail(msg)
            records.extend(
                batch if suspicious else [decode_event(raw) for raw in batch]
            )
            if len(records) > total:
                msg = "invalid telemetry coverage"
                raise _fail(msg)
            # A retained scroll ID is harmless when exact total_hits proves completion.
            if len(records) == total:
                return records
            if not token:
                msg = "truncated telemetry coverage"
                raise _fail(msg)
            if json.dumps(batch, sort_keys=True) in seen_batches or not batch:
                msg = "invalid pagination progress"
                raise _fail(msg)
            seen_batches.add(json.dumps(batch, sort_keys=True))
            code, page = self.api(path + "/scroll", {"scroll_id": token})
        return self._split_pages(namespace, lb, since, end, suspicious, user)

    def _split_pages(
        self,
        namespace: str,
        lb: str,
        since: float,
        end: float,
        suspicious: bool,
        user: str | None,
    ) -> list[Any]:
        """Split oversized windows while retaining complete child page coverage."""
        if end - since <= MIN_TELEMETRY_WINDOW:
            msg = "telemetry pagination exceeded bound within ten-second window"
            raise _fail(msg)
        midpoint = (since + end) / 2
        records = self.pages(
            namespace, lb, since, midpoint, suspicious, user
        ) + self.pages(namespace, lb, midpoint, end, suspicious, user)
        return list(
            {json.dumps(record, sort_keys=True): record for record in records}.values()
        )

    def ssh(
        self,
        vm: Vm,
        args: VerifyOptions,
        remote: str,
        *,
        phase_budget: bool = False,
        allowed: tuple[int, ...] = (0,),
    ) -> str:
        """Use dedicated key, strict known hosts and validated address and username."""
        if not args.ssh_key or not args.known_hosts:
            msg = "dedicated SSH key and known-hosts required"
            raise _fail(msg)
        ipaddress.ip_address(vm["public_ip"])
        username = vm["admin_username"]
        if not re.fullmatch(r"[a-z_][a-z0-9_-]*", username):
            msg = "invalid SSH username"
            raise _fail(msg)
        return self.command(
            [
                "ssh",
                "-i",
                args.ssh_key,
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "ConnectTimeout=10",
                "-o",
                "UserKnownHostsFile=" + args.known_hosts,
                username + "@" + vm["public_ip"],
                remote,
            ],
            phase_budget=phase_budget,
            allowed=allowed,
        )

    def request(
        self,
        host: str,
        path: str,
        method: str,
        user: str,
        body: dict[str, Any] | None = None,
    ) -> tuple[int, Any]:
        """Issue a synthetic HTTP probe without accepting redirects as evidence."""
        identified_user(user)
        try:
            ipaddress.ip_address(host)
            protocol = "http"
        except ValueError:
            protocol = "https"
        url = protocol + "://" + host + path
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != protocol or parsed.netloc != host or parsed.username:
            msg = "valid application HTTPS host required"
            raise _fail(msg)
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(  # noqa: S310 - validated explicit HTTP scheme
            url,
            data=data,
            method=method,
            headers={"X-MUD-User": user, "Content-Type": "application/json"},
        )
        try:
            # Explicit HTTP scheme for the demo application; redirects disabled.
            with HTTP.open(request, timeout=self.remaining()) as response:
                raw = response.read(APPLICATION_BOUND + 1)
                code = response.status
        except urllib.error.HTTPError as exc:
            with exc:
                code, raw = exc.code, exc.read(APPLICATION_BOUND + 1)
        except OSError as exc:
            msg = "application transport failure"
            raise _fail(msg) from exc
        if len(raw) > APPLICATION_BOUND:
            msg = "application body exceeded bound"
            raise _fail(msg)
        try:
            result = json.loads(raw)
        except ValueError:
            result = None
        return code, result
