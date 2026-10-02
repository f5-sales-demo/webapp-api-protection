"""Deadline-bounded subprocess and tenant HTTP execution with private receipts."""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import time
import urllib.error
import urllib.request
from contextlib import suppress
from http import HTTPStatus
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast

from demo_lifecycle_state import Blocked, save_json

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from http.client import HTTPResponse

    from demo_lifecycle_state import Context

_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_READ_CHUNK_BYTES = 65536
_OPEN_TIMEOUT_SECONDS = 30
_REAP_TIMEOUT_SECONDS = 5
_TERRAFORM_VERB_INDEX = 2
_DIAGNOSTICS = (
    (r"(?:^|\s)(?:http[ -])?403(?=\s|$|[,;:)])", "HTTP-403-permission"),
    (r"\bauthorizationpermissionmismatch\b", "blob-data-permission"),
    (r"\bauthorizationfailed\b", "permission"),
    (r"\balready exists\b", "resource-conflict"),
    (r"(?:^|\s)(?:http[ -])?401(?=\s|$|[,;:)])", "authentication"),
    (r"(?:^|\s)(?:http[ -])?400(?=\s|$|[,;:)])", "HTTP-400-configuration"),
    (r"\binvalidapiversionparameter\b", "arm-api-version-unsupported"),
    (r"\bunsupportedapiversion\b", "arm-api-version-unsupported"),
    (r"(?:^|\s)quota(?=\s|$|[:;,])", "quota"),
    (r"(?:^|\s)timeout(?=\s|$|[:;,])", "timeout"),
)
_SAFE_VERBS = {
    "init",
    "fmt",
    "validate",
    "plan",
    "apply",
    "output",
    "state",
    "show",
    "import",
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Reject redirects rather than forward tenant authorization headers."""

    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        """Refuse every redirect without exposing credentials."""
        message = "XC redirect refused to protect tenant credentials"
        raise Blocked(message)


def _terminate_group(proc: subprocess.Popen[str]) -> None:
    """Kill descendants and reap, even if an inherited pipe remains open."""
    with suppress(ProcessLookupError):
        os.killpg(proc.pid, signal.SIGKILL)
    try:
        proc.communicate(timeout=_REAP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        for stream in (proc.stdout, proc.stderr):
            if stream is not None:
                stream.close()
        with suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=_REAP_TIMEOUT_SECONDS)


def _diagnostic(argv: Sequence[str | Path], stderr: str) -> str:
    lower = stderr.lower()
    for pattern, label in _DIAGNOSTICS:
        if re.search(pattern, lower):
            return label
    # State-lock is Terraform's actual diagnostic, not fields like blocking_page.
    if Path(str(argv[0])).name == "terraform" and re.search(r"\bstate lock\b", lower):
        return "state-lock"
    return "upstream-output-withheld"


class Runtime:
    """Execute commands and XC reads using a shared shrinking operation budget."""

    def __init__(self, context: Context) -> None:
        """Bind execution to the approved context without making network calls."""
        self.context = context
        self.opener = urllib.request.build_opener(_NoRedirect())

    def remaining(self) -> float:
        """Return the remaining total operation budget, or fail closed."""
        value = self.context.state.deadline - time.monotonic()
        if value <= 0:
            message = "operation deadline exceeded"
            raise Blocked(message)
        return value

    def phase(
        self,
        name: str,
        status: Literal["passed", "blocked"] = "passed",
    ) -> None:
        """Persist a bounded phase summary without private command output."""
        self.context.state.receipt["phases"].append(
            {
                "name": name,
                "status": status,
                "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
        )
        save_json(
            self.context.paths.state / "operation-receipt.json",
            self.context.state.receipt,
        )

    def run(
        self,
        argv: Sequence[str | Path],
        cwd: Path | None = None,
        allowed: tuple[int, ...] = (0,),
        env: Mapping[str, str] | None = None,
        input_text: str | None = None,
    ) -> tuple[str, int]:
        """Run argv without a shell; kill the process group on interruption."""
        began = time.monotonic()
        budget = self.remaining()
        # Trusted internal argv is never shell-expanded; callers own command selection.
        with subprocess.Popen(  # noqa: S603
            [str(argument) for argument in argv],
            cwd=cwd or self.context.paths.root,
            env=env or self.context.env,
            stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            text=True,
        ) as proc:
            try:
                stdout, stderr = proc.communicate(input=input_text, timeout=budget)
            except BaseException:
                _terminate_group(proc)
                self._record_command(
                    argv,
                    proc.returncode,
                    began,
                    "interrupted-or-deadline",
                )
                raise
            code = proc.returncode
            if code is None:
                message = "required subprocess failed: process exit unavailable"
                raise Blocked(message)
            category = "none" if code in allowed else _diagnostic(argv, stderr)
            self._record_command(argv, code, began, category)
            if code not in allowed:
                message = (
                    "required subprocess failed: "
                    + Path(str(argv[0])).name
                    + " exit "
                    + str(code)
                    + " ("
                    + category
                    + ")"
                )
                raise Blocked(message)
            return stdout, code

    def _record_command(
        self,
        argv: Sequence[str | Path],
        code: int | None,
        began: float,
        category: str,
    ) -> None:
        program = Path(str(argv[0])).name
        verb = (
            str(argv[_TERRAFORM_VERB_INDEX])
            if program == "terraform" and len(argv) > _TERRAFORM_VERB_INDEX
            else "invocation"
        )
        if verb not in _SAFE_VERBS:
            verb = "invocation"
        self.context.state.receipt.setdefault("commands", []).append(
            {
                "program": program,
                "verb": verb,
                "exit_code": code,
                "seconds": round(time.monotonic() - began, 3),
                "diagnostic": category,
            }
        )
        save_json(
            self.context.paths.state / "operation-receipt.json",
            self.context.state.receipt,
        )

    def az(self, *argv: str | Path) -> Any:
        """Read Azure JSON scoped to the privately approved subscription."""
        return json.loads(
            self.run(
                [
                    "az",
                    *argv,
                    "--subscription",
                    self.context.settings.scope["subscription_id"],
                    "-o",
                    "json",
                ]
            )[0]
        )

    def _read_response(self, response: HTTPResponse) -> dict[str, Any]:
        chunks: list[bytes] = []
        size = 0
        while response.fp is not None:
            # urllib has no public socket setter. Reset the actual transport deadline
            # before each read1 so a slow drip cannot refresh an idle-only timeout.
            cast("Any", response.fp.raw)._sock.settimeout(self.remaining())  # noqa: SLF001  # pylint: disable=protected-access
            chunk = response.read1(_READ_CHUNK_BYTES)
            self.remaining()
            if not chunk:
                break
            size += len(chunk)
            if size > _MAX_RESPONSE_BYTES:
                message = "XC response exceeded bounded evidence size"
                raise Blocked(message)
            chunks.append(chunk)
        if getattr(response, "length", None) not in (None, 0):
            message = "truncated XC response"
            raise Blocked(message)
        result = json.loads(b"".join(chunks))
        if not isinstance(result, dict):
            message = "XC response must be a JSON object"
            raise Blocked(message)
        return result

    def xc(self, path: str, allow_absent: bool = False) -> dict[str, Any] | None:
        """Read tenant evidence without redirects or an unbounded response body."""
        # Fixed validated HTTPS base; redirects are prohibited by the opener.
        request = urllib.request.Request(  # noqa: S310
            self.context.settings.scope["xc_url"] + path,
            headers={"Authorization": "APIToken " + self.context.env["XCSH_API_TOKEN"]},
        )
        try:
            # The base URL is fixed and validated, never a caller-selected scheme.
            with self.opener.open(
                request,
                timeout=min(_OPEN_TIMEOUT_SECONDS, self.remaining()),
            ) as response:
                return self._read_response(cast("HTTPResponse", response))
        except urllib.error.HTTPError as exc:
            if exc.code == HTTPStatus.NOT_FOUND and allow_absent:
                return None
            message = "XC authentication/permission check failed: HTTP " + str(exc.code)
            raise Blocked(message) from None
        except (urllib.error.URLError, TimeoutError):
            message = "XC connectivity check failed"
            raise Blocked(message) from None
