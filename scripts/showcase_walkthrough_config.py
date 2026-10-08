"""Full-resource demonstration transactions with private recovery snapshots."""

from __future__ import annotations

import copy
import json
from typing import TYPE_CHECKING, Any, NoReturn, cast

from demo_verify_types import EvidenceError

SUCCESS = 200

if TYPE_CHECKING:
    from pathlib import Path

    from demo_verify_client import Client


def fail(message: str) -> NoReturn:
    """Raise a safe local diagnostic."""
    raise EvidenceError(message)


def save(path: Path, value: Any) -> None:
    """Keep configuration and evidence private, including partial failures."""
    path.write_text(json.dumps(value, indent=2))
    path.chmod(0o600)


def choice(spec: dict, arms: tuple[str, ...], selected: str, value: Any) -> None:
    """Select one API union member, removing every competing member."""
    for key in arms:
        spec.pop(key, None)
    spec[selected] = copy.deepcopy(value)


def focused(
    form: dict, category: str, enabled: bool, *, firewall: bool = False
) -> dict:
    """Change only the category leaf and the required detection isolation."""
    result = copy.deepcopy(form)
    spec = result["spec"]
    if firewall:
        choice(
            spec,
            ("blocking", "monitoring"),
            "blocking" if enabled else "monitoring",
            {},
        )
        return result
    choice(
        spec,
        ("enable_malicious_user_detection", "disable_malicious_user_detection"),
        "enable_malicious_user_detection"
        if category == "mud" and enabled
        else "disable_malicious_user_detection",
        {},
    )
    if category == "schema":
        active = spec["api_specification"]["validation_all_spec_endpoints"][
            "validation_mode"
        ]["validation_mode_active"]
        choice(
            active,
            ("enforcement_block", "enforcement_report"),
            "enforcement_block" if enabled else "enforcement_report",
            {},
        )
    if category == "endpoint-denial":
        rules = spec["api_protection_rules"]["api_endpoint_rules"]
        matches = [
            r
            for r in rules
            if r["api_endpoint_path"] == "/httpbin/anything/admin"
            and set(r["api_endpoint_method"]["methods"]) == {"POST", "DELETE"}
        ]
        if len(matches) != 1:
            fail("exact admin rule required")
        choice(
            matches[0]["action"], ("allow", "deny"), "deny" if enabled else "allow", {}
        )
    if category == "rate-limit":
        api = form["spec"].get("api_rate_limit")
        if not isinstance(api, dict):
            fail("captured endpoint limiter required")
        choice(
            spec,
            ("api_rate_limit", "disable_rate_limit", "rate_limit"),
            "api_rate_limit" if enabled else "disable_rate_limit",
            api if enabled else {},
        )
    return result


def content(form: dict) -> dict:
    """Exclude only the server-issued optimistic resource version."""
    return {k: v for k, v in form.items() if k != "resource_version"}


class Configuration:
    """Capture replacement forms and reject changes outside a submitted phase."""

    def __init__(self, client: Client, directory: Path) -> None:
        """Bind scoped transport and an already-private receipt directory."""
        self.client, self.directory = client, directory
        self.original: dict[str, dict] = {}
        self.current: dict[str, dict] = {}
        self.pending: dict[str, dict] = {}

    def read(self, path: str) -> dict:
        """Fetch the API's complete writable form, rather than copying a GET spec."""
        code, obj = self.client.api(
            path + "?response_format=GET_RSP_FORMAT_FOR_REPLACE"
        )
        form = obj.get("replace_form") if isinstance(obj, dict) else None
        if isinstance(form, dict) and not form.get("resource_version"):
            form = {**form, "resource_version": obj.get("resource_version")}
        if (
            code != SUCCESS
            or not isinstance(form, dict)
            or not all(k in form for k in ("metadata", "spec", "resource_version"))
            or not form["resource_version"]
        ):
            fail("complete versioned replacement form required")
        return cast("dict", form)

    def capture(self, path: str) -> None:
        """Retain the complete original before granting any write."""
        form = self.read(path)
        self.original[path] = copy.deepcopy(form)
        self.current[path] = form
        save(self.directory / "configuration-original.json", self.original)

    def put(self, _path: str, _form: dict) -> None:
        """Walkthroughs cannot modify XC configuration."""
        fail("walkthrough configuration writes are prohibited; use Terraform endpoints")

    def update(self, _path: str, _desired: dict) -> None:
        """Reject configuration transactions in read-only walkthroughs."""
        fail("walkthrough configuration writes are prohibited; use Terraform endpoints")

    def restore(self) -> bool:
        """Verify walkthroughs left every captured configuration unchanged."""
        outcomes = {}
        for path, original in self.original.items():
            try:
                outcomes[path] = content(self.read(path)) == content(original)
            except (EvidenceError, OSError, ValueError):
                outcomes[path] = False
        save(self.directory / "restoration.json", outcomes)
        return bool(outcomes) and all(outcomes.values())
