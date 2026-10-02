"""Validate private scope inputs and read exact effective or captured identities.

No function grants ownership, adopts resources, inventories a namespace, or
publishes upstream payloads. Manifest validation finishes before remote reads.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from demo_verify_types import CheckedAzure, CheckedManifest, CheckedXC, EvidenceError

if TYPE_CHECKING:
    from typing import NoReturn

    from demo_verify_types import EvidenceReader, ShowcaseOutputs, Vm

_NAME = re.compile(r"^[a-z][a-z0-9-]{0,62}[a-z0-9]$")
_SUBSCRIPTION = re.compile(r"[0-9a-f-]{36}")
_ARM_ID = re.compile(r"/[A-Za-z0-9_./-]+")
_API_VERSION = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}(?:-preview)?")
_XC_OBJECT = re.compile(r"/api/config/namespaces/[a-z0-9-]+/[a-z_]+/[a-z0-9-]+")
_XC_NAMESPACE = re.compile(r"/api/web/namespaces/[a-z][a-z0-9-]*[a-z0-9]")
_XC_COLLECTIONS = {
    "healthchecks",
    "origin_pools",
    "app_firewalls",
    "http_loadbalancers",
    "malicious_user_mitigations",
    "user_identifications",
    "api_discoverys",
    "api_definitions",
    "service_policys",
    "rate_limiters",
    "rate_limiter_policys",
}
_ARM_RESOURCE = re.compile(
    r"/subscriptions/[0-9a-f-]{36}/resourcegroups/[^/]+"
    r"(?:/providers/(?:microsoft\.compute/virtualmachines/[^/]+"
    r"|microsoft\.network/(?:publicipaddresses|networksecuritygroups|networkinterfaces)/[^/]+"
    r"|microsoft\.network/virtualnetworks/[^/]+(?:/subnets/[^/]+)?))?",
    re.IGNORECASE,
)
_MANIFEST_REQUIRED = {
    "schema_version",
    "subscription_id",
    "azure_owned",
    "xc_owned",
    "azure_preserved",
    "xc_preserved",
    "azure_api_versions",
}
_MANIFEST_OPTIONAL = {"namespace", "owned_resources", "persistent_resource_ids"}
_PROTECTION = {
    "waf_mode": "blocking",
    "csd_enabled": False,
    "mud_enabled": True,
    "mud_user_id": "user_identification",
    "api_definition_choice": "specification",
    "api_specification_validation": "all_spec_endpoints",
    "api_validation_request_mode": "block",
    "rate_limiting_mode": "api_rate_limit",
}
_CHALLENGE_ARMS = (
    "enable_challenge",
    "policy_based_challenge",
    "no_challenge",
    "js_challenge",
    "captcha_challenge",
)
_RATE_THRESHOLD = 20
_MUD_RULE_COUNT = 3
_DOMAIN_COUNT = 2
_OK = 200
_NOT_FOUND = 404
_WAF_BODY = (
    "string:///PCFkb2N0eXBlIGh0bWw+PGh0bWw+PGJvZHk+"
    "UmVxdWVzdCBSZWplY3RlZDwvYm9keT48L2h0bWw+"
)


def _reject(message: str) -> NoReturn:
    """Raise only a local sanitized diagnostic."""
    raise EvidenceError(message)


def _object(raw: Any) -> dict[str, Any]:
    """Narrow an opaque JSON object, rejecting malformed shapes."""
    if not isinstance(raw, dict) or any(not isinstance(key, str) for key in raw):
        _reject("malformed required evidence object")
    return raw


def _field(value: dict[str, Any], key: str) -> dict[str, Any]:
    """Read an object field without substituting for explicit malformed data."""
    return _object(value.get(key, {}))


def _strings(raw: Any) -> list[str]:
    """Narrow an opaque list to JSON strings."""
    if not isinstance(raw, list) or any(not isinstance(item, str) for item in raw):
        _reject("malformed required evidence list")
    return raw


def _name(raw: Any) -> str:
    """Validate a resource name before constructing an exact path."""
    if not isinstance(raw, str) or not _NAME.fullmatch(raw):
        _reject("invalid output resource name")
    return raw


def _domains(raw: Any) -> list[str]:
    """Validate two distinct domain strings without hashability assumptions."""
    domains = _strings(raw)
    if len(domains) != _DOMAIN_COUNT or len(set(domains)) != _DOMAIN_COUNT:
        _reject("two distinct domains required")
    if any(
        not re.fullmatch(r"[a-z0-9.-]+", host) or "." not in host for host in domains
    ):
        _reject("invalid output domain")
    return domains


def _vm(raw: Any) -> Vm:
    """Validate private guest fields and preserve the existing output mapping."""
    vm = _object(raw)
    for key in ("public_ip", "admin_username"):
        if not isinstance(vm.get(key), str) or not vm[key]:
            _reject("invalid output guest metadata")
    if "id" in vm and (not isinstance(vm["id"], str) or not vm["id"]):
        _reject("invalid output guest identity")
    return vm


def outputs(path: str | Path) -> ShowcaseOutputs:
    """Load and validate private Terraform showcase outputs.

    Args:
        path: Local captured outputs JSON file.

    Returns:
        Validated existing showcase output mapping.

    Raises:
        EvidenceError: Required output shape or protection selection is invalid.
        OSError: The local evidence file cannot be read.
        ValueError: The file is not valid JSON.
    """
    return parse_outputs(json.loads(Path(path).read_text(encoding="utf-8")))


def parse_outputs(raw: Any) -> ShowcaseOutputs:
    """Validate raw showcase outputs or the Terraform output envelope.

    Args:
        raw: Unvalidated decoded local JSON.

    Returns:
        Showcase fields, preserving private guest and protection metadata.

    Raises:
        EvidenceError: Required names, domains, guests, or protections are invalid.
    """
    value = _object(raw)
    if "showcase" in value:
        value = _field(_field(value, "showcase"), "value")
    protection = _field(value, "protection")
    if any(
        type(protection.get(key)) is not type(expected)
        or protection.get(key) != expected
        for key, expected in _PROTECTION.items()
    ):
        _reject("showcase protection outputs mismatch")
    return {
        **value,
        "namespace": _name(value.get("namespace")),
        "loadbalancer_name": _name(value.get("loadbalancer_name")),
        "domains": _domains(value.get("domains")),
        "origin": _vm(value.get("origin")),
        "generator": _vm(value.get("generator")),
        "protection": protection,
    }


def _selected(value: Any, arm: str, alternatives: tuple[str, ...] = ()) -> bool:
    """Treat empty object markers as selected, never relying on truthiness."""
    return (
        isinstance(value, dict)
        and isinstance(value.get(arm), dict)
        and all(value.get(other) is None for other in alternatives)
    )


def _reference(raw: Any, namespace: str) -> dict[str, Any]:
    """Join only explicit references in the selected namespace."""
    ref = _object(raw)
    if (
        ref.get("namespace") != namespace
        or not isinstance(ref.get("name"), str)
        or not _NAME.fullmatch(ref["name"])
    ):
        _reject("effective control reference mismatch")
    return ref


def _read_control(
    client: EvidenceReader, namespace: str, kind: str, name: str
) -> dict[str, Any]:
    """Read exactly one selected resource and validate its response envelope."""
    code, raw = client.api(f"/api/config/namespaces/{namespace}/{kind}/{name}")
    if code != _OK:
        _reject("effective control unavailable")
    config = _object(raw)
    metadata = _field(config, "metadata")
    if metadata.get("disable"):
        _reject("effective control disabled")
    # Dependency responses sometimes omit metadata; when present it must join.
    if ("name" in metadata and metadata["name"] != name) or (
        "namespace" in metadata and metadata["namespace"] != namespace
    ):
        _reject("effective control resource scope mismatch")
    return config


def _base_controls(spec: dict[str, Any], domains: list[str]) -> None:
    """Validate LB-level oneOf selections and domain scope."""
    choices = (
        ("enable_api_discovery", ("disable_api_discovery",)),
        ("enable_malicious_user_detection", ("disable_malicious_user_detection",)),
        ("user_identification", ("user_id_client_ip",)),
        ("api_rate_limit", ("disable_rate_limit", "rate_limit")),
        ("api_specification", ("disable_api_definition",)),
        ("app_firewall", ("disable_waf",)),
    )
    if (
        set(_strings(spec.get("domains"))) != set(domains)
        or spec.get("client_side_defense") is not None
        or not all(_selected(spec, arm, others) for arm, others in choices)
    ):
        _reject("effective control configuration mismatch")


def _schema_control(spec: dict[str, Any], namespace: str) -> None:
    """Require referenced schema and active request-body blocking."""
    api = _field(spec, "api_specification")
    _reference(api.get("api_definition"), namespace)
    validation = _field(_field(api, "validation_all_spec_endpoints"), "validation_mode")
    active = _field(validation, "validation_mode_active")
    properties = _strings(active.get("request_validation_properties"))
    if (
        not _selected(validation, "validation_mode_active", ("skip_validation",))
        or not _selected(active, "enforcement_block", ("enforcement_report",))
        or not {"PROPERTY_HTTP_BODY", "PROPERTY_CONTENT_TYPE"}.issubset(properties)
    ):
        _reject("effective control configuration mismatch")


def _challenge_control(spec: dict[str, Any], namespace: str) -> dict[str, Any]:
    """Require exactly one supported challenge with explicit MUD attachment."""
    arms = [key for key in _CHALLENGE_ARMS if spec.get(key) is not None]
    if len(arms) != 1 or arms[0] not in ("enable_challenge", "policy_based_challenge"):
        _reject("effective control configuration mismatch")
    challenge = _field(spec, arms[0])
    if not _selected(
        challenge, "malicious_user_mitigation", ("default_mitigation_settings",)
    ):
        _reject("effective MUD mitigation attachment missing")
    return _reference(challenge.get("malicious_user_mitigation"), namespace)


def _rate_rule(rule: dict[str, Any]) -> bool:
    """Check the first effective endpoint rule, identity bucket and minute limit."""
    method = _field(rule, "api_endpoint_method")
    limiter = _field(rule, "inline_rate_limiter")
    return (
        rule.get("api_endpoint_path") == "/httpbin/anything/rate-limit"
        and method.get("methods") == ["GET"]
        and not method.get("invert_matcher", False)
        and not rule.get("base_path")
        and _selected(rule, "any_domain", ("specific_domain",))
        and _selected(rule, "inline_rate_limiter", ("ref_rate_limiter",))
        and isinstance(limiter.get("threshold"), int)
        and not isinstance(limiter.get("threshold"), bool)
        and limiter.get("threshold") == _RATE_THRESHOLD
        and limiter.get("unit") == "MINUTE"
        and _selected(limiter, "use_http_lb_user_id", ("ref_user_id",))
    )


def _rate_control(spec: dict[str, Any]) -> None:
    """Reject absent or malformed effective endpoint rules."""
    rules = _field(spec, "api_rate_limit").get("api_endpoint_rules")
    if not isinstance(rules, list) or not rules or not _rate_rule(_object(rules[0])):
        _reject("effective API rate limit configuration mismatch")


def _waf_control(config: dict[str, Any]) -> None:
    """Require blocking WAF and the configured custom Forbidden page."""
    spec = _field(config, "spec")
    page = _field(spec, "blocking_page")
    if (
        not _selected(spec, "blocking", ("monitoring",))
        or not _selected(spec, "blocking_page", ("use_default_blocking_page",))
        or page.get("response_code") != "Forbidden"
        or page.get("blocking_page") != _WAF_BODY
    ):
        _reject("effective WAF not blocking with custom Forbidden page")


def _identity_control(config: dict[str, Any]) -> None:
    """Require the single synthetic-user header rule."""
    if _field(config, "spec").get("rules") != [{"http_header_name": "X-MUD-User"}]:
        _reject("effective synthetic-user header identification mismatch")


def _mud_control(config: dict[str, Any]) -> None:
    """Require exactly one temporary-block rule for each threat level."""
    rules = _field(_field(config, "spec"), "mitigation_type").get("rules")
    if not isinstance(rules, list) or len(rules) != _MUD_RULE_COUNT:
        _reject("effective MUD temporary-block policy mismatch")
    counts = [
        sum(
            isinstance(rule, dict)
            and rule.get("threat_level") == {level: {}}
            and rule.get("mitigation_action") == {"block_temporarily": {}}
            for rule in rules
        )
        for level in ("low", "medium", "high")
    ]
    if counts != [1, 1, 1]:
        _reject("effective MUD temporary-block policy mismatch")


def effective(client: EvidenceReader, out: ShowcaseOutputs) -> None:
    """Verify controls using exactly the LB and its three selected references.

    Args:
        client: Scoped read-only evidence reader.
        out: Validated showcase scope and domain inputs.

    Raises:
        EvidenceError: A response, reference, or effective control is invalid.
    """
    namespace = _name(out["namespace"])
    name = _name(out["loadbalancer_name"])
    domains = _domains(out["domains"])
    config = _read_control(client, namespace, "http_loadbalancers", name)
    metadata = _field(config, "metadata")
    if metadata.get("name") != name or metadata.get("namespace") != namespace:
        _reject("effective load balancer scope mismatch")
    spec = _field(config, "spec")
    _base_controls(spec, domains)
    _schema_control(spec, namespace)
    _rate_control(spec)
    mitigation = _challenge_control(spec, namespace)
    waf = _reference(spec.get("app_firewall"), namespace)
    identity = _reference(spec.get("user_identification"), namespace)
    _waf_control(_read_control(client, namespace, "app_firewalls", waf["name"]))
    _identity_control(
        _read_control(client, namespace, "user_identifications", identity["name"])
    )
    _mud_control(
        _read_control(
            client, namespace, "malicious_user_mitigations", mitigation["name"]
        )
    )


def _manifest_shape(raw: Any) -> dict[str, Any]:
    """Validate the complete version-one receipt envelope and known fields."""
    value = _object(raw)
    if (
        not _MANIFEST_REQUIRED.issubset(value)
        or set(value) - _MANIFEST_REQUIRED - _MANIFEST_OPTIONAL
        or not isinstance(value.get("schema_version"), int)
        or isinstance(value.get("schema_version"), bool)
        or value["schema_version"] != 1
    ):
        _reject("owned manifest version and known fields required")
    if (
        not value["azure_owned"]
        or not value["xc_owned"]
        or not value["xc_preserved"]
        or value["azure_preserved"] != []
    ):
        _reject("complete owned and external foundation preservation manifest required")
    return value


def _azure_checks(value: dict[str, Any]) -> tuple[CheckedAzure, ...]:
    """Validate every captured ARM identity and exact advertised API version."""
    sub = value["subscription_id"]
    if not isinstance(sub, str) or not _SUBSCRIPTION.fullmatch(sub):
        _reject("invalid subscription scope")
    owned = _strings(value["azure_owned"])
    preserved = _strings(value["azure_preserved"])
    versions = _object(value["azure_api_versions"])
    identities = owned + preserved
    if len(set(identities)) != len(identities) or set(versions) != set(identities):
        _reject("manifest Azure identities or API versions mismatch")
    checks = []
    for rid in identities:
        if (
            not _ARM_ID.fullmatch(rid)
            or not _ARM_RESOURCE.fullmatch(rid)
            or ".." in rid
            or not rid.lower().startswith(
                "/subscriptions/" + sub.lower() + "/resourcegroups/"
            )
        ):
            _reject("manifest Azure scope mismatch")
        version = versions[rid]
        if not isinstance(version, str) or not _API_VERSION.fullmatch(version):
            _reject("manifest Azure API version required")
        checks.append(CheckedAzure(sub, rid, version, rid in preserved))
    return tuple(checks)


def _xc_group(raw: Any, *, present: bool) -> list[CheckedXC]:
    """Validate all exact captured XC paths and UIDs before any reads."""
    if not isinstance(raw, list):
        _reject("malformed required evidence list")
    checks = []
    for entry in raw:
        item = _object(entry)
        if set(item) != {"path", "uid"}:
            _reject("exact captured XC object identity required")
        path, uid = item["path"], item["uid"]
        if (
            not isinstance(path, str)
            or not (
                _XC_OBJECT.fullmatch(path)
                or (present and _XC_NAMESPACE.fullmatch(path))
            )
            or not isinstance(uid, str)
            or not uid.strip()
            or any(character.isspace() for character in uid)
        ):
            _reject("exact captured XC object identity required")
        if _XC_OBJECT.fullmatch(path) and path.split("/")[5] not in _XC_COLLECTIONS:
            _reject("unknown captured XC collection")
        checks.append(CheckedXC(path, uid, present))
    return checks


def _xc_checks(value: dict[str, Any]) -> tuple[CheckedXC, ...]:
    """Reject duplicate or overlapping XC scopes and optional namespace drift."""
    checks = _xc_group(value["xc_owned"], present=False) + _xc_group(
        value["xc_preserved"], present=True
    )
    paths = [check.path for check in checks]
    if len(set(paths)) != len(paths):
        _reject("owned and preserved scopes overlap or duplicate")
    foundations = [check for check in checks if _XC_NAMESPACE.fullmatch(check.path)]
    if len(foundations) != 1:
        _reject("exact preserved namespace identity required")
    namespace = foundations[0].path.split("/")[4]
    if any(check.path.split("/")[4] != namespace for check in checks) or (
        "namespace" in value and _name(value["namespace"]) != namespace
    ):
        _reject("manifest XC namespace scope mismatch")
    return tuple(checks)


def _receipt_extras(value: dict[str, Any]) -> None:
    """Validate known optional receipt ledgers without remote adoption."""
    if "persistent_resource_ids" in value:
        persistent = _object(value["persistent_resource_ids"])
        identities = _strings(list(persistent.values()))
        if not identities or len(identities) != len(set(identities)):
            _reject("malformed persistent resource ledger")
    if "owned_resources" in value:
        resources = value["owned_resources"]
        if not isinstance(resources, list) or not resources:
            _reject("malformed owned resource ledger")
        for raw in resources:
            resource = _object(raw)
            if set(resource) != {"address", "type", "id"} or any(
                not isinstance(item, str) or not item for item in resource.values()
            ):
                _reject("malformed owned resource ledger")


def validate_manifest(raw: Any) -> CheckedManifest:
    """Validate all receipt entries before permitting exact absence reads.

    Args:
        raw: Unvalidated local version-one captured ownership receipt.

    Returns:
        Immutable exact ARM and XC identity checks with presence expectations.

    Raises:
        EvidenceError: Any field, identity, version or scope is malformed.
    """
    value = _manifest_shape(raw)
    azure = _azure_checks(value)
    xc = _xc_checks(value)
    _receipt_extras(value)
    return CheckedManifest(azure, xc)


def _xc_outcome(client: EvidenceReader, check: CheckedXC) -> bool:
    """Compare exact presence and UID without accepting unknown HTTP statuses."""
    code, response = client.api(check.path)
    if code not in (_OK, _NOT_FOUND):
        _reject("captured XC identity read failed")
    if check.present and code == _OK:
        return _field(_object(response), "system_metadata").get("uid") == check.uid
    return not check.present and code == _NOT_FOUND


def absence(client: EvidenceReader, manifest: Any) -> bool:
    """Read absence and preservation only after complete manifest validation.

    Args:
        client: Scoped reader whose ARM 404 handling rejects unknown failures.
        manifest: Raw captured receipt; validation is mandatory on every call.

    Returns:
        Whether every owned identity is absent and preserved identity is unchanged.

    Raises:
        EvidenceError: The receipt or any remote response is malformed or unknown.
    """
    checked = validate_manifest(manifest)
    outcomes = []
    for item in checked.azure:
        actual = client.azure_exists(item.sub, item.resource_id, item.api_version)
        if not isinstance(actual, bool):
            _reject("captured Azure identity read failed")
        outcomes.append(actual is item.present)
    outcomes.extend(_xc_outcome(client, item) for item in checked.xc)
    return all(outcomes)
