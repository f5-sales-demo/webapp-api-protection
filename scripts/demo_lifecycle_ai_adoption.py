"""Reviewed import of the six manually staged AI WAF comparison objects."""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import TYPE_CHECKING

from demo_lifecycle_state import Blocked

if TYPE_CHECKING:
    from demo_lifecycle_state import Context
    from demo_lifecycle_terraform import Terraform

LABELS = {
    "demo-owner": "terraform-ownership-571",
    "demo-use-case": "ai-waf",
    "demo-staging": "meeting-607",
}
OWNERS = {
    f'module.use_case["ai-waf"].{kind}.this["{phase}"]': (
        collection,
        "ai-waf-" + phase + suffix,
    )
    for phase in ("before", "after")
    for kind, collection, suffix in (
        ("xcsh_app_firewall", "app_firewalls", "-waf"),
        ("xcsh_user_identification", "user_identifications", "-user"),
        ("xcsh_http_loadbalancer", "http_loadbalancers", ""),
    )
}
# These API readback fields describe operational state, not writable policy.
OPERATIONAL = {
    "state",
    "host_name",
    "auto_cert_info",
    "cert_state",
    "dns_info",
    "internet_vip_info",
    "downstream_tls_certificate_expiration_timestamps",
}


def policy_digest(obj: dict, collection: str) -> str:
    """Bind all writable controls and route UUIDs; retain raw readbacks privately."""
    spec = obj.get("spec")
    if not isinstance(spec, dict):
        message = "AI adoption policy readback missing"
        raise Blocked(message)
    managed = {
        key: value
        for key, value in spec.items()
        if collection != "http_loadbalancers" or key not in OPERATIONAL
    }
    return hashlib.sha256(json.dumps(managed, sort_keys=True).encode()).hexdigest()


def validate_ai_imports(context: Context, terraform: Terraform, entries: list) -> None:
    """Validate the complete identity/ownership/policy set before the first import."""
    if not entries:
        return
    if len(entries) != len(OWNERS) or {row.get("address") for row in entries} != set(
        OWNERS
    ):
        message = "AI adoption requires all six reviewed declared owners"
        raise Blocked(message)
    namespace = context.settings.scope["namespace"]
    listings = {}
    for entry in entries:
        collection, name = OWNERS[entry["address"]]
        try:
            uid = str(uuid.UUID(entry["uid"]))
        except (KeyError, ValueError, TypeError, AttributeError) as exc:
            message = "AI adoption exact live UID missing"
            raise Blocked(message) from exc
        if (
            entry.get("reviewed") is not True
            or entry.get("id") != namespace + "/" + name
            or entry.get("labels") != LABELS
            or entry.get("collection") != collection
            or entry.get("uid") != uid
        ):
            message = "AI adoption mapping or ownership review differs"
            raise Blocked(message)
        path = "/api/config/namespaces/" + namespace + "/" + collection
        if collection not in listings:
            listing = terraform.runtime.xc(path)
            if not isinstance(listing, dict) or not isinstance(
                listing.get("items"), list
            ):
                message = "AI adoption live UID inventory unavailable"
                raise Blocked(message)
            listings[collection] = listing["items"]
        matches = [
            row
            for row in listings[collection]
            if row.get("name") == name and row.get("namespace") == namespace
        ]
        if len(matches) != 1 or matches[0].get("uid") != uid:
            message = "AI adoption live identity changed"
            raise Blocked(message)
        live = terraform.runtime.xc(path + "/" + name)
        metadata = live.get("metadata", {}) if isinstance(live, dict) else {}
        labels = metadata.get("labels", {})
        expected_labels = LABELS.copy()
        if collection == "http_loadbalancers" and "ves.io/app_type" in labels:
            # XC owns this derived discovery label; verify its exact resource identity.
            expected_labels["ves.io/app_type"] = "ves-io-" + namespace + "-" + name
        if (
            metadata.get("name") != name
            or metadata.get("namespace") != namespace
            or labels != expected_labels
            or policy_digest(live, collection) != entry.get("policy_sha256")
        ):
            message = "AI adoption live ownership or reviewed policy changed"
            raise Blocked(message)
