"""XC capacity checks use actual fresh plan creations, including clean deployments."""

from typing import Any, cast

from demo_lifecycle_state import Blocked

QUOTA_TYPES = {
    "xcsh_http_loadbalancer": "HTTP Load Balancer",
    "xcsh_app_firewall": "Application Firewall",
    "xcsh_api_definition": "API Definition",
    "xcsh_user_identification": "User Identification",
    "xcsh_malicious_user_mitigation": "Malicious User Mitigation",
    "xcsh_healthcheck": "Healthcheck",
    "xcsh_origin_pool": "origin_pool",
    "xcsh_swagger_object": "Stored Object",
}


def creation_needs(plan: dict) -> dict[str, int]:
    """Count only resources that will be created; adopted/no-op objects consume no extra slot."""
    needs = dict.fromkeys((*QUOTA_TYPES.values(), "TLS Certificate"), 0)
    for row in plan.get("resource_changes", []):
        change = row["change"]
        if row.get("mode") == "data" or "create" not in change["actions"]:
            continue
        category = QUOTA_TYPES.get(row["type"])
        if category is None:
            continue
        needs[category] += 1
        if row["type"] == "xcsh_http_loadbalancer":
            after = change.get("after") or {}
            unknown = change.get("after_unknown") or {}
            certificate = after.get("https_auto_cert")
            unresolved = unknown.get("https_auto_cert")
            if unresolved is True or (unresolved and not isinstance(certificate, dict)):
                message = "planned automatic certificate capacity is unknown"
                raise Blocked(message)
            if certificate is not None:
                needs["TLS Certificate"] += 1
    return needs


def require_capacity(runtime: Any, needs: dict[str, int] | None = None) -> None:
    """Check typed limits before mutation; never credit a deletion not yet completed."""
    if needs is None:
        needs = dict.fromkeys((*QUOTA_TYPES.values(), "TLS Certificate"), 0)
    response = runtime.xc("/api/web/namespaces/system/quota/usage")
    usage = response.get("quota_usage") if isinstance(response, dict) else None
    if not isinstance(usage, dict):
        message = "XC quota usage unavailable"
        raise Blocked(message)
    for category, needed in needs.items():
        row = usage.get(category)
        limit = row.get("limit") if isinstance(row, dict) else None
        used = row.get("usage") if isinstance(row, dict) else None
        maximum = limit.get("maximum") if isinstance(limit, dict) else None
        current = used.get("current") if isinstance(used, dict) else None
        if any(
            isinstance(value, bool) or not isinstance(value, int)
            for value in (maximum, current, needed)
        ):
            message = "unavailable XC capacity: " + category
            raise Blocked(message)
        maximum, current = cast("int", maximum), cast("int", current)
        if current < 0 or maximum < -1 or needed < 0:
            message = "unavailable XC capacity: " + category
            raise Blocked(message)
        if maximum != -1 and current + needed > maximum:
            message = "insufficient or unavailable XC capacity: " + category
            raise Blocked(message)
