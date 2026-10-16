"""Readback and request-bound AI risk evidence; analytics scores are insufficient."""

from __future__ import annotations

import copy
import re

from demo_verify_evidence import rate_origin
from demo_verify_types import EvidenceError
from showcase_walkthrough_evidence import matched

SUPPORTED = {
    "ATTACK_TYPE_SQL_INJECTION",
    "ATTACK_TYPE_CROSS_SITE_SCRIPTING",
    "ATTACK_TYPE_COMMAND_EXECUTION",
    "ATTACK_TYPE_PATH_TRAVERSAL",
    "ATTACK_TYPE_LDAP_INJECTION",
    "ATTACK_TYPE_XPATH_INJECTION",
    "ATTACK_TYPE_SERVER_SIDE_CODE_INJECTION",
}
RISK_LEVELS = {"high", "medium", "low", "false positive"}
FALSE_POSITIVE_REASON = (
    "The AI has determined that the triggered signatures are false positives"
)
FORBIDDEN, SUCCESS = 403, 200


def require(condition: bool, message: str) -> None:
    """Reject incomplete evidence without accepting a default assumption."""
    if not condition:
        raise EvidenceError(message)


def pair_configuration(configs: dict) -> None:
    """Require equal effective controls and the exact AI high-risk selection."""
    firewalls, listeners = {}, {}
    for phase in ("before", "after"):
        endpoint = configs[phase]
        firewall = copy.deepcopy(endpoint["firewall"]["spec"])
        listener = copy.deepcopy(endpoint["listener"]["spec"])
        require(
            firewall.get("blocking") == {} and firewall.get("monitoring") is None,
            "AI pair must retain blocking on both hosts",
        )
        selection = firewall.get("detection_settings", {}).get(
            "signature_selection_setting", {}
        )
        require(
            "high_medium_accuracy_signatures" in selection
            and "only_high_accuracy_signatures" not in selection
            and "high_medium_low_accuracy_signatures" not in selection
            and firewall.get("default_detection_settings") is None,
            "AI pair must retain identical high/medium accuracy signatures",
        )
        if phase == "before":
            require(
                firewall.get("disable_ai_enhancements") == {}
                and firewall.get("enable_ai_enhancements") is None,
                "traditional AI disable readback missing",
            )
        else:
            require(
                firewall.get("enable_ai_enhancements")
                == {"mitigate_high_risk_action": {}}
                and firewall.get("disable_ai_enhancements") is None,
                "exact enabled AI high-risk readback missing",
            )
        for key in ("enable_ai_enhancements", "disable_ai_enhancements"):
            firewall.pop(key, None)
        firewalls[phase] = firewall
        require(
            all(
                listener.get(key) is None
                for key in (
                    "enable_malicious_user_detection",
                    "enable_challenge",
                    "api_rate_limit",
                    "api_protection_rules",
                    "api_specification",
                )
            )
            and listener.get("disable_malicious_user_detection") == {}
            and listener.get("no_challenge") == {},
            "unrelated enforcement can explain AI comparison",
        )
        require(
            listener.get("app_firewall", {}).get("name")
            == endpoint["names"]["app_firewall_name"],
            "AI firewall reference mismatch",
        )
        require(
            listener.get("user_identification", {}).get("name")
            == endpoint["names"]["user_identification_name"],
            "AI identity reference mismatch",
        )
        require(
            endpoint["identity"]["spec"].get("rules")
            == [{"http_header_name": "X-MUD-User"}],
            "AI synthetic identity scope mismatch",
        )
        pools = listener.get("default_route_pools")
        require(
            isinstance(pools, list) and len(pools) == 1 and isinstance(pools[0], dict),
            "AI origin routing identity missing",
        )
        require(
            pools[0].get("pool")
            == {
                "name": endpoint["names"]["origin_pool_name"],
                "namespace": endpoint["names"]["namespace"],
            },
            "AI origin pool does not match Terraform output",
        )
        for key in ("app_firewall", "user_identification", "domains"):
            listener.pop(key, None)
        listeners[phase] = listener
    require(
        firewalls["before"] == firewalls["after"],
        "AI pair has unequal effective signature controls",
    )
    require(
        listeners["before"] == listeners["after"],
        "AI pair has unequal effective routing or enforcement",
    )


def risk_evidence(
    events: list[dict], access: dict, probe: dict, namespace: str, lb: str
) -> dict:
    """Join actual risk classification and AI reasons to enabled supported signatures."""
    candidates = [event for event in events if event.get("req_id") == access["req_id"]]
    event = matched(candidates, probe, namespace, lb)
    require(event is not None, "exact AI request security event missing or ambiguous")
    if event is None:
        message = "exact AI event missing"
        raise EvidenceError(message)
    require(
        event.get("sec_event_type") == "waf_sec_event"
        and event.get("sec_event_name") == "WAF"
        and event.get("app_firewall_name") == lb + "-waf",
        "AI request lacks exact WAF policy attribution",
    )
    signatures = event.get("signatures", [])
    enabled = {
        str(sig.get("id"))
        for sig in signatures
        if isinstance(sig, dict)
        and sig.get("state") == "Enabled"
        and sig.get("attack_type") in SUPPORTED
        and sig.get("accuracy") in {"high_accuracy", "medium_accuracy"}
        and str(sig.get("id", "")).isdigit()
    }
    risk = event.get("req_risk")
    reasons = event.get("req_risk_reasons")
    require(
        bool(enabled) and risk in RISK_LEVELS,
        "enabled supported signature or AI risk classification missing",
    )
    require(
        isinstance(reasons, list),
        "AI risk reasons missing; analytics score is insufficient",
    )
    bound_reasons = [
        reason
        for reason in reasons
        if isinstance(reason, str)
        and reason.startswith("The AI has ")
        and any(
            sig in enabled for sig in re.findall(r"attack signature ([0-9]+)", reason)
        )
    ]
    if risk == "false positive":
        bound_reasons = [
            reason for reason in reasons if reason == FALSE_POSITIVE_REASON
        ]
    require(
        bool(bound_reasons),
        "AI reason does not identify an enabled supported signature",
    )
    return {
        "req_id": access["req_id"],
        "risk": risk,
        "action": event.get("action"),
        "recommended_action": event.get("recommended_action"),
        "signature_ids": sorted(enabled),
        "ai_reasons": bound_reasons,
    }


def evaluate_phase(
    records: list[dict],
    events: list[dict],
    probes: list[dict],
    endpoint: dict,
    protected: bool,
) -> dict:
    """Accept legitimate echoes and attributable decisions, never generic denials."""
    evidence = {}
    for probe in probes:
        access = matched(
            records, probe, endpoint["namespace"], endpoint["loadbalancer_name"]
        )
        require(access is not None, "AI request access log missing or ambiguous")
        if access is None:
            message = "exact AI access log missing"
            raise EvidenceError(message)
        if probe["status"] == SUCCESS:
            rate_origin(
                probe["status"],
                probe["body"],
                probe["host"],
                probe["request_target"],
                probe["user"],
            )
            require(
                probe["body"].get("args", {}).get("input") == probe["input"],
                "AI fixture origin echo mismatch",
            )
        else:
            require(
                probe["status"] == FORBIDDEN,
                "AI comparison transport or unexpected response failure",
            )
        if probe["kind"] == "benign":
            require(
                probe["status"] == SUCCESS,
                "legitimate AI comparison request did not succeed",
            )
            evidence[probe["label"]] = {"status": SUCCESS, "req_id": access["req_id"]}
            continue
        risk = risk_evidence(
            events, access, probe, endpoint["namespace"], endpoint["loadbalancer_name"]
        )
        if protected:
            expected = "block" if risk["risk"] == "high" else "allow"
            require(
                risk["recommended_action"] == expected and risk["action"] == expected,
                "AI risk/action attribution mismatch",
            )
            require(
                probe["status"] == (FORBIDDEN if expected == "block" else SUCCESS),
                "AI high-risk enforcement response mismatch",
            )
        else:
            require(
                probe["status"] == FORBIDDEN and risk["action"] == "block",
                "traditional enabled signature control did not block",
            )
        evidence[probe["label"]] = {
            **risk,
            "status": probe["status"],
            "input": probe["input"],
        }
    return evidence


def require_control_difference(before: dict, after: dict) -> None:
    """A shared 403 cannot prove AI enforcement caused the decision."""
    require(
        any(
            row.get("risk") == "high" and row.get("status") == FORBIDDEN
            for row in after.values()
        ),
        "high-risk AI mitigation evidence missing",
    )
    require(
        any(
            row.get("risk") in {"medium", "low"}
            and row.get("status") == SUCCESS
            and before.get(label, {}).get("status") == FORBIDDEN
            and before[label].get("input") == row.get("input")
            for label, row in after.items()
        ),
        "AI enforcement control attribution incomplete: matching 403 responses alone are insufficient",
    )
