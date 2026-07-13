#!/usr/bin/env python3
"""Generate the WAF (app_firewall) coverage matrix as a JSON manifest.

Coverage model (see docs/superpowers/specs/2026-07-13-waf-exhaustive-coverage-design.md):
  * all-pairs (pairwise) over every app_firewall oneof-group dimension, so every
    pair of option-values co-occurs in at least one variant (AETG-style greedy);
  * PLUS an explicit case per enum value (bot actions, AI risk action);
  * PLUS an explicit case per list min/max bound (response codes, disabled
    violation/attack types);
  * PLUS one maximal all-on variant.

Deterministic: dimension/value ordering is fixed and the greedy tie-break is
lowest-index, so the same manifest is produced on every run (no RNG).

Output: JSON array of {"name": str, "vars": {tfvar: value}} to stdout.
Payload vars (lists, actions, periods) are attached only when the selecting arm
is active, so each variant is a valid, minimal config.
"""

import itertools
import json
import sys
from collections.abc import Mapping
from pathlib import Path

# Core pairwise dimensions: oneof-group arm selectors. Detection sub-dimensions
# are only meaningful when waf_detection_mode=custom; when it is "default" the
# module ignores them (harmless no-ops), so pairwise still covers the custom space.
# Custom bot protection (waf_bot_mode/waf_detection_bot_mode = "custom") is
# intentionally NOT in the live matrix: it requires the tenant Bot Defense add-on,
# and without it the API silently normalizes custom bot actions back to
# default_bot_setting (verified live -> guaranteed round-trip import drift). The
# module still renders it (plan-tested) for Bot-Defense-entitled tenants; here we
# exercise only the omit/default arms so the live matrix is idempotent + import-clean.
DIMENSIONS = {
    "waf_mode": ["blocking", "monitoring"],
    "waf_allowed_response_codes_mode": ["omit", "list"],
    "waf_blocking_page_mode": ["omit", "custom"],
    "waf_anonymization_mode": ["omit", "disable"],
    "waf_ai_mode": ["omit", "enable"],
    "waf_detection_mode": ["default", "custom"],
    "waf_violation_mode": ["default", "custom"],
    "waf_staging_mode": ["disable", "new", "new_and_updated"],
    "waf_suppression": ["enable", "disable"],
    "waf_threat_campaigns": ["enable", "disable"],
    "waf_signature_accuracy": ["only_high", "high_medium", "high_medium_low"],
    "waf_attack_type_mode": ["default", "custom"],
}

VIOLATION_TYPES = [
    "VIOL_NONE",
    "VIOL_FILETYPE",
    "VIOL_METHOD",
    "VIOL_MANDATORY_HEADER",
    "VIOL_HTTP_RESPONSE_STATUS",
    "VIOL_REQUEST_MAX_LENGTH",
    "VIOL_FILE_UPLOAD",
    "VIOL_FILE_UPLOAD_IN_BODY",
    "VIOL_XML_MALFORMED",
    "VIOL_JSON_MALFORMED",
    "VIOL_ASM_COOKIE_MODIFIED",
    "VIOL_HTTP_PROTOCOL_MULTIPLE_HOST_HEADERS",
    "VIOL_HTTP_PROTOCOL_BAD_HOST_HEADER_VALUE",
    "VIOL_HTTP_PROTOCOL_UNPARSABLE_REQUEST_CONTENT",
    "VIOL_HTTP_PROTOCOL_NULL_IN_REQUEST",
    "VIOL_HTTP_PROTOCOL_BAD_HTTP_VERSION",
    "VIOL_HTTP_PROTOCOL_CRLF_CHARACTERS_BEFORE_REQUEST_START",
    "VIOL_HTTP_PROTOCOL_NO_HOST_HEADER_IN_HTTP_1_1_REQUEST",
    "VIOL_HTTP_PROTOCOL_BAD_MULTIPART_PARAMETERS_PARSING",
    "VIOL_HTTP_PROTOCOL_SEVERAL_CONTENT_LENGTH_HEADERS",
    "VIOL_HTTP_PROTOCOL_CONTENT_LENGTH_SHOULD_BE_A_POSITIVE_NUMBER",
    "VIOL_EVASION_DIRECTORY_TRAVERSALS",
    "VIOL_MALFORMED_REQUEST",
    "VIOL_EVASION_MULTIPLE_DECODING",
    "VIOL_DATA_GUARD",
    "VIOL_EVASION_APACHE_WHITESPACE",
    "VIOL_COOKIE_MODIFIED",
    "VIOL_EVASION_IIS_UNICODE_CODEPOINTS",
    "VIOL_EVASION_IIS_BACKSLASHES",
    "VIOL_EVASION_PERCENT_U_DECODING",
    "VIOL_EVASION_BARE_BYTE_DECODING",
    "VIOL_EVASION_BAD_UNESCAPE",
    "VIOL_HTTP_PROTOCOL_BAD_MULTIPART_FORMDATA_REQUEST_PARSING",
    "VIOL_HTTP_PROTOCOL_BODY_IN_GET_OR_HEAD_REQUEST",
    "VIOL_HTTP_PROTOCOL_HIGH_ASCII_CHARACTERS_IN_HEADERS",
    "VIOL_ENCODING",
    "VIOL_COOKIE_MALFORMED",
    "VIOL_GRAPHQL_FORMAT",
    "VIOL_GRAPHQL_MALFORMED",
    "VIOL_GRAPHQL_INTROSPECTION_QUERY",
]  # 40 total (= maxItems)

ATTACK_TYPES = [
    "ATTACK_TYPE_NONE",
    "ATTACK_TYPE_NON_BROWSER_CLIENT",
    "ATTACK_TYPE_OTHER_APPLICATION_ATTACKS",
    "ATTACK_TYPE_TROJAN_BACKDOOR_SPYWARE",
    "ATTACK_TYPE_DETECTION_EVASION",
    "ATTACK_TYPE_VULNERABILITY_SCAN",
    "ATTACK_TYPE_ABUSE_OF_FUNCTIONALITY",
    "ATTACK_TYPE_AUTHENTICATION_AUTHORIZATION_ATTACKS",
    "ATTACK_TYPE_BUFFER_OVERFLOW",
    "ATTACK_TYPE_PREDICTABLE_RESOURCE_LOCATION",
    "ATTACK_TYPE_INFORMATION_LEAKAGE",
    "ATTACK_TYPE_DIRECTORY_INDEXING",
    "ATTACK_TYPE_PATH_TRAVERSAL",
    "ATTACK_TYPE_XPATH_INJECTION",
    "ATTACK_TYPE_LDAP_INJECTION",
    "ATTACK_TYPE_SERVER_SIDE_CODE_INJECTION",
    "ATTACK_TYPE_COMMAND_EXECUTION",
    "ATTACK_TYPE_SQL_INJECTION",
    "ATTACK_TYPE_CROSS_SITE_SCRIPTING",
    "ATTACK_TYPE_DENIAL_OF_SERVICE",
    "ATTACK_TYPE_HTTP_PARSER_ATTACK",
    "ATTACK_TYPE_SESSION_HIJACKING",
]  # first 22 of 27 (= maxItems 22)


def all_pairs(dims: dict[str, list[str]]) -> list[dict[str, str]]:
    """Return AETG-style greedy all-pairs rows ({dim: value})."""
    names = list(dims)
    # every unordered pair of (dim_i, val_i)-(dim_j, val_j) that must co-occur
    uncovered = set()
    for i, j in itertools.combinations(range(len(names)), 2):
        for vi in dims[names[i]]:
            for vj in dims[names[j]]:
                uncovered.add((i, vi, j, vj))

    rows = []
    while uncovered:
        # Seed the row from a still-uncovered pair so every row covers >=1 new
        # pair (guarantees termination; a purely greedy row can cover 0 new pairs
        # and, with a deterministic tie-break, loop forever). Take the smallest
        # uncovered tuple for determinism.
        si, sv, sj, sv2 = min(uncovered)
        row = {si: sv, sj: sv2}
        # fill remaining dimensions greedily (fixed order, lowest-index tie-break)
        for idx in range(len(names)):
            if idx in row:
                continue
            best_val, best_gain = dims[names[idx]][0], -1
            for val in dims[names[idx]]:
                gain = 0
                for pidx, pval in row.items():
                    a, b = sorted([(pidx, pval), (idx, val)])
                    if (a[0], a[1], b[0], b[1]) in uncovered:
                        gain += 1
                if gain > best_gain:
                    best_gain, best_val = gain, val
            row[idx] = best_val
        # retire the pairs this row covers
        for i, j in itertools.combinations(sorted(row), 2):
            uncovered.discard((i, row[i], j, row[j]))
        rows.append({names[k]: v for k, v in row.items()})
    return rows


def payloads(v: Mapping[str, object]) -> dict[str, object]:
    """Attach payload vars required by the active arms in variant v."""
    out: dict[str, object] = dict(v)
    if v.get("waf_allowed_response_codes_mode") == "list":
        out["waf_allowed_response_codes"] = [200, 204, 301, 302, 403]
    if v.get("waf_ai_mode") == "enable":
        out.setdefault("waf_ai_risk_action", "high")
    if (
        v.get("waf_detection_mode") == "custom"
        and v.get("waf_violation_mode") == "custom"
    ):
        out["waf_disabled_violation_types"] = [
            "VIOL_EVASION_DIRECTORY_TRAVERSALS",
            "VIOL_DATA_GUARD",
        ]
    if v.get("waf_staging_mode") in ("new", "new_and_updated"):
        out.setdefault("waf_staging_period", 7)
    if (
        v.get("waf_detection_mode") == "custom"
        and v.get("waf_attack_type_mode") == "custom"
    ):
        out["waf_disabled_attack_types"] = [
            "ATTACK_TYPE_SQL_INJECTION",
            "ATTACK_TYPE_CROSS_SITE_SCRIPTING",
        ]
    return out


def canonical() -> dict[str, object]:
    """Return the live-canonical WAF end state (blocking + all server defaults)."""
    return {"waf_mode": "blocking"}


def build() -> list[dict[str, object]]:
    """Build the full ordered variant manifest (all-pairs + enum + bounds + maximal)."""
    variants: list[dict[str, object]] = []

    # 1) all-pairs core
    for i, row in enumerate(all_pairs(DIMENSIONS)):
        variants.append({"name": f"pair-{i:03d}", "vars": payloads(row)})

    # 2) explicit enum cases (bot-action enums are plan-tested only — see DIMENSIONS
    # note; they require Bot Defense and are excluded from the live matrix).
    variants.extend(
        {
            "name": f"enum-ai-{ra}",
            "vars": {
                "waf_mode": "blocking",
                "waf_ai_mode": "enable",
                "waf_ai_risk_action": ra,
            },
        }
        for ra in ("high", "high_medium")
    )

    # 3) explicit min/max bounds
    variants.append(
        {
            "name": "bound-rc-min",
            "vars": {
                "waf_mode": "blocking",
                "waf_allowed_response_codes_mode": "list",
                "waf_allowed_response_codes": [200],
            },
        }
    )
    variants.append(
        {
            "name": "bound-rc-max",
            "vars": {
                "waf_mode": "blocking",
                "waf_allowed_response_codes_mode": "list",
                "waf_allowed_response_codes": list(range(200, 248)),
            },
        }
    )
    variants.append(
        {
            "name": "bound-viol-max",
            "vars": {
                "waf_mode": "blocking",
                "waf_detection_mode": "custom",
                "waf_violation_mode": "custom",
                "waf_disabled_violation_types": VIOLATION_TYPES,
                "waf_staging_mode": "disable",
                "waf_suppression": "enable",
                "waf_threat_campaigns": "enable",
                "waf_detection_bot_mode": "default",
                "waf_signature_accuracy": "high_medium",
                "waf_attack_type_mode": "default",
            },
        }
    )
    variants.append(
        {
            "name": "bound-attack-max",
            "vars": {
                "waf_mode": "blocking",
                "waf_detection_mode": "custom",
                "waf_violation_mode": "default",
                "waf_staging_mode": "disable",
                "waf_suppression": "enable",
                "waf_threat_campaigns": "enable",
                "waf_detection_bot_mode": "default",
                "waf_signature_accuracy": "high_medium",
                "waf_attack_type_mode": "custom",
                "waf_disabled_attack_types": ATTACK_TYPES,
            },
        }
    )

    # 4) maximal all-on. staging is kept at "disable" here: the F5 XC API rejects
    # signature staging (stage_new/stage_new_and_updated) combined with the rest of
    # the maximal detection_settings (violation-custom + attack-custom +
    # high_medium_low accuracy) with 400 BAD_REQUEST "Invalid request parameters"
    # (bisected live). Staging is independently exercised by the pairwise rows, so
    # the maximal stays a valid all-on rather than an invalid combination.
    variants.append(
        {
            "name": "maximal",
            "vars": {
                "waf_mode": "monitoring",
                "waf_allowed_response_codes_mode": "list",
                "waf_allowed_response_codes": [200, 204, 301, 302, 403],
                "waf_blocking_page_mode": "custom",
                "waf_anonymization_mode": "disable",
                "waf_ai_mode": "enable",
                "waf_ai_risk_action": "high_medium",
                "waf_detection_mode": "custom",
                "waf_violation_mode": "custom",
                "waf_disabled_violation_types": VIOLATION_TYPES,
                "waf_staging_mode": "disable",
                "waf_suppression": "disable",
                "waf_threat_campaigns": "disable",
                "waf_signature_accuracy": "high_medium_low",
                "waf_attack_type_mode": "custom",
                "waf_disabled_attack_types": ATTACK_TYPES,
            },
        }
    )

    # 5) restore canonical last
    variants.append({"name": "canonical-restore", "vars": canonical()})
    return variants


def emit(directory: str) -> int:
    """Write one <NNN>-<name>.tfvars.json per variant plus manifest.txt (NNN name)."""
    out_dir = Path(directory)
    out_dir.mkdir(parents=True, exist_ok=True)
    for existing in out_dir.iterdir():
        if existing.name.endswith(".tfvars.json") or existing.name == "manifest.txt":
            existing.unlink()
    variants = build()
    named = [(f"{i:03d}-{v['name']}.tfvars.json", v) for i, v in enumerate(variants)]
    for fname, v in named:
        (out_dir / fname).write_text(json.dumps(v["vars"], indent=2) + "\n")
    lines = [f"{i:03d} {v['name']} {fname}" for i, (fname, v) in enumerate(named)]
    (out_dir / "manifest.txt").write_text("\n".join(lines) + "\n")
    return len(variants)


def main(argv: list[str]) -> None:
    """CLI: --count prints the variant count, --emit <dir> writes files, else JSON to stdout."""
    match argv[1:]:
        case ["--count"]:
            sys.stdout.write(f"{len(build())}\n")
        case ["--emit", directory]:
            sys.stdout.write(f"{emit(directory)}\n")
        case _:
            json.dump(build(), sys.stdout, indent=2)
            sys.stdout.write("\n")


if __name__ == "__main__":
    main(sys.argv)
