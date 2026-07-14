#!/usr/bin/env python3
"""Generate the API Protection (SP3) coverage matrix.

Coverage model (see docs/superpowers/specs/2026-07-14-sp3-api-protection-design.md
and docs/superpowers/plans/sp3-findings.md):
  * all-pairs (pairwise, AETG greedy) over the SP3 capability dimensions, so every
    pair of option-values co-occurs in at least one variant;
  * PLUS the canonical restore end state (all SP3 features off).

Pairwise dimensions:
  rate_limit      disable | rate_limit  -> rate_limit_choice (inline request limiter)
  client_matcher  any | ip_prefix | ip_threat  (applied to api_protection_rules)
  sensitive_data  default | custom  (custom => standalone xcsh_sensitive_data_policy)
  data_guard      off | on
  api_protection  off | allow | deny
  validation      off | custom_list  (on => api_definition specification + custom_list;
                  SP2 already matrix-covered validation_disabled/all_spec_endpoints)

payloads() reconciles the module's constraints so every emitted variant is a valid
root config, and dedups byte-identical payloads (slow live matrix). Secret-free —
no injection needed (unlike SP2's access_token). Deterministic (no RNG).

Output: JSON array of {"name", "vars"} to stdout, or files via --emit.
"""

import itertools
import json
import sys
from collections.abc import Mapping
from pathlib import Path

DIMENSIONS = {
    "rate_limit": ["disable", "rate_limit"],
    "client_matcher": ["any", "ip_prefix", "ip_threat"],
    "sensitive_data": ["default", "custom"],
    "data_guard": ["off", "on"],
    "api_protection": ["off", "allow", "deny"],
    "validation": ["off", "custom_list"],
}


def _best_value(
    values: list[str],
    idx: int,
    row: dict[int, str],
    uncovered: set[tuple[int, str, int, str]],
) -> str:
    """Pick the value for dimension idx covering the most still-uncovered pairs."""
    best_val, best_gain = values[0], -1
    for val in values:
        gain = 0
        for pidx, pval in row.items():
            a, b = sorted([(pidx, pval), (idx, val)])
            if (a[0], a[1], b[0], b[1]) in uncovered:
                gain += 1
        if gain > best_gain:
            best_gain, best_val = gain, val
    return best_val


def all_pairs(dims: dict[str, list[str]]) -> list[dict[str, str]]:
    """Return AETG-style greedy all-pairs rows ({dim: value})."""
    names = list(dims)
    uncovered: set[tuple[int, str, int, str]] = set()
    for i, j in itertools.combinations(range(len(names)), 2):
        for vi in dims[names[i]]:
            for vj in dims[names[j]]:
                uncovered.add((i, vi, j, vj))

    rows = []
    while uncovered:
        si, sv, sj, sv2 = min(uncovered)
        row = {si: sv, sj: sv2}
        for idx, name in enumerate(names):
            if idx not in row:
                row[idx] = _best_value(dims[name], idx, row, uncovered)
        for i, j in itertools.combinations(sorted(row), 2):
            uncovered.discard((i, row[i], j, row[j]))
        rows.append({names[k]: v for k, v in row.items()})
    return rows


def payloads(v: Mapping[str, object]) -> dict[str, object]:
    """Expand a pairwise row into real tfvars."""
    out: dict[str, object] = {}

    if v.get("rate_limit") == "rate_limit":
        out["rate_limit_choice"] = "rate_limit"
        out["rate_limit_total_number"] = 500
        out["rate_limit_unit"] = "MINUTE"

    # client_matcher is only observable when api_protection rules exist, but set it
    # per the pairwise row so (client_matcher x api_protection) pairs are covered.
    if v.get("client_matcher") == "ip_prefix":
        out["client_matcher"] = {"mode": "ip_prefix", "ip_prefixes": ["10.0.0.0/8"]}
    elif v.get("client_matcher") == "ip_threat":
        out["client_matcher"] = {
            "mode": "ip_threat",
            "ip_threat_categories": ["BOTNETS"],
        }

    if v.get("sensitive_data") == "custom":
        out["sensitive_data_policy_choice"] = "custom"
        out["sensitive_data_compliances"] = ["GDPR", "PCI_DSS"]

    if v.get("data_guard") == "on":
        out["data_guard_rules"] = [
            {"domain_mode": "any", "path": "/api/pay", "apply": True}
        ]

    if v.get("api_protection") in ("allow", "deny"):
        out["api_protection_rules"] = [
            {"path": "/api/admin", "methods": ["POST"], "action": v["api_protection"]}
        ]

    if v.get("validation") == "custom_list":
        out["api_definition_choice"] = "specification"
        out["api_specification_validation"] = "custom_list"
        out["validation_custom_rules"] = [
            {"path": "/api/health", "methods": ["GET"], "action": "report"}
        ]

    return out


def canonical() -> dict[str, object]:
    """Return the live-canonical end state (all SP3 features off)."""
    return {"rate_limit_choice": "disable", "api_definition_choice": "disable"}


def build() -> list[dict[str, object]]:
    """Build the ordered variant manifest (all-pairs + canonical restore), deduped."""
    variants: list[dict[str, object]] = []
    seen: set[str] = set()
    idx = 0
    for row in all_pairs(DIMENSIONS):
        vars_ = payloads(row)
        key = json.dumps(vars_, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        variants.append({"name": f"pair-{idx:03d}", "vars": vars_})
        idx += 1
    variants.append({"name": "canonical-restore", "vars": canonical()})
    return variants


def emit(directory: str) -> int:
    """Write one <NNN>-<name>.tfvars.json per variant plus manifest.txt."""
    out_dir = Path(directory)
    out_dir.mkdir(parents=True, exist_ok=True)
    for existing in out_dir.iterdir():
        if existing.name.endswith(".tfvars.json") or existing.name == "manifest.txt":
            existing.unlink()
    variants = build()
    named = [(f"{i:03d}-{v['name']}.tfvars.json", v) for i, v in enumerate(variants)]
    for fname, v in named:
        (out_dir / fname).write_text(json.dumps(v["vars"], indent=2) + "\n")
    lines = [f"{i:03d} {v['name']} {fname} LIVE" for i, (fname, v) in enumerate(named)]
    (out_dir / "manifest.txt").write_text("\n".join(lines) + "\n")
    return len(variants)


def main(argv: list[str]) -> None:
    """CLI: --count, --emit <dir>, else JSON to stdout."""
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
