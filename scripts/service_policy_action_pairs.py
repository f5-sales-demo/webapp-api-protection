#!/usr/bin/env python3
"""Generate the service_policy action-side + constraints (SPol-4a/4b) coverage matrix.

AETG all-pairs over the per-rule action-side oneofs and constraint blocks, each variant a
rule_list policy with one rule, LB-detached (service_policies_choice=omit) so the standalone
policy destroys cleanly without the two-phase detach the attached case needs. Plus canonical
restore.

Dimensions:
  waf  none | skip | detection_control   (waf_action arm)
  bot  omit | skip                        (bot_action)
  mum  omit | skip                        (mum_action)
  seg  omit | any | intra                 (segment_policy markers; segments refs deferred)
  rc   off | on                           (request_constraints, exceeds + none markers)

The rule action is derived from waf: a configured WAF action (skip/detection_control) is
rejected by F5 XC on a DENY rule ("WAF Action cannot be configured for a rule with action
DENY" — live-verified), so waf!=none => action ALLOW, else DENY. bot/mum are independent of
waf and of each other (the SPol-4a all-or-nothing rule was a misdiagnosis of that DENY
rejection). All generated combinations are therefore valid; no combos are filtered.

Deterministic (no RNG). Output: JSON to stdout, or files via --emit.
"""

import itertools
import json
import sys
from collections.abc import Mapping
from pathlib import Path

POLICY_NAME = "matrix-spol-a"

DIMENSIONS = {
    "waf": ["none", "skip", "detection_control"],
    "bot": ["omit", "skip"],
    "mum": ["omit", "skip"],
    "seg": ["omit", "any", "intra"],
    "rc": ["off", "on"],
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


def rule(v: Mapping[str, object]) -> dict[str, object]:
    """Build one rule from an action-side + constraints row."""
    waf = v["waf"]
    # A configured WAF action requires a non-DENY rule (F5 XC constraint).
    r: dict[str, object] = {
        "name": "r0",
        "action": "DENY" if waf == "none" else "ALLOW",
        "waf_action_mode": waf,
    }
    if waf == "detection_control":
        # Exercise all four exclusion list types: attack-type (default CONTEXT_ANY), violation
        # (CONTEXT_HEADER), signature (CONTEXT_URL + id), and bot-name.
        r["waf_exclude_attack_type_contexts"] = [
            {"exclude_attack_type": "ATTACK_TYPE_SQL_INJECTION"}
        ]
        r["waf_exclude_violation_contexts"] = [
            {"context": "CONTEXT_HEADER", "exclude_violation": "VIOL_JSON_MALFORMED"}
        ]
        r["waf_exclude_signature_contexts"] = [
            {"context": "CONTEXT_URL", "signature_id": 200000001}
        ]
        r["waf_exclude_bot_names"] = ["curl"]
    if v["bot"] == "skip":
        r["bot_action_mode"] = "skip"
    if v["mum"] == "skip":
        r["mum_action_mode"] = "skip"
    if v["seg"] == "any":
        r["segment_src"] = "any"
        r["segment_dst"] = "any"
    elif v["seg"] == "intra":
        r["segment_intra"] = True
    if v["rc"] == "on":
        r["request_constraints_enabled"] = True
        r["max_url_size"] = 2048
    return r


def payloads(v: Mapping[str, object]) -> dict[str, object]:
    """Expand a matcher row into real tfvars (rule_list policy, LB-detached)."""
    return {
        "service_policies": [
            {"name": POLICY_NAME, "rule_handling": "rule_list", "rules": [rule(v)]}
        ],
        "service_policies_choice": "omit",
    }


def canonical() -> dict[str, object]:
    """Live-canonical end state (no service policy; LB server default)."""
    return {"service_policies": [], "service_policies_choice": "omit"}


def build() -> list[dict[str, object]]:
    """Build the ordered variant manifest (all-pairs + canonical), deduped."""
    variants: list[dict[str, object]] = []
    seen: set[str] = set()
    idx = 0
    for row in all_pairs(DIMENSIONS):
        # All combinations are valid (action is derived from waf to satisfy the DENY
        # coupling; bot/mum/seg/rc are independent) — nothing to filter.
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
