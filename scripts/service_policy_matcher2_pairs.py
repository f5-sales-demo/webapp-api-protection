#!/usr/bin/env python3
"""Generate the service_policy remaining-matcher (SPol-3b) coverage matrix.

AETG all-pairs over the SPol-3b rule matchers, each variant a rule_list policy with one
rule combining the selected matchers (all additive AND), LB-detached
(service_policies_choice=omit). Plus canonical restore.

Dimensions:
  arg     none | item | present   (arg_matchers: item exact+transformers, or present marker)
  cookie  none | absent           (cookie_matchers check_not_present)
  jwt     none | item             (jwt_claims item exact)
  body    none | regex            (body_matcher regex)
  ident   none | exact            (user_identity_matcher exact)
  label   none | keys             (label_matcher keys)
  port    none | ports            (port_matcher ports + invert)
  apigrp  none | match            (api_group_matcher match)

All matchers are independent (live-verified — no cross-field constraint), so every
combination is valid; only the all-"none" row is skipped (that is the SPol-3 baseline).

Deterministic (no RNG). Output: JSON to stdout, or files via --emit.
"""

import itertools
import json
import sys
from collections.abc import Mapping
from pathlib import Path

POLICY_NAME = "matrix-spol-c"

DIMENSIONS = {
    "arg": ["none", "item", "present"],
    "cookie": ["none", "absent"],
    "jwt": ["none", "item"],
    "body": ["none", "regex"],
    "ident": ["none", "exact"],
    "label": ["none", "keys"],
    "port": ["none", "ports"],
    "apigrp": ["none", "match"],
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
    """Build one rule from a matcher row."""
    r: dict[str, object] = {"name": "r0", "action": "DENY"}
    if v["arg"] == "item":
        r["arg_matchers"] = [
            {
                "name": "q",
                "presence": "match",
                "exact_values": ["1"],
                "transformers": ["LOWER_CASE"],
            }
        ]
    elif v["arg"] == "present":
        r["arg_matchers"] = [{"name": "q", "presence": "present"}]
    if v["cookie"] == "absent":
        r["cookie_matchers"] = [{"name": "sid", "presence": "absent"}]
    if v["jwt"] == "item":
        r["jwt_claims"] = [
            {"name": "sub", "presence": "match", "exact_values": ["admin"]}
        ]
    if v["body"] == "regex":
        r["body_regex"] = [".*evil.*"]
    if v["ident"] == "exact":
        r["user_identity_exact"] = ["u1"]
    if v["label"] == "keys":
        r["label_keys"] = ["env"]
    if v["port"] == "ports":
        r["port_ports"] = ["443"]
        r["port_invert"] = True
    if v["apigrp"] == "match":
        r["api_groups"] = ["grp1"]
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
        if all(val == "none" for val in row.values()):
            continue
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
