#!/usr/bin/env python3
"""Generate the inline WAF exclusion (LPC-4a) coverage matrix.

AETG all-pairs over the rule's domain oneof, path oneof, and exclusion action, each variant
applied to the LIVE LB. Plus canonical-restore (no rules).

Dimensions:
  domain  any | exact | suffix        (any_domain / exact_value / suffix_value)
  path    any | prefix | regex        (any_path / path_prefix / path_regex)
  excl    skip | signature | violation | attack | bot
          skip      -> waf_skip_processing (skip WAF for the match)
          signature -> app_firewall_detection_control.exclude_signature_contexts
          violation -> ...exclude_violation_contexts
          attack    -> ...exclude_attack_type_contexts
          bot       -> ...exclude_bot_name_contexts

Env is NON-PRODUCTION/destructive-OK; a matched skip rule is transient (applied, verified,
then canonical-restore clears it). Deterministic (no RNG). Output: JSON to stdout, or --emit.
"""

import itertools
import json
import sys
from collections.abc import Mapping
from pathlib import Path

DIMENSIONS = {
    "domain": ["any", "exact", "suffix"],
    "path": ["any", "prefix", "regex"],
    "excl": ["skip", "signature", "violation", "attack", "bot"],
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


def _excl_fields(excl: str) -> dict[str, object]:
    """Expand an excl dimension value into the rule's action + exclusion lists."""
    if excl == "skip":
        return {"action": "skip"}
    base: dict[str, object] = {"action": "detection_control"}
    if excl == "signature":
        # signature_id 0 = "exclude ALL signatures for the context"; round-trips faithfully since
        # provider v3.72.10 (#1129, meaningful-zero int64 read). A real ID is the 200000001+ range.
        base["exclude_signatures"] = [
            {"signature_id": 0, "context": "CONTEXT_ANY"},
            {
                "signature_id": 200002147,
                "context": "CONTEXT_HEADER",
                "context_name": "x-api",
            },
        ]
    elif excl == "violation":
        base["exclude_violations"] = [{"violation": "VIOL_JSON_MALFORMED"}]
    elif excl == "attack":
        base["exclude_attack_types"] = [
            {
                "attack_type": "ATTACK_TYPE_SQL_INJECTION",
                "context": "CONTEXT_PARAMETER",
                "context_name": "q",
            }
        ]
    elif excl == "bot":
        base["exclude_bot_names"] = ["Googlebot"]
    return base


def _rule(row: Mapping[str, object]) -> dict[str, object]:
    """Build one waf_exclusion rule from an all-pairs row."""
    domain, path, excl = str(row["domain"]), str(row["path"]), str(row["excl"])
    rule: dict[str, object] = {
        "name": f"excl-{domain}-{path}-{excl}",
        "domain": domain,
        "path": path,
        "methods": ["GET", "POST"],
    }
    if domain == "exact":
        rule["domain_value"] = "api.f5-sales-demo.com"
    elif domain == "suffix":
        rule["domain_value"] = "f5-sales-demo.com"
    if path == "prefix":
        rule["path_value"] = "/waf-excl-probe"
    elif path == "regex":
        rule["path_value"] = "^/waf-excl/.*$"
    rule.update(_excl_fields(excl))
    return rule


def build() -> list[dict[str, object]]:
    """Build the ordered variant manifest (all-pairs + canonical), deduped."""
    variants: list[dict[str, object]] = []
    seen: set[str] = set()
    idx = 0
    for row in all_pairs(DIMENSIONS):
        vars_ = {"waf_exclusion_rules": [_rule(row)]}
        key = json.dumps(vars_, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        variants.append({"name": f"pair-{idx:03d}", "vars": vars_})
        idx += 1
    variants.append({"name": "canonical-restore", "vars": {"waf_exclusion_rules": []}})
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
