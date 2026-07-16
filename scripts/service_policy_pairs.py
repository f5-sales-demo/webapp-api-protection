#!/usr/bin/env python3
"""Generate the service_policy foundation (SPol-1) coverage matrix.

Coverage model (mirrors scripts/api_protection_pairs.py):
  * all-pairs (pairwise, AETG greedy) over the SPol-1 outer dimensions, so every pair
    of option-values co-occurs in at least one variant;
  * PLUS the canonical restore end state (no service policy created, LB back to the
    server default service_policies_from_namespace).

Pairwise dimensions:
  rule_handling  allow_all | deny_all | rule_list   (xcsh_service_policy rule-handling oneof)
  server_scope   any_server | selector              (server-scope oneof; any_server omitted)
  lb_choice      omit | none | active               (LB service_policies_choice arm)

payloads() reconciles the module's constraints so every emitted variant is a valid root
config, and dedups byte-identical payloads. Secret-free. Deterministic (no RNG).

Output: JSON array of {"name", "vars"} to stdout, or files via --emit.
"""

import itertools
import json
import sys
from collections.abc import Mapping
from pathlib import Path

POLICY_NAME = "matrix-spol"

DIMENSIONS = {
    "rule_handling": ["allow_all", "deny_all", "rule_list"],
    "server_scope": ["any_server", "selector"],
    "lb_choice": ["omit", "none", "active"],
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
    pol: dict[str, object] = {
        "name": POLICY_NAME,
        "rule_handling": v["rule_handling"],
        "server_scope": v["server_scope"],
    }
    if v.get("rule_handling") == "rule_list":
        pol["rules"] = [{"name": "r0", "action": "ALLOW"}]
    if v.get("server_scope") == "selector":
        pol["server_selector"] = ["app in (webapp)"]

    out: dict[str, object] = {
        "service_policies": [pol],
        "service_policies_choice": v["lb_choice"],
    }
    if v.get("lb_choice") == "active":
        out["service_policy_active"] = [POLICY_NAME]
    return out


def detach() -> dict[str, object]:
    """Detach the policy from the LB while keeping it defined.

    F5 XC refuses to delete a service policy an LB still references (referential
    integrity), and terraform's single-apply ordering does not reliably update the LB
    (drop active_service_policies) before destroying the policy — the destroy hits a
    referential 400 and the provider's bounded delete-retry exhausts. So teardown is
    two-phase: this detach (LB -> server default, policy kept), then canonical (destroy
    the now-unreferenced policy). Verified live on f5-sales-demo.
    """
    return {
        "service_policies": [
            {
                "name": POLICY_NAME,
                "rule_handling": "allow_all",
                "server_scope": "any_server",
            }
        ],
        "service_policies_choice": "omit",
        "service_policy_active": [],
    }


def canonical() -> dict[str, object]:
    """Return the live-canonical end state (no service policy; LB server default)."""
    return {
        "service_policies": [],
        "service_policies_choice": "omit",
        "service_policy_active": [],
    }


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
    # Two-phase teardown: detach the policy from the LB before destroying it (F5 XC
    # refuses to delete a referenced policy; see detach()).
    variants.append({"name": "detach", "vars": detach()})
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
