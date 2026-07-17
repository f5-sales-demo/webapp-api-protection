#!/usr/bin/env python3
"""Generate the app-layer protection (LPC-1) coverage matrix.

AETG all-pairs over cors_policy / csrf_policy / protected_cookies, each variant applied to
the LIVE LB. Plus canonical-restore (all off).

Dimensions:
  cors     none | on                                (cors_policy access-control-* headers)
  csrf     omit | all_domains | custom | disabled   (csrf_policy oneof)
  cookies  none | one                               (a protected_cookies entry)

All independent; only the all-off row is skipped (canonical baseline).
Deterministic (no RNG). Output: JSON to stdout, or files via --emit.
"""

import itertools
import json
import sys
from collections.abc import Mapping
from pathlib import Path

DIMENSIONS = {
    "cors": ["none", "on"],
    "csrf": ["omit", "all_domains", "custom", "disabled"],
    "cookies": ["none", "one"],
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
    """Expand an LPC-1 row into real tfvars."""
    cors = None
    if v["cors"] == "on":
        cors = {
            "allow_origin": ["https://app.example.com"],
            "allow_methods": "GET, POST",
            "allow_credentials": True,
            "maximum_age": 600,
        }
    cookies: list[dict[str, object]] = []
    if v["cookies"] == "one":
        cookies = [
            {
                "name": "SESSION",
                "httponly": "add",
                "secure": "add",
                "samesite": "strict",
                "tampering": "enable",
                "max_age_value": 3600,
            }
        ]
    return {
        "cors_policy": cors,
        "csrf_policy_mode": v["csrf"],
        "csrf_custom_domains": ["trusted.example.com"] if v["csrf"] == "custom" else [],
        "protected_cookies": cookies,
    }


def canonical() -> dict[str, object]:
    """Live-canonical end state (all LPC-1 features off)."""
    return {
        "cors_policy": None,
        "csrf_policy_mode": "omit",
        "csrf_custom_domains": [],
        "protected_cookies": [],
    }


def build() -> list[dict[str, object]]:
    """Build the ordered variant manifest (all-pairs + canonical), deduped."""
    variants: list[dict[str, object]] = []
    seen: set[str] = set()
    idx = 0
    for row in all_pairs(DIMENSIONS):
        if row["cors"] == "none" and row["csrf"] == "omit" and row["cookies"] == "none":
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
