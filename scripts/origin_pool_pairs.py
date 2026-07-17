#!/usr/bin/env python3
"""Generate the origin_pool (LPC-5b) coverage matrix.

AETG all-pairs over the safe origin-pool tuning axes, each applied to the LIVE pool. The pool
is the serving path, so origin_servers (public_ip) and TLS (no_tls) are fixed — only the
load-balancing algorithm, endpoint selection, and advanced_options timeouts vary. Plus
canonical-restore (ROUND_ROBIN / DISTRIBUTED / no advanced_options).

Dimensions:
  algo  ROUND_ROBIN | LEAST_REQUEST | RANDOM   (RING_HASH/LB_OVERRIDE need companion config)
  sel   DISTRIBUTED | LOCAL_ONLY | LOCAL_PREFERRED
  adv   none | timeouts   (advanced_options connection_timeout + http_idle_timeout)

Deterministic (no RNG). Output: JSON to stdout, or files via --emit.
"""

import itertools
import json
import sys
from collections.abc import Mapping
from pathlib import Path

DIMENSIONS = {
    "algo": ["ROUND_ROBIN", "LEAST_REQUEST", "RANDOM"],
    "sel": ["DISTRIBUTED", "LOCAL_ONLY", "LOCAL_PREFERRED"],
    "adv": ["none", "timeouts"],
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
    """Expand an LPC-5b row into real tfvars."""
    out: dict[str, object] = {
        "origin_lb_algorithm": v["algo"],
        "origin_endpoint_selection": v["sel"],
        "origin_connection_timeout": None,
        "origin_http_idle_timeout": None,
    }
    if v["adv"] == "timeouts":
        out["origin_connection_timeout"] = 3000
        out["origin_http_idle_timeout"] = 300000
    return out


def canonical() -> dict[str, object]:
    """Live-canonical end state (ROUND_ROBIN / DISTRIBUTED / no advanced_options)."""
    return {
        "origin_lb_algorithm": "ROUND_ROBIN",
        "origin_endpoint_selection": "DISTRIBUTED",
        "origin_connection_timeout": None,
        "origin_http_idle_timeout": None,
    }


def build() -> list[dict[str, object]]:
    """Build the ordered variant manifest (all-pairs + canonical), deduped."""
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
