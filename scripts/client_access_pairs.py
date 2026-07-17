#!/usr/bin/env python3
"""Generate the client access control (CAC) coverage matrix.

AETG all-pairs over the LB client-access features, each variant applied to the LIVE LB.
Uses RFC 5737 TEST-NET prefixes (192.0.2.0/24, 198.51.100.0/24) and a private ASN so no
real client traffic is ever blocked — the LB stays healthy through the matrix. Plus a
canonical-restore variant (all CAC features off).

Dimensions:
  blocked  none | ip | asn        (blocked_clients: by ip_prefix / by as_number)
  trusted  none | ip_waf          (trusted_clients: ip_prefix + actions SKIP_PROCESSING_WAF)
  iprep    off | on               (enable_ip_reputation with an IpThreatCategory list)

All three are independent LB features (no cross-field constraint), so every combination is
valid; only the all-off row is skipped (that is the canonical/no-CAC baseline).

Deterministic (no RNG). Output: JSON to stdout, or files via --emit.
"""

import itertools
import json
import sys
from collections.abc import Mapping
from pathlib import Path

DIMENSIONS = {
    "blocked": ["none", "ip", "asn"],
    "trusted": ["none", "ip_waf"],
    "iprep": ["off", "on"],
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
    """Expand a CAC row into real tfvars (TEST-NET prefixes / private ASN, never real)."""
    blocked: list[dict[str, object]] = []
    if v["blocked"] == "ip":
        blocked = [{"name": "cac-blk-ip", "ip_prefix": "192.0.2.0/24"}]
    elif v["blocked"] == "asn":
        blocked = [{"name": "cac-blk-asn", "as_number": 64512}]
    trusted: list[dict[str, object]] = []
    if v["trusted"] == "ip_waf":
        trusted = [
            {
                "name": "cac-trust-ip",
                "ip_prefix": "198.51.100.0/24",
                "actions": ["SKIP_PROCESSING_WAF"],
            }
        ]
    return {
        "trusted_clients": trusted,
        "blocked_clients": blocked,
        "ip_reputation_enabled": v["iprep"] == "on",
        "ip_reputation_categories": ["BOTNETS", "SPAM_SOURCES"]
        if v["iprep"] == "on"
        else [],
    }


def canonical() -> dict[str, object]:
    """Live-canonical end state (all CAC features off)."""
    return {
        "trusted_clients": [],
        "blocked_clients": [],
        "ip_reputation_enabled": False,
        "ip_reputation_categories": [],
    }


def build() -> list[dict[str, object]]:
    """Build the ordered variant manifest (all-pairs + canonical), deduped."""
    variants: list[dict[str, object]] = []
    seen: set[str] = set()
    idx = 0
    for row in all_pairs(DIMENSIONS):
        if (
            row["blocked"] == "none"
            and row["trusted"] == "none"
            and row["iprep"] == "off"
        ):
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
