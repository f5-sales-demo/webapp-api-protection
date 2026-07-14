#!/usr/bin/env python3
"""Generate the API Discovery + Crawler coverage matrix as a JSON manifest.

Coverage model (see docs/superpowers/specs/2026-07-13-sp1-api-discovery-crawler-blindfold-design.md):
  * all-pairs (pairwise) over every api_discovery oneof-group dimension, so every
    pair of option-values co-occurs in at least one variant (AETG-style greedy);
  * PLUS an explicit case for the discovered_api_settings purge-duration bound;
  * PLUS the canonical restore end state (bare enable_api_discovery {}).

Pairwise dimensions include the two pseudo-dimensions `api_crawler` (none/one
domain) and `secret_method` (clear/blindfold); these are expanded by payloads()
into the real tfvars (api_crawler_domains + api_crawler_password) and removed, so
every emitted variant is a valid, minimal root config.

Deterministic: dimension/value ordering is fixed and the greedy tie-break is
lowest-index, so the same manifest is produced on every run (no RNG).

Output: JSON array of {"name": str, "vars": {tfvar: value}} to stdout.
"""

import itertools
import json
import sys
from collections.abc import Mapping
from pathlib import Path

# Pairwise dimensions. `api_crawler` and `secret_method` are pseudo-dimensions
# expanded by payloads(); when api_discovery_choice=disable the enable-only arms
# (crawler/learn/auth) are ignored by the module (harmless no-ops), so pairwise
# still covers the enable space. secret_method is only meaningful when a crawler
# domain exists, but pairwise over (api_crawler, secret_method) still guarantees
# (one, clear) and (one, blindfold) both occur, exercising both SecretType arms live.
DIMENSIONS = {
    "api_discovery_choice": ["enable", "disable"],
    "api_crawler": ["none", "one"],
    "secret_method": ["clear", "blindfold"],
    "api_discovery_learn_from_redirect": ["omit", "enable"],
    "api_discovery_auth_mode": ["default", "custom"],
}

# The crawler `domain` is a bare FQDN (an LB-served domain), NOT a URL with scheme/
# path — F5 XC rejects the URL form with 400 (verified live). Use a served domain.
_CRAWLER_DOMAIN = "www.f5-sales-demo.com"
_CRAWLER_USER = "apitester"
_CRAWLER_PLAINTEXT = "Sp1-Cr@wl-Demo"  # demo credential; matrix files are gitignored


def _best_value(
    values: list[str],
    idx: int,
    row: dict[int, str],
    uncovered: set[tuple[int, str, int, str]],
) -> str:
    """Pick the value for dimension idx covering the most still-uncovered pairs.

    Deterministic lowest-index tie-break: scan values in order and keep the first
    that strictly improves on the best gain so far.
    """
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
        # Seed each row from a still-uncovered pair so it covers >=1 new pair
        # (guarantees termination). Smallest tuple for determinism.
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
    """Expand pseudo-dimensions into real tfvars for variant v."""
    out: dict[str, object] = dict(v)
    if v.get("api_crawler") == "one":
        out["api_crawler_domains"] = [
            {"domain": _CRAWLER_DOMAIN, "user": _CRAWLER_USER}
        ]
        if v.get("secret_method") == "blindfold":
            # location is injected by the matrix harness (sealed once via
            # scripts/blindfold-seal.sh) — the generator is offline and cannot seal.
            out["api_crawler_password"] = {"method": "blindfold"}
        else:
            out["api_crawler_password"] = {
                "method": "clear",
                "plaintext": _CRAWLER_PLAINTEXT,
            }
    else:
        out["api_crawler_domains"] = []
    if v.get("api_discovery_auth_mode") == "custom":
        out["api_discovery_custom_auth_types"] = [
            {"parameter_name": "X-API-Key", "parameter_type": "HEADER"}
        ]
    out.pop("api_crawler", None)
    out.pop("secret_method", None)
    return out


def canonical() -> dict[str, object]:
    """Return the live-canonical end state (bare enable_api_discovery, no crawler)."""
    return {"api_discovery_choice": "enable", "api_crawler_domains": []}


def build() -> list[dict[str, object]]:
    """Build the full ordered variant manifest (all-pairs + purge bound + canonical)."""
    variants: list[dict[str, object]] = []

    for i, row in enumerate(all_pairs(DIMENSIONS)):
        variants.append({"name": f"pair-{i:03d}", "vars": payloads(row)})

    # discovered_api_settings purge-duration bound (enable arm, no crawler).
    variants.append(
        {
            "name": "bound-purge-duration",
            "vars": {
                "api_discovery_choice": "enable",
                "api_crawler_domains": [],
                "api_discovery_purge_duration": 48,
            },
        }
    )

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
