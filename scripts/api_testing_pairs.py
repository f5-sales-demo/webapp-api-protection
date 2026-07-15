#!/usr/bin/env python3
"""Generate the API Testing (SP4) coverage matrix.

Coverage model (see docs/superpowers/specs/2026-07-14-sp4-api-testing-design.md):
  * all-pairs (pairwise, AETG greedy) over the SP4 dimensions, so every pair of
    option-values co-occurs in at least one variant;
  * PLUS the canonical restore end state (API testing off).

Pairwise dimensions:
  surface   lb | standalone | both   -> api_testing_choice + api_testing_standalone_enabled
  auth      admin | standard | api_key | basic_auth | bearer_token  (per credential)
  secret    clear | blindfold        (only for api_key/basic_auth/bearer_token)
  schedule  every_week | every_day | every_month  (standalone surfaces only)

Secret values are NEVER in the manifest — the harness injects them (placeholders
below), exactly as the SP1/SP2 matrices inject sealed/clear secrets. Manifest flag:
  LIVE   - no write-only secret (admin/standard): must import 0-change.
  SECRET - clear api_key/basic_auth/bearer_token: F5 XC never returns the secret on
           read, so the harness re-applies after import to re-set it, then requires a
           clean plan (write-only-secret gate).
  SKIP:<reason> - blindfold secret: F5 XC 500s on offline-sealed API-testing secrets
           (same platform limitation as SP1 crawler / SP2 access_token); plan-tested only.

payloads() reconciles module constraints so every emitted variant is a valid root
config, and dedups byte-identical payloads. Deterministic (no RNG).

Output: JSON array of {"name","vars","flag"} to stdout, or files via --emit.
"""

import itertools
import json
import sys
from collections.abc import Mapping
from pathlib import Path

DIMENSIONS = {
    "surface": ["lb", "standalone", "both"],
    "auth": ["admin", "standard", "api_key", "basic_auth", "bearer_token"],
    "secret": ["clear", "blindfold"],
    "schedule": ["every_week", "every_day", "every_month"],
}

CLEAR_VALUE_MARKER = "__TEST_SECRET__"  # clear plaintext, injected from env
BF_PLACEHOLDER = "__BF_LOCATION__"  # blindfold sealed location, injected
SECRET_ARMS = ("api_key", "basic_auth", "bearer_token")


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


def payloads(v: Mapping[str, object]) -> tuple[dict[str, object], str]:
    """Expand a pairwise row into real tfvars + the manifest flag."""
    out: dict[str, object] = {}
    surface = v.get("surface")
    auth = v.get("auth")
    method_sel = v.get("secret")

    out["api_testing_choice"] = "enabled" if surface in ("lb", "both") else "disable"
    out["api_testing_standalone_enabled"] = surface in ("standalone", "both")

    # schedule only observable on a standalone surface; canonicalize otherwise so
    # (schedule x lb-only) rows dedup instead of emitting redundant variants.
    if surface in ("standalone", "both"):
        out["api_testing_schedule"] = v.get("schedule")

    cred: dict[str, object] = {"credential_name": f"c-{auth}", "auth_type": auth}
    flag = "LIVE"
    if auth == "api_key":
        cred["api_key_name"] = "X-API-Key"
    if auth == "basic_auth":
        cred["user"] = "tester"
    if auth in SECRET_ARMS:
        if method_sel == "blindfold":
            cred["secret"] = {"method": "blindfold", "location": BF_PLACEHOLDER}
            flag = "SKIP:blindfold API-testing secret 500s on F5 XC (platform limitation); clear is the live path"
        else:
            cred["secret"] = {"method": "clear", "plaintext": CLEAR_VALUE_MARKER}
            flag = "SECRET"

    out["api_testing_domains"] = [
        {"domain": "api.f5-sales-demo.com", "credentials": [cred]}
    ]
    return out, flag


def canonical() -> dict[str, object]:
    """Return the live-canonical end state (API testing off)."""
    return {"api_testing_choice": "disable", "api_testing_standalone_enabled": False}


def build() -> list[dict[str, object]]:
    """Build the ordered variant manifest (all-pairs + canonical restore), deduped."""
    variants: list[dict[str, object]] = []
    seen: set[str] = set()
    idx = 0
    for row in all_pairs(DIMENSIONS):
        vars_, flag = payloads(row)
        key = json.dumps(vars_, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        variants.append({"name": f"pair-{idx:03d}", "vars": vars_, "flag": flag})
        idx += 1
    variants.append({"name": "canonical-restore", "vars": canonical(), "flag": "LIVE"})
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
    lines = [
        f"{i:03d} {v['name']} {fname} {v['flag']}" for i, (fname, v) in enumerate(named)
    ]
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
