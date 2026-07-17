#!/usr/bin/env python3
"""Generate the JWT validation + GraphQL inspection (LPC-3) coverage matrix.

AETG all-pairs over the jwt_validation arms and the graphql_rules arms, each variant applied
to the LIVE LB. Plus canonical-restore (both off).

Dimensions:
  jwt  none | block_all | report_paths
       none         -> no jwt_validation
       block_all    -> action=block, target=all_endpoint, issuer+audiences+validate_period
       report_paths -> action=report, target=base_paths, mandatory_claims, issuer_disable
  gql  none | any_post | exact_get
       none      -> no graphql_rules
       any_post  -> domain=any, method=post, introspection=disable, depth/length limits
       exact_get -> domain=exact, method=get, introspection=enable, batched-queries limit

The JWKS is a readable JSON document (RFC 7517); the module base64-encodes it for the API
(F5 XC validates the "cleartext" field as base64). Embedded key below is a public RSA JWKS.

Deterministic (no RNG). Output: JSON to stdout, or files via --emit.
"""

import itertools
import json
import sys
from collections.abc import Mapping
from pathlib import Path

# A valid public RSA JWKS (RFC 7517). Public key material only — safe to embed.
JWKS = json.dumps(
    {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "kid": "webapp-test-1",
                "alg": "RS256",
                "n": (
                    "oXkqKtCbRs88qF3SyyWysA5vXHXsdPheDF0pbJz_AG3FGbDriytdB8UR"
                    "ONeNyhfO_ad3kucemewL4b0EQfopAR5LEPOIWmnmjhTnQB7a3YP1C-HQ"
                    "yrWoQ_xNI9mXuhwcns65Ry-gZc2FFvGGdwJykDBPzDG4AVXNdAwzffWg"
                    "FYXf903vKewC-mHsHuZuZkmEHOg3RXIgtY0dSpIFwH_QYyQl1HCZCWtN"
                    "bp4yWZy0Pi8yAt-zcfze516-XxywCJiJ61KLCE0RwyIzZ1PpZlyCK0TQ"
                    "tRF94N-A0b1Ws4IOfQ-QOanBWS5bC-Q7N7SaoUHEDmUJlnQS7hJZWOKV"
                    "fn8jPQ"
                ),
                "e": "AQAB",
            }
        ]
    }
)

DIMENSIONS = {
    "jwt": ["none", "block_all", "report_paths"],
    "gql": ["none", "any_post", "exact_get"],
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


def _jwt(kind: str) -> object:
    """Expand a jwt dimension value into the jwt_validation object (or None)."""
    if kind == "block_all":
        return {
            "jwks_cleartext": JWKS,
            "action": "block",
            "target": "all_endpoint",
            "issuer": "https://issuer.example.com",
            "audiences": ["api://webapp"],
            "validate_period": True,
        }
    if kind == "report_paths":
        # issuer omitted -> issuer_disable derived; audiences omitted -> audience_disable derived.
        return {
            "jwks_cleartext": JWKS,
            "action": "report",
            "target": "base_paths",
            "base_paths": ["/api"],
            "mandatory_claims": ["sub", "iat"],
            "validate_period": False,
        }
    return None


def _gql(kind: str) -> list[dict[str, object]]:
    """Expand a gql dimension value into the graphql_rules list."""
    if kind == "any_post":
        return [
            {
                "name": "gql-any",
                "exact_path": "/graphql",
                "domain": "any",
                "method": "post",
                "max_depth": 10,
                "max_total_length": 4096,
                "introspection": "disable",
            }
        ]
    if kind == "exact_get":
        return [
            {
                "name": "gql-exact",
                "exact_path": "/graphql",
                "domain": "exact",
                "domain_value": "api.f5-sales-demo.com",
                "method": "get",
                "max_batched_queries": 5,
                "introspection": "enable",
            }
        ]
    return []


def payloads(v: Mapping[str, object]) -> dict[str, object]:
    """Expand an LPC-3 row into real tfvars."""
    return {"jwt_validation": _jwt(str(v["jwt"])), "graphql_rules": _gql(str(v["gql"]))}


def canonical() -> dict[str, object]:
    """Live-canonical end state (jwt off, graphql off)."""
    return {"jwt_validation": None, "graphql_rules": []}


def build() -> list[dict[str, object]]:
    """Build the ordered variant manifest (all-pairs + canonical), deduped."""
    variants: list[dict[str, object]] = []
    seen: set[str] = set()
    idx = 0
    for row in all_pairs(DIMENSIONS):
        if row["jwt"] == "none" and row["gql"] == "none":
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
    # jwt-bearing variants carry a write-only secret (jwks_config.cleartext) the API masks as
    # "Redacted"; their whole-LB import re-applies it (expected). Flag SECRET so the runner
    # classifies the round-trip via lpc3_import_check.py instead of demanding a 0-change plan.
    def flag(variant: dict[str, object]) -> str:
        vars_ = variant["vars"]
        return "SECRET" if isinstance(vars_, dict) and vars_.get("jwt_validation") else "LIVE"

    lines = [f"{i:03d} {v['name']} {fname} {flag(v)}" for i, (fname, v) in enumerate(named)]
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
