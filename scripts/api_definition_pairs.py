#!/usr/bin/env python3
"""Generate the API Definition & spec-enforcement (SP2) coverage matrix.

Coverage model (see docs/superpowers/specs/2026-07-14-sp2-api-definition-spec-management-design.md
and docs/superpowers/plans/sp2-findings.md):
  * all-pairs (pairwise, AETG greedy) over the SP2 oneof-group dimensions, so every
    pair of option-values co-occurs in at least one variant;
  * PLUS the canonical restore end state (all SP2 features off).

Pairwise dimensions and the pseudo-dimensions expanded by payloads():
  api_definition  disable | specification  -> api_definition_choice
  validation      disabled | all_spec_endpoints  (only when specification)
  schema_origin   strict | mixed  (only when specification)
  swagger         none | one  (one => a pinned object-store path, injected live)
  integration     off | on  -> code_base_integration_enabled
  token_method    clear | blindfold  (only when integration; blindfold is a
                  documented live SKIP — F5 XC 500s, see sp2-findings.md — so it is
                  plan-tested only, matching the SP1 crawler password)
  code_scan       off | selected  (requires integration on + repos; reconciled below)

payloads() reconciles the module's cross-field preconditions so every emitted
variant is a valid root config: when api_definition=disable the specification-only
arms are dropped; when integration=off the token/code_scan arms are dropped (code
scan requires the integration). Secret values and the uploaded swagger path are
NOT in the manifest — the harness injects them (placeholders below), exactly as the
SP1 matrix injects the sealed blindfold location.

Deterministic: fixed ordering + lowest-index tie-break (no RNG).

Output: JSON array of {"name", "vars", optional "skip_live"} to stdout, or files.
"""

import itertools
import json
import sys
from collections.abc import Mapping
from pathlib import Path

DIMENSIONS = {
    "api_definition": ["disable", "specification"],
    "validation": ["disabled", "all_spec_endpoints"],
    "schema_origin": ["strict", "mixed"],
    "swagger": ["none", "one"],
    "integration": ["off", "on"],
    "token_method": ["clear", "blindfold"],
    "code_scan": ["off", "selected"],
}

# Placeholders the harness substitutes with live values (never committed here).
SWAGGER_PLACEHOLDER = "__SWAGGER_PATH__"
CODE_SCAN_REPO = "api-catalog"


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


def payloads(v: Mapping[str, object]) -> tuple[dict[str, object], str | None]:
    """Expand a pairwise row into real tfvars + an optional live-skip reason."""
    out: dict[str, object] = {}
    skip: str | None = None

    if v.get("api_definition") == "specification":
        out["api_definition_choice"] = "specification"
        out["api_specification_validation"] = v["validation"]
        out["api_definition_schema_origin"] = v["schema_origin"]
        if v.get("swagger") == "one":
            out["api_definition_swagger_specs"] = [SWAGGER_PLACEHOLDER]
    else:
        out["api_definition_choice"] = "disable"

    if v.get("integration") == "on":
        out["code_base_integration_enabled"] = True
        out["code_base_integration_username"] = "robinmordasiewicz"
        if v.get("token_method") == "blindfold":
            # location injected by the harness; blindfold access_token 500s on F5 XC
            # (see sp2-findings.md) -> plan-tested only, skip the live apply.
            out["code_base_integration_access_token"] = {"method": "blindfold"}
            skip = "blindfold access_token 500s on F5 XC (platform limitation); clear is the live path"
        else:
            out["code_base_integration_access_token"] = {"method": "clear"}
        if v.get("code_scan") == "selected":
            out["api_discovery_code_scan"] = "selected"
            out["api_discovery_code_scan_repos"] = [CODE_SCAN_REPO]
    # integration=off => no token/code_scan (code scan requires the integration).

    return out, skip


def canonical() -> dict[str, object]:
    """Return the live-canonical end state (all SP2 features off)."""
    return {"api_definition_choice": "disable", "code_base_integration_enabled": False}


def build() -> list[dict[str, object]]:
    """Build the ordered variant manifest (all-pairs + canonical restore).

    Constraint reconciliation collapses several distinct pairwise rows to the same
    root config (e.g. every integration=off + api_definition=disable row yields the
    bare disable config); those byte-identical payloads are deduped so the slow live
    matrix does not re-apply the same variant. Pairwise coverage is unaffected — it
    is achieved at the row level before reconciliation.
    """
    variants: list[dict[str, object]] = []
    seen: set[str] = set()
    idx = 0
    for row in all_pairs(DIMENSIONS):
        vars_, skip = payloads(row)
        key = json.dumps(vars_, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        variant: dict[str, object] = {"name": f"pair-{idx:03d}", "vars": vars_}
        if skip:
            variant["skip_live"] = skip
        variants.append(variant)
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
    lines = [
        f"{i:03d} {v['name']} {fname} {'SKIP:' + str(v['skip_live']) if v.get('skip_live') else 'LIVE'}"
        for i, (fname, v) in enumerate(named)
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
