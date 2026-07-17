#!/usr/bin/env python3
"""Generate the standalone WAF exclusion policy (LPC-4b) coverage matrix.

The inline rule-shape combinatorics are already exhausted by LPC-4a; this matrix verifies the
standalone xcsh_waf_exclusion_policy resource round-trip and the LB waf_exclusion_policy ref
arm. Small explicit variant set (rule kind x attached), plus canonical-restore.

Each variant defines one policy `excl-pol` and optionally attaches it to the LB via
waf_exclusion_policy_ref. Deterministic. Output: JSON to stdout, or files via --emit.
"""

import json
import sys
from pathlib import Path

SKIP_RULE = {
    "name": "skip-probe",
    "path": "prefix",
    "path_value": "/waf-excl-probe",
    "action": "skip",
}
# Use a real signature ID (200000001-299999999). signature_id=0 ("all signatures") hits a
# distinct provider zero-value-omission bug (marshal drops the 0 -> read-back null -> apply
# "inconsistent result"); tracked separately, not exercised here.
DC_RULE = {
    "name": "excl-sig",
    "domain": "exact",
    "domain_value": "api.f5-sales-demo.com",
    "action": "detection_control",
    "exclude_signatures": [
        {
            "signature_id": 200002147,
            "context": "CONTEXT_HEADER",
            "context_name": "x-api",
        }
    ],
    "exclude_violations": [{"violation": "VIOL_JSON_MALFORMED"}],
}


def _variant(name: str, rules: list[dict], attached: bool) -> dict[str, object]:
    """Build a variant: one policy `excl-pol` with rules, optionally attached to the LB."""
    vars_: dict[str, object] = {
        "waf_exclusion_policies": [{"name": "excl-pol", "rules": rules}],
        "waf_exclusion_policy_ref": "excl-pol" if attached else None,
    }
    return {"name": name, "vars": vars_}


def build() -> list[dict[str, object]]:
    """Ordered variant manifest: policy round-trips (attached + standalone) + canonical."""
    return [
        _variant("skip-attached", [SKIP_RULE], attached=True),
        _variant("dc-attached", [DC_RULE], attached=True),
        _variant("multi-standalone", [SKIP_RULE, DC_RULE], attached=False),
        {
            "name": "canonical-restore",
            "vars": {"waf_exclusion_policies": [], "waf_exclusion_policy_ref": None},
        },
    ]


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
    # flag: variants that attach the policy exercise the whole-LB import too (LB_REF); the
    # standalone-only variant and canonical only import the policy resource(s) (POLICY).
    lines = []
    for i, (fname, v) in enumerate(named):
        vars_ = v["vars"]
        policies = (
            vars_.get("waf_exclusion_policies") if isinstance(vars_, dict) else None
        )
        ref = vars_.get("waf_exclusion_policy_ref") if isinstance(vars_, dict) else None
        # NONE: nothing created (canonical) -> no resource to round-trip. LB_REF: attached to LB
        # (round-trip policy + whole LB). POLICY: standalone only (round-trip policy).
        flag = "NONE" if not policies else ("LB_REF" if ref else "POLICY")
        lines.append(f"{i:03d} {v['name']} {fname} {flag}")
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
