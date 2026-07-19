#!/usr/bin/env python3
"""Generate the standalone route object (CR-5) coverage matrix.

The inline route arms are exhausted by CR-1..CR-4; this verifies the standalone xcsh_route
resource round-trip and the LB custom_route (route_ref) arm. Small explicit variant set
(standalone route attached to the LB, standalone-only), plus canonical-restore (nothing).

Deterministic. Output: JSON to stdout, or files via --emit.
"""

import json
import sys
from pathlib import Path

RO = {
    "name": "cr5-ro",
    "path_prefix": "/cr5-route",
    "response_code": 200,
    "response_body": "routed via xcsh_route",
}


def build() -> list[dict[str, object]]:
    """Ordered variants: route attached to LB, standalone-only, canonical."""
    return [
        {
            "name": "route-attached",
            "vars": {"route_objects": [RO], "custom_route_ref": "cr5-ro"},
        },
        {
            "name": "route-standalone",
            "vars": {"route_objects": [RO], "custom_route_ref": None},
        },
        {
            "name": "canonical-restore",
            "vars": {"route_objects": [], "custom_route_ref": None},
        },
    ]


def emit(directory: str) -> int:
    """Write one <NNN>-<name>.tfvars.json per variant plus manifest.txt (flag = round-trip mode)."""
    out_dir = Path(directory)
    out_dir.mkdir(parents=True, exist_ok=True)
    for existing in out_dir.iterdir():
        if existing.name.endswith(".tfvars.json") or existing.name == "manifest.txt":
            existing.unlink()
    variants = build()
    named = [(f"{i:03d}-{v['name']}.tfvars.json", v) for i, v in enumerate(variants)]
    for fname, v in named:
        (out_dir / fname).write_text(json.dumps(v["vars"], indent=2) + "\n")
    lines = []
    for i, (fname, v) in enumerate(named):
        vars_ = v["vars"]
        if not (isinstance(vars_, dict) and vars_.get("route_objects")):
            flag = "NONE"  # nothing created -> no round-trip
        elif vars_.get("custom_route_ref"):
            flag = "ROUTE_LB"  # round-trip the route object AND the whole LB
        else:
            flag = "ROUTE"  # round-trip the route object only
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
