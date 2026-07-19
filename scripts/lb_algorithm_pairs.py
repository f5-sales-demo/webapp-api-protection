#!/usr/bin/env python3
"""Generate the LB loadbalancer_algorithm (LBA) coverage matrix.

Cycles the LIVE LB through each supported algorithm arm — least_active / random /
source_ip_stickiness / ring_hash (with a hash_policy) — and ends on canonical-restore
(round_robin, the server default). cookie_stickiness is excluded (tenant returns 500).
Deterministic. Output: JSON to stdout, or files via --emit.
"""

import json
import sys
from pathlib import Path


def build() -> list[dict[str, object]]:
    """Ordered variant manifest: each algorithm arm + canonical (round_robin)."""
    return [
        {"name": "least-active", "vars": {"lb_algorithm": {"mode": "least_active"}}},
        {"name": "random", "vars": {"lb_algorithm": {"mode": "random"}}},
        {
            "name": "source-ip-stickiness",
            "vars": {"lb_algorithm": {"mode": "source_ip_stickiness"}},
        },
        {
            "name": "ring-hash",
            "vars": {
                "lb_algorithm": {
                    "mode": "ring_hash",
                    "ring_hash_policies": [{"source_ip": True, "terminal": True}],
                }
            },
        },
        {
            "name": "canonical-restore",
            "vars": {"lb_algorithm": {"mode": "round_robin"}},
        },
    ]


def emit(directory: str) -> int:
    """Write one <NNN>-<name>.tfvars.json per variant plus manifest.txt (all LIVE)."""
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
