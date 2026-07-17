#!/usr/bin/env python3
"""Generate the custom routes (CR-1 foundation) coverage matrix.

CR-1 covers a simple_route that matches a path prefix (+ http_method) and routes to the module
origin pool. Small explicit variant set (path prefix x method, single + multi route), plus
canonical-restore (no routes). Custom routes are additive to default_route_pools, so the LB
keeps serving www/api throughout.

Deterministic (no RNG). Output: JSON to stdout, or files via --emit.
"""

import json
import sys
from pathlib import Path


def build() -> list[dict[str, object]]:
    """Ordered variant manifest over the route match surface, then canonical."""
    return [
        {
            "name": "prefix-any",
            "vars": {
                "custom_routes": [
                    {"path_mode": "prefix", "path_value": "/app", "http_method": "ANY"}
                ]
            },
        },
        {
            "name": "exact-get",
            "vars": {
                "custom_routes": [
                    {
                        "path_mode": "exact",
                        "path_value": "/health",
                        "http_method": "GET",
                    }
                ]
            },
        },
        {
            "name": "regex-post",
            "vars": {
                "custom_routes": [
                    {
                        "path_mode": "regex",
                        "path_value": "^/v[0-9]+/.*$",
                        "http_method": "POST",
                    }
                ]
            },
        },
        {
            "name": "headers-port",
            "vars": {
                "custom_routes": [
                    {
                        "path_mode": "prefix",
                        "path_value": "/api",
                        "incoming_port": 443,
                        "headers": [
                            {"name": "x-canary", "mode": "exact", "value": "on"},
                            {
                                "name": "x-legacy",
                                "mode": "presence",
                                "invert_match": True,
                            },
                            {
                                "name": "x-trace",
                                "mode": "regex",
                                "value": "^[0-9a-f]+$",
                            },
                        ],
                    }
                ]
            },
        },
        {
            "name": "multi",
            "vars": {
                "custom_routes": [
                    {"path_mode": "prefix", "path_value": "/app"},
                    {
                        "path_mode": "exact",
                        "path_value": "/admin",
                        "http_method": "POST",
                    },
                ]
            },
        },
        {"name": "canonical-restore", "vars": {"custom_routes": []}},
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
    # canonical creates no routes but the whole LB is always imported, so every variant is LIVE.
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
