#!/usr/bin/env python3
"""Generate the L7 DDoS protection (DDoS-1) coverage matrix.

Cycles the LIVE LB through the l7_ddos_protection oneofs — rps (custom vs default),
clientside_action (none/js/captcha), ddos_policy (none/block) — each applied additively (MUD
stays at its default, so the LB keeps serving). Ends on canonical-restore (ddos disabled ->
l7_ddos_protection omitted -> server default, import-suppressed). Deterministic (no RNG).
Output: JSON to stdout, or files via --emit.
"""

import json
import sys
from pathlib import Path


def build() -> list[dict[str, object]]:
    """Ordered variant manifest: l7_ddos_protection oneof combinations + canonical."""
    return [
        {
            "name": "custom-rps-js",
            "vars": {
                "ddos": {
                    "l7_enabled": True,
                    "rps_threshold": 2500,
                    "clientside_action": "js",
                    "cs_cookie_expiry": 3600,
                    "cs_js_script_delay": 2000,
                }
            },
        },
        {
            "name": "default-rps-captcha",
            "vars": {
                "ddos": {
                    "l7_enabled": True,
                    "clientside_action": "captcha",
                    "cs_cookie_expiry": 7200,
                }
            },
        },
        {
            "name": "all-default",
            "vars": {"ddos": {"l7_enabled": True}},
        },
        {
            "name": "canonical-restore",
            "vars": {"ddos": {"l7_enabled": False}},
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
