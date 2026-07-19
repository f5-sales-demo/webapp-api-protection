#!/usr/bin/env python3
"""Generate the LB challenge_type coverage matrix (CH-1 foundation + simple arms).

Cycles the LIVE LB through each arm of the unified `challenge` variable (which owns the LB
challenge_type oneof): js / captcha (challenge all traffic, standalone — MUD off), enable /
policy_based (MUD auto-mitigation carriers — MUD on, mitigation ref attached), and none. Ends
on canonical-restore (challenge unset -> derives the MUD default enable+attach, the live LB's
normal state).

Standalone js/captcha run with mud_enabled=false so the oneof is theirs alone; the MUD-carrier
arms run with mud_enabled=true. Deterministic (no RNG). Output: JSON to stdout, or files via
--emit.
"""

import json
import sys
from pathlib import Path


def build() -> list[dict[str, object]]:
    """Ordered variant manifest: each challenge arm + canonical (MUD default)."""
    return [
        {
            "name": "js-all-traffic",
            "vars": {
                "mud_enabled": False,
                "challenge": {
                    "mode": "js",
                    "cookie_expiry": 3600,
                    "js_script_delay": 5000,
                },
            },
        },
        {
            "name": "captcha-all-traffic",
            "vars": {
                "mud_enabled": False,
                "challenge": {"mode": "captcha", "cookie_expiry": 7200},
            },
        },
        {
            "name": "enable-mud",
            "vars": {
                "mud_enabled": True,
                "challenge": {
                    "mode": "enable",
                    "attach_malicious_user_mitigation": True,
                },
            },
        },
        {
            "name": "policy-based-mud",
            "vars": {
                "mud_enabled": True,
                "challenge": {
                    "mode": "policy_based",
                    "attach_malicious_user_mitigation": True,
                },
            },
        },
        {
            "name": "none",
            "vars": {"mud_enabled": False, "challenge": {"mode": "none"}},
        },
        {
            # Canonical: challenge unset + MUD on -> derives enable + attach (the live default).
            "name": "canonical-restore",
            "vars": {"mud_enabled": True, "challenge": {}},
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
