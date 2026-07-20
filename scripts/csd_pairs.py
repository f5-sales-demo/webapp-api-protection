#!/usr/bin/env python3
"""Generate the Client-Side Defense (CSD) policy coverage matrix.

Cycles the LIVE LB through the client_side_defense.policy js_insert oneof arms: disabled
(disable_js_insert), all_except (js_insert_all_pages_except + exclude_list), all_except with regex
domain/path matchers, and insertion_rules (js_insertion_rules + rules + nested exclude_list). Ends
on canonical-restore (all_pages, the default the merged baseline uses). csd_enabled stays true.
Deterministic. Output: JSON to stdout, or files via --emit.
"""

import json
import sys
from pathlib import Path


def build() -> list[dict[str, object]]:
    """Ordered variant manifest: js_insert arms + canonical (all_pages)."""
    return [
        {"name": "disabled", "vars": {"csd": {"js_insert": "disabled"}}},
        {
            "name": "all-except",
            "vars": {
                "csd": {
                    "js_insert": "all_except",
                    "exclude_list": [
                        {
                            "name": "skip-admin",
                            "domain_mode": "suffix",
                            "domain_value": "f5-sales-demo.com",
                            "path_mode": "prefix",
                            "path_value": "/admin",
                        },
                        {
                            "name": "skip-health",
                            "domain_mode": "any",
                            "path_mode": "exact",
                            "path_value": "/health",
                        },
                    ],
                }
            },
        },
        {
            "name": "insertion-rules",
            "vars": {
                "csd": {
                    "js_insert": "insertion_rules",
                    "insertion_rules": {
                        "rules": [
                            {
                                "name": "ins-home",
                                "domain_mode": "any",
                                "path_mode": "prefix",
                                "path_value": "/",
                            },
                            {
                                "name": "ins-checkout",
                                "description": "checkout pages",
                                "domain_mode": "suffix",
                                "domain_value": "f5-sales-demo.com",
                                "path_mode": "exact",
                                "path_value": "/csd-demo/",
                            },
                        ],
                        "exclude_list": [
                            {
                                "name": "skip-health",
                                "domain_mode": "any",
                                "path_mode": "exact",
                                "path_value": "/health",
                            },
                        ],
                    },
                }
            },
        },
        {
            "name": "all-except-regex",
            "vars": {
                "csd": {
                    "js_insert": "all_except",
                    "exclude_list": [
                        {
                            "name": "skip-regex",
                            "domain_mode": "regex",
                            "domain_value": "cdn[.].*",
                            "path_mode": "regex",
                            "path_value": "^/static/.*$",
                        },
                    ],
                }
            },
        },
        {"name": "canonical-restore", "vars": {"csd": {"js_insert": "all_pages"}}},
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
