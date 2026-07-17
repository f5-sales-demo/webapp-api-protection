#!/usr/bin/env python3
"""Classify a whole-LB import round-trip plan for LPC-3 SECRET variants.

jwt_validation.jwks_config.cleartext is a write-only secret: the F5 XC API masks it as
"Redacted" on read, so after `state rm` + `import` the next plan always re-applies the real
value (a 1-change that cannot be avoided — same class as other clear secrets). That single
re-apply is EXPECTED; any OTHER meaningful (known-value) drift on the LB is a real import bug.

This reads `terraform show -json <planfile>` and prints the meaningful config-driven changes
on module.http_lb.xcsh_http_loadbalancer.this, excluding:
  - the allowed jwks_config.cleartext secret re-apply, and
  - computed values the plan marks unknown (after_unknown — e.g. ref tenant recompute).

Exit 0 if nothing unexpected changed (import round-trip clean modulo the secret); exit 1 and
list the offending paths otherwise.

Usage: lpc3_import_check.py <plan.json>
"""

import json
import sys
from pathlib import Path

LB_ADDR = "module.http_lb.xcsh_http_loadbalancer.this"
EXPECTED_ARGC = 2


def flatten(obj: object, prefix: str = "") -> dict[str, object]:
    """Flatten nested dict/list into dotted paths -> scalar leaves.

    An empty dict/list emits a presence sentinel at its own path so that empty-marker oneof
    arms (e.g. action.block {}, target.all_endpoint {}) are detectable — otherwise flipping
    between two empty-marker arms would produce no leaves and hide a real import drift.
    """
    out: dict[str, object] = {}
    if isinstance(obj, dict):
        if not obj and prefix:
            out[prefix] = "<empty>"
        for k, v in obj.items():
            out.update(flatten(v, f"{prefix}.{k}" if prefix else k))
    elif isinstance(obj, list):
        if not obj and prefix:
            out[prefix] = "<empty>"
        for i, v in enumerate(obj):
            out.update(flatten(v, f"{prefix}[{i}]"))
    else:
        out[prefix] = obj
    return out


def unknown_paths(obj: object, prefix: str = "") -> set[str]:
    """Collect dotted paths the plan marks unknown (True leaves in after_unknown)."""
    paths: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            paths |= unknown_paths(v, f"{prefix}.{k}" if prefix else k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            paths |= unknown_paths(v, f"{prefix}[{i}]")
    elif obj is True:
        paths.add(prefix)
    return paths


def meaningful_changes(change: dict[str, object]) -> list[str]:
    """Return LB leaf paths that changed to a KNOWN value (excludes computed-unknown)."""
    before = flatten(change.get("before") or {})
    after = flatten(change.get("after") or {})
    unknown = unknown_paths(change.get("after_unknown") or {})
    changed = [
        path
        for path, aval in after.items()
        if path not in unknown and before.get(path) != aval
    ]
    # deletions (present before, absent after and not unknown)
    changed.extend(p for p in before if p not in after and p not in unknown)
    return changed


def is_allowed(path: str) -> bool:
    """The one expected write-only-secret re-apply."""
    return path.endswith("jwks_config.cleartext") or "jwks_config.cleartext" in path


def main(argv: list[str]) -> int:
    """Parse the plan JSON and report unexpected LB drift."""
    if len(argv) != EXPECTED_ARGC:
        sys.stderr.write("usage: lpc3_import_check.py <plan.json>\n")
        return 2
    plan = json.loads(Path(argv[1]).read_text())
    rc = next(
        (r for r in plan.get("resource_changes", []) if r.get("address") == LB_ADDR),
        None,
    )
    if rc is None:
        sys.stderr.write(f"LB resource_change {LB_ADDR} not found in plan\n")
        return 1
    unexpected = [p for p in meaningful_changes(rc["change"]) if not is_allowed(p)]
    if unexpected:
        sys.stderr.write("unexpected import drift on LB:\n")
        for p in sorted(unexpected):
            sys.stderr.write(f"  {p}\n")
        return 1
    sys.stdout.write("import clean modulo jwks_config.cleartext secret\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
