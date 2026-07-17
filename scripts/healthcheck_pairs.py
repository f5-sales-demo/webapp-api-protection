#!/usr/bin/env python3
"""Generate the xcsh_healthcheck (LPC-5a) coverage matrix.

Explicit safe variants over the health-check surface, each applied to the LIVE origin health
check. The type oneof (http/tcp) makes a full cartesian degenerate, so variants are enumerated
directly. EVERY variant must keep the HTTP origin healthy (http on /health with 200 in the
accepted codes, or a tcp connect/send probe on the pool port) so the LB keeps serving —
udp_icmp is intentionally excluded. Ends on canonical-restore (http /health, 200, 3/1/3/15).

Deterministic (no RNG). Output: JSON to stdout, or files via --emit.
"""

import json
import sys
from pathlib import Path

CANONICAL = {
    "health_check_type": "http",
    "hc_http_host_header": None,
    "hc_expected_status_codes": ["200"],
    "hc_expected_response": None,
    "hc_request_headers_to_remove": [],
    "hc_tcp_send_payload": None,
    "hc_tcp_expected_response": None,
    "hc_healthy_threshold": 3,
    "hc_unhealthy_threshold": 1,
    "hc_timeout": 3,
    "hc_interval": 15,
    "hc_jitter_percent": None,
}


def _v(name: str, **overrides: object) -> dict[str, object]:
    """A variant = canonical with the named overrides applied."""
    vars_ = dict(CANONICAL)
    vars_.update(overrides)
    return {"name": name, "vars": vars_}


def build() -> list[dict[str, object]]:
    """Ordered variant manifest. Every http variant keeps 200 in the accepted codes."""
    return [
        _v("http-host-header", hc_http_host_header="www.f5-sales-demo.com"),
        _v(
            "http-codes-range-headers",
            hc_expected_status_codes=["200", "301-302"],
            hc_request_headers_to_remove=["x-debug"],
        ),
        _v(
            "http-tuned-thresholds",
            hc_healthy_threshold=5,
            hc_unhealthy_threshold=2,
            hc_timeout=5,
            hc_interval=30,
            hc_jitter_percent=20,
        ),
        _v("tcp-connect-only", health_check_type="tcp"),
        _v("tcp-send-payload", health_check_type="tcp", hc_tcp_send_payload="50494e47"),
        _v("canonical-restore"),
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
