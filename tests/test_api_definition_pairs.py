"""Unit tests for the API Definition (SP2) all-pairs generator.

Backfilled in Coverage Batch A — the SP2 generator shipped without a unit test
(unlike the SP1/SP3/SP4/SP5 generators), leaving its dedup + constraint-reconciliation
logic unverified.
"""

import itertools
import json
from typing import Any, cast

from api_definition_pairs import DIMENSIONS, all_pairs, build, payloads


def json_dump(obj: object) -> str:
    return json.dumps(obj, sort_keys=True)


def test_covers_all_pairs() -> None:
    """Every value-pair from distinct dimensions co-occurs in at least one row."""
    rows = all_pairs(DIMENSIONS)
    names = list(DIMENSIONS)
    for i, j in itertools.combinations(range(len(names)), 2):
        for vi in DIMENSIONS[names[i]]:
            for vj in DIMENSIONS[names[j]]:
                assert any(r[names[i]] == vi and r[names[j]] == vj for r in rows), (
                    f"pair ({names[i]}={vi}, {names[j]}={vj}) uncovered"
                )


def test_deterministic() -> None:
    """build() is stable across calls (no RNG / set-iteration leakage)."""
    first = json_dump(build())
    assert json_dump(build()) == first
    assert json_dump(build()) == first


def test_dedup_no_identical_payloads() -> None:
    """The reconciliation dedup collapses byte-identical payloads."""
    seen = set()
    for v in build():
        key = json_dump(cast("dict[str, Any]", v["vars"]))
        assert key not in seen, f"duplicate payload: {v['name']}"
        seen.add(key)


def test_canonical_restore_is_last() -> None:
    """The final variant restores canonical (definition/discovery off)."""
    assert build()[-1]["name"] == "canonical-restore"


def test_blindfold_token_is_skip() -> None:
    """A blindfold access_token row is flagged skip (F5 XC 500 platform limit)."""
    saw_blindfold = False
    for row in all_pairs(DIMENSIONS):
        _, skip = payloads(row)
        if row.get("token_method") == "blindfold" and row.get("integration") != "off":
            saw_blindfold = True
            assert skip, "blindfold access_token variant must carry a skip reason"
    assert saw_blindfold, "generator never produced a blindfold integration row"


def test_secret_never_holds_real_token() -> None:
    """The manifest carries only the swagger placeholder / no real secret value."""
    for v in build():
        blob = json_dump(cast("dict[str, Any]", v["vars"]))
        assert "ghp_" not in blob, (
            f"real GitHub token leaked into manifest: {v['name']}"
        )
