"""Unit tests for the API Protection (SP3) all-pairs generator."""

import json
from typing import Any, cast

from api_protection_pairs import DIMENSIONS, all_pairs, build, payloads


def test_covers_all_pairs() -> None:
    """Every unordered pair of option-values co-occurs in at least one row."""
    rows = all_pairs(DIMENSIONS)
    names = list(DIMENSIONS)
    required: set[tuple[str, str, str, str]] = set()
    for i, ka in enumerate(names):
        for kb in names[i + 1 :]:
            for va in DIMENSIONS[ka]:
                for vb in DIMENSIONS[kb]:
                    required.add((ka, va, kb, vb))
    covered: set[tuple[str, str, str, str]] = set()
    for row in rows:
        for i, ka in enumerate(names):
            for kb in names[i + 1 :]:
                covered.add((ka, row[ka], kb, row[kb]))
    assert required <= covered


def test_deterministic() -> None:
    """The manifest is byte-stable across runs (no RNG)."""
    assert build() == build()


def test_dedup_no_identical_payloads() -> None:
    """Emitted variant payloads are unique (constraint reconciliation is deduped)."""
    keys = [
        json.dumps(cast("dict[str, Any]", v["vars"]), sort_keys=True) for v in build()
    ]
    assert len(keys) == len(set(keys))


def test_custom_list_validation_covered() -> None:
    """At least one variant exercises the validation_custom_list arm."""
    assert any(
        cast("dict[str, Any]", v["vars"]).get("api_specification_validation")
        == "custom_list"
        for v in build()
    )


def test_canonical_restore_is_last_and_off() -> None:
    """The final variant restores canonical (all SP3 off)."""
    last = build()[-1]
    assert last["name"] == "canonical-restore"
    variant_vars = cast("dict[str, Any]", last["vars"])
    assert variant_vars["rate_limit_choice"] == "disable"
    assert variant_vars["api_definition_choice"] == "disable"


def test_payloads_reconciles_api_protection_action() -> None:
    """api_protection allow/deny maps to a single rule with that action."""
    out = payloads({"api_protection": "deny", "client_matcher": "any"})
    rules = cast("list[dict[str, Any]]", out["api_protection_rules"])
    assert rules[0]["action"] == "deny"
