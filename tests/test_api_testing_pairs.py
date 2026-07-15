"""Unit tests for the API Testing (SP4) all-pairs generator."""

import itertools
import json
from typing import Any, cast

import api_testing_pairs as m


def test_covers_all_pairs() -> None:
    """Every value-pair from distinct dimensions co-occurs in at least one row."""
    rows = m.all_pairs(m.DIMENSIONS)
    names = list(m.DIMENSIONS)
    for i, j in itertools.combinations(range(len(names)), 2):
        for vi in m.DIMENSIONS[names[i]]:
            for vj in m.DIMENSIONS[names[j]]:
                assert any(r[names[i]] == vi and r[names[j]] == vj for r in rows), (
                    f"pair ({names[i]}={vi}, {names[j]}={vj}) uncovered"
                )


def json_dump(obj: object) -> str:
    return json.dumps(obj, sort_keys=True)


def test_deterministic() -> None:
    """build() is stable across calls (no RNG / set-iteration order leakage)."""
    first = json_dump(m.build())
    assert json_dump(m.build()) == first
    assert json_dump(m.build()) == first


def test_dedup_no_identical_payloads() -> None:
    """No two emitted variants share a byte-identical tfvars payload."""
    seen = set()
    for v in m.build():
        key = json_dump(v["vars"])
        assert key not in seen, f"duplicate payload: {v['name']}"
        seen.add(key)


def test_canonical_restore_is_last_and_off() -> None:
    """The final variant restores canonical (API testing off)."""
    last = m.build()[-1]
    assert last["name"] == "canonical-restore"
    variant_vars = cast("dict[str, Any]", last["vars"])
    assert variant_vars["api_testing_choice"] == "disable"
    assert variant_vars["api_testing_standalone_enabled"] is False


def test_flags_match_secret_arms() -> None:
    """Every credential carries a secret; clear => SECRET, blindfold => SKIP."""
    for v in m.build():
        if v["name"] == "canonical-restore":
            assert v["flag"] == "LIVE"
            continue
        variant_vars = cast("dict[str, Any]", v["vars"])
        creds = variant_vars["api_testing_domains"][0]["credentials"][0]
        assert creds["auth_type"] in ("api_key", "basic_auth", "bearer_token")
        secret = creds["secret"]
        flag = cast(str, v["flag"])
        if secret["method"] == "blindfold":
            assert flag.startswith("SKIP:")
            assert secret["location"] == m.BF_PLACEHOLDER
        else:
            assert flag == "SECRET"
            assert secret["plaintext"] == m.CLEAR_VALUE_MARKER


def test_secret_never_holds_real_value() -> None:
    """The manifest must carry only placeholders, never a real secret."""
    for v in m.build():
        variant_vars = cast("dict[str, Any]", v["vars"])
        blob = json_dump(variant_vars)
        for cred in variant_vars.get("api_testing_domains", [{}])[0].get(
            "credentials", []
        ):
            sec = cred.get("secret")
            if sec and sec["method"] == "clear":
                assert sec["plaintext"] == m.CLEAR_VALUE_MARKER, blob


def test_schedule_only_on_standalone_surfaces() -> None:
    """schedule is emitted only when a standalone resource exists."""
    for v in m.build():
        vs = cast("dict[str, Any]", v["vars"])
        if vs.get("api_testing_standalone_enabled"):
            assert "api_testing_schedule" in vs
        elif v["name"] != "canonical-restore":
            assert "api_testing_schedule" not in vs
