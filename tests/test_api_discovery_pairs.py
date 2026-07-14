"""Unit tests for the API Discovery all-pairs generator."""

from typing import Any, cast

from api_discovery_pairs import DIMENSIONS, all_pairs, build, payloads


def test_covers_all_pairs() -> None:
    """Every unordered pair of option-values co-occurs in at least one row."""
    rows = all_pairs(DIMENSIONS)
    names = list(DIMENSIONS)
    required: set[tuple[str, str, str, str]] = set()
    for i, ka in enumerate(names):
        for kb in names[i + 1:]:
            for va in DIMENSIONS[ka]:
                for vb in DIMENSIONS[kb]:
                    required.add((ka, va, kb, vb))
    covered: set[tuple[str, str, str, str]] = set()
    for row in rows:
        for i, ka in enumerate(names):
            for kb in names[i + 1:]:
                covered.add((ka, row[ka], kb, row[kb]))
    assert required <= covered


def test_deterministic() -> None:
    """The manifest is byte-stable across runs (no RNG)."""
    assert build() == build()


def test_both_secret_arms_exercised_with_a_crawler() -> None:
    """A crawler variant exists for both clear and blindfold (proves both arms run live)."""
    methods: set[str] = set()
    for variant in build():
        variant_vars = cast("dict[str, Any]", variant["vars"])
        if variant_vars.get("api_crawler_domains") and "api_crawler_password" in variant_vars:
            methods.add(variant_vars["api_crawler_password"]["method"])
    assert {"clear", "blindfold"} <= methods


def test_payloads_strip_pseudo_dimensions() -> None:
    """Pseudo-dimensions never leak; blindfold omits plaintext (harness seals location)."""
    out = payloads({"api_crawler": "one", "secret_method": "blindfold"})
    assert "api_crawler" not in out
    assert "secret_method" not in out
    assert out["api_crawler_password"] == {"method": "blindfold"}

    clear = payloads({"api_crawler": "one", "secret_method": "clear"})
    assert clear["api_crawler_password"] == {
        "method": "clear",
        "plaintext": "Sp1-Cr@wl-Demo",
    }
