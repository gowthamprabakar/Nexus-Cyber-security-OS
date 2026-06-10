"""D.8 v0.2 Task 10 — customer industry profile loading tests."""

from __future__ import annotations

from pathlib import Path

from threat_intel.customer.industry_profile import (
    IndustryProfile,
    load_industry_profile,
    load_industry_profile_from_path,
    normalize_industry,
    parse_industry,
)


def test_normalize_industry() -> None:
    assert normalize_industry("Financial Services") == "financial-services"
    assert normalize_industry("financial_services") == "financial-services"


def test_parse_industry_yaml_frontmatter() -> None:
    assert parse_industry("---\nindustry: healthcare\ntier: gold\n---\n") == "healthcare"


def test_parse_industry_markdown_line() -> None:
    assert (
        parse_industry("# Customer\n\n**Industry:** Financial Services\n") == "Financial Services"
    )


def test_parse_industry_absent() -> None:
    assert parse_industry("# Customer\nno vertical here\n") is None


def test_load_known_industry_maps_vertical_and_keywords() -> None:
    prof = load_industry_profile("industry: financial-services")
    assert prof == IndustryProfile(
        industry="financial-services",
        vertical="finance",
        keywords=("banking", "payment", "fintech", "swift"),
    )


def test_load_unknown_industry_is_other_but_still_loaded() -> None:
    prof = load_industry_profile("industry: aerospace")
    assert prof is not None
    assert prof.industry == "aerospace" and prof.vertical == "other" and prof.keywords == ()


def test_load_no_industry_returns_none() -> None:
    assert load_industry_profile("nothing relevant") is None


def test_load_from_path(tmp_path: Path) -> None:
    p = tmp_path / "customer_context.md"
    p.write_text("**Industry:** Healthcare\n", encoding="utf-8")
    prof = load_industry_profile_from_path(p)
    assert prof is not None and prof.vertical == "healthcare"


def test_load_from_missing_path_returns_none(tmp_path: Path) -> None:
    assert load_industry_profile_from_path(tmp_path / "nope.md") is None
