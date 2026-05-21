"""Tests — `curiosity.nlah_loader` + bundled NLAH content (Task 11).

D.12 is the 11th agent shipped natively against ADR-007 v1.2's
21-LOC shim pattern. These tests verify:

1. The shim is a thin re-export over ``charter.nlah_loader`` and
   stays under the ≤35-LOC budget (per the plan).
2. The bundled ``nlah/`` directory ships ``README.md`` + ``tools.md``
   + a 3-example ``examples/`` subdirectory.
3. ``load_system_prompt`` concatenates README + tools + examples.
4. The README documents the Curiosity persona + 7-stage pipeline +
   Q6 invariant + ADR-012 reference.
5. ``tools.md`` declares the in-driver helper surface.
6. The Q6 example walks through the reviewer-retry loop.
"""

from __future__ import annotations

from pathlib import Path

from curiosity.nlah_loader import default_nlah_dir, load_system_prompt

_SHIM_PATH = Path(__file__).parent.parent / "src" / "curiosity" / "nlah_loader.py"
_LOC_BUDGET = 35


# ---------------------------------------------------------------------------
# 21-LOC shim conformance (ADR-007 v1.2)
# ---------------------------------------------------------------------------


def test_nlah_loader_under_loc_budget() -> None:
    """ADR-007 v1.2: per-agent NLAH shim must be a thin re-export.

    The plan specifies a ~21-LOC shim; the LOC budget here is set
    at 35 to leave room for the module docstring + imports."""
    line_count = sum(1 for _ in _SHIM_PATH.read_text().splitlines())
    assert line_count <= _LOC_BUDGET, (
        f"nlah_loader.py grew to {line_count} lines (budget {_LOC_BUDGET})"
    )


def test_nlah_loader_reexports_from_charter() -> None:
    """The shim's public surface is the same shape charter offers."""
    import curiosity.nlah_loader as shim

    assert callable(shim.default_nlah_dir)
    assert callable(shim.load_system_prompt)
    assert set(shim.__all__) == {"default_nlah_dir", "load_system_prompt"}


# ---------------------------------------------------------------------------
# NLAH directory layout
# ---------------------------------------------------------------------------


def test_default_nlah_dir_exists() -> None:
    nlah = default_nlah_dir()
    assert nlah.is_dir(), f"NLAH dir missing: {nlah}"


def test_nlah_readme_present() -> None:
    nlah = default_nlah_dir()
    assert (nlah / "README.md").is_file()


def test_nlah_tools_present() -> None:
    nlah = default_nlah_dir()
    assert (nlah / "tools.md").is_file()


def test_nlah_examples_dir_present() -> None:
    nlah = default_nlah_dir()
    assert (nlah / "examples").is_dir()


def test_nlah_ships_three_examples() -> None:
    """Plan §Task 11: 3 examples covering region-gap, q6-rejection,
    fabric-publish."""
    examples = sorted((default_nlah_dir() / "examples").glob("*.md"))
    assert len(examples) == 3
    names = {p.name for p in examples}
    assert any("region-gap" in n for n in names)
    assert any("q6" in n for n in names)
    assert any("fabric" in n or "publish" in n for n in names)


# ---------------------------------------------------------------------------
# load_system_prompt concatenation
# ---------------------------------------------------------------------------


def test_load_system_prompt_returns_non_empty() -> None:
    text = load_system_prompt()
    assert text.strip()


def test_load_system_prompt_includes_readme_content() -> None:
    text = load_system_prompt()
    assert "Curiosity Agent" in text or "Curiosity persona" in text


def test_load_system_prompt_includes_tools_md_content() -> None:
    text = load_system_prompt()
    assert "read_sibling_state" in text
    assert "detect_coverage_gaps" in text


def test_load_system_prompt_includes_example_content() -> None:
    text = load_system_prompt()
    assert "[Q6 RETRY]" in text or "q6_violation" in text or "Pass 1" in text


def test_load_system_prompt_accepts_explicit_path() -> None:
    """load_system_prompt(None) and load_system_prompt(default) match."""
    a = load_system_prompt()
    b = load_system_prompt(default_nlah_dir())
    assert a == b


# ---------------------------------------------------------------------------
# README content
# ---------------------------------------------------------------------------


def test_readme_documents_7_pipeline_stages() -> None:
    readme = (default_nlah_dir() / "README.md").read_text(encoding="utf-8")
    for stage in (
        "INGEST",
        "DETECT",
        "HYPOTHESIZE",
        "REVIEW",
        "PERSIST",
        "PUBLISH",
        "HANDOFF",
    ):
        assert stage in readme, f"pipeline stage {stage} missing from README.md"


def test_readme_carries_q6_invariant_block() -> None:
    """The Q6 invariant block is load-bearing for WI-2 acceptance."""
    readme = (default_nlah_dir() / "README.md").read_text(encoding="utf-8")
    assert "Q6" in readme
    # Sensitive classifier labels named explicitly
    assert "SSN" in readme
    assert "credit-card" in readme.lower() or "credit card" in readme.lower()


def test_readme_references_adr_012_and_claims_substrate() -> None:
    """D.12 is the first publisher on the claims.> substrate; the
    NLAH must name the ADR + substrate so the LLM understands its
    novel role in the fleet."""
    readme = (default_nlah_dir() / "README.md").read_text(encoding="utf-8")
    assert "ADR-012" in readme
    assert "claims.>" in readme or "claims.tenant" in readme


def test_readme_mentions_region_gap_detector() -> None:
    """v0.1 ships region-gap only; the persona must explain the
    detector floor so the LLM grounds its hypotheses correctly."""
    readme = (default_nlah_dir() / "README.md").read_text(encoding="utf-8")
    assert "region-gap" in readme.lower() or "region gap" in readme.lower()
    assert "10 assets" in readme or "≥10 assets" in readme


# ---------------------------------------------------------------------------
# tools.md content
# ---------------------------------------------------------------------------


def test_tools_md_declares_in_driver_helpers() -> None:
    """v0.1 ships no charter-registered tools; the in-driver helpers
    are documented for the LLM's mental model."""
    tools = (default_nlah_dir() / "tools.md").read_text(encoding="utf-8")
    assert "read_sibling_state" in tools
    assert "detect_coverage_gaps" in tools
    assert "hypothesize" in tools
    assert "review" in tools
    assert "upsert_hypotheses" in tools
    assert "publish_claims" in tools


def test_tools_md_references_adr_012_acl() -> None:
    """The subscriber-ACL fence is the load-bearing safety mechanism;
    tools.md must mention it so future maintainers understand why
    D.12 is producer-only."""
    tools = (default_nlah_dir() / "tools.md").read_text(encoding="utf-8")
    assert "ADR-012" in tools
    assert "ACL" in tools or "fence" in tools.lower()
