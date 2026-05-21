"""Tests — ``synthesis.nlah_loader`` + bundled NLAH content (Task 10).

D.13 is the 10th agent shipped natively against ADR-007 v1.2's
21-LOC shim pattern. These tests verify:

1. The shim is a thin re-export over ``charter.nlah_loader`` and
   stays under the ≤35-LOC budget (per the plan).
2. The bundled ``nlah/`` directory ships ``README.md`` + ``tools.md``
   + a 3-example ``examples/`` subdirectory.
3. ``load_system_prompt`` concatenates README + tools + examples.
4. The README documents the Narrator persona + 6-stage pipeline +
   Q6 invariant block.
5. ``tools.md`` declares the in-driver helper surface.
6. The Q6 example walks through the reviewer-retry loop.
"""

from __future__ import annotations

from pathlib import Path

from synthesis.nlah_loader import default_nlah_dir, load_system_prompt

_SHIM_PATH = Path(__file__).parent.parent / "src" / "synthesis" / "nlah_loader.py"
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
    import synthesis.nlah_loader as shim

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
    """Plan §Task 10: 'NLAH bundle ... 3 examples (executive_summary,
    mixed-severity-narrative, q6_substring_rejection)'."""
    examples = sorted((default_nlah_dir() / "examples").glob("*.md"))
    assert len(examples) == 3
    names = {p.name for p in examples}
    # Each example name fragment present
    assert any("executive" in n for n in names)
    assert any("mixed-severity" in n or "mixed_severity" in n for n in names)
    assert any("q6" in n for n in names)


# ---------------------------------------------------------------------------
# load_system_prompt concatenation
# ---------------------------------------------------------------------------


def test_load_system_prompt_returns_non_empty() -> None:
    text = load_system_prompt()
    assert text.strip()


def test_load_system_prompt_includes_readme_content() -> None:
    text = load_system_prompt()
    assert "Narrator persona" in text or "Synthesis Agent" in text


def test_load_system_prompt_includes_tools_md_content() -> None:
    text = load_system_prompt()
    assert "read_sibling_workspaces" in text


def test_load_system_prompt_includes_example_content() -> None:
    text = load_system_prompt()
    assert "[Q6 RETRY]" in text or "q6_violation" in text


def test_load_system_prompt_accepts_explicit_path() -> None:
    """load_system_prompt(None) and load_system_prompt(default) match."""
    a = load_system_prompt()
    b = load_system_prompt(default_nlah_dir())
    assert a == b


# ---------------------------------------------------------------------------
# README content
# ---------------------------------------------------------------------------


def test_readme_documents_pipeline_stages() -> None:
    readme = (default_nlah_dir() / "README.md").read_text(encoding="utf-8")
    for stage in ("INGEST", "ENRICH", "NARRATE", "REVIEW", "SUMMARIZE", "HANDOFF"):
        assert stage in readme, f"pipeline stage {stage} missing from README.md"


def test_readme_carries_q6_invariant_block() -> None:
    """The Q6 invariant block is load-bearing for WI-2 acceptance."""
    readme = (default_nlah_dir() / "README.md").read_text(encoding="utf-8")
    assert "Q6" in readme
    # Sensitive classifier labels named explicitly
    assert "SSN" in readme
    assert "credit-card" in readme.lower() or "credit card" in readme.lower()


def test_readme_lists_three_sibling_sources() -> None:
    """D.7 + D.6 + F.3 must all appear in the persona doc."""
    readme = (default_nlah_dir() / "README.md").read_text(encoding="utf-8")
    assert "D.7" in readme and "Investigation" in readme
    assert "D.6" in readme and "Compliance" in readme
    assert "F.3" in readme and "Cloud Posture" in readme


# ---------------------------------------------------------------------------
# tools.md content
# ---------------------------------------------------------------------------


def test_tools_md_declares_in_driver_helpers() -> None:
    """v0.1 ships no charter-registered tools; the in-driver helpers
    are documented for the LLM's mental model."""
    tools = (default_nlah_dir() / "tools.md").read_text(encoding="utf-8")
    assert "read_sibling_workspaces" in tools
    assert "build_context_bundle" in tools
    assert "narrate" in tools
    assert "review" in tools
