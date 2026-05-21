"""Tests — `meta_harness.nlah_loader` + bundled NLAH content (Task 11).

A.4 is the 12th agent shipped natively against ADR-007 v1.2's
21-LOC shim pattern. 16 tests verifying:

1.  21-LOC shim under the ≤35-line budget (per plan + ADR-007 v1.2).
2.  Shim public surface matches charter's contract.
3.  Default NLAH directory exists.
4.  README.md present.
5.  tools.md present.
6.  examples/ subdirectory present.
7.  Three examples shipped (batch-eval / ab-compare / first-run).
8.  load_system_prompt returns non-empty content.
9.  load_system_prompt includes README.
10. load_system_prompt includes tools.md.
11. load_system_prompt includes example content.
12. load_system_prompt(None) == load_system_prompt(default_dir).
13. README documents all 6 pipeline stages.
14. README carries the WI-4 read-only invariant block.
15. README carries the WI-5 v0.2 subscriber-ACL carry-forward.
16. tools.md declares the four in-driver helper groups.
"""

from __future__ import annotations

from pathlib import Path

from meta_harness.nlah_loader import default_nlah_dir, load_system_prompt

_SHIM_PATH = Path(__file__).parent.parent / "src" / "meta_harness" / "nlah_loader.py"
_LOC_BUDGET = 35


# ---------------------------------------------------------------------------
# 21-LOC shim conformance
# ---------------------------------------------------------------------------


def test_nlah_loader_under_loc_budget() -> None:
    line_count = sum(1 for _ in _SHIM_PATH.read_text().splitlines())
    assert line_count <= _LOC_BUDGET, (
        f"nlah_loader.py grew to {line_count} lines (budget {_LOC_BUDGET})"
    )


def test_nlah_loader_reexports_from_charter() -> None:
    import meta_harness.nlah_loader as shim

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
    """Plan §Task 11: 3 examples covering batch-eval / ab-compare /
    first-run-baseline."""
    examples = sorted((default_nlah_dir() / "examples").glob("*.md"))
    assert len(examples) == 3
    names = {p.name for p in examples}
    assert any("batch-eval" in n for n in names)
    assert any("ab-compare" in n for n in names)
    assert any("first-run" in n or "baseline" in n for n in names)


# ---------------------------------------------------------------------------
# load_system_prompt concatenation
# ---------------------------------------------------------------------------


def test_load_system_prompt_returns_non_empty() -> None:
    assert load_system_prompt().strip()


def test_load_system_prompt_includes_readme_content() -> None:
    text = load_system_prompt()
    assert "Meta-Harness Agent" in text or "Meta-Harness persona" in text


def test_load_system_prompt_includes_tools_md_content() -> None:
    text = load_system_prompt()
    assert "parse_nlah_dir" in text
    assert "BatchEvalRunner" in text
    assert "ab_compare" in text


def test_load_system_prompt_includes_example_content() -> None:
    text = load_system_prompt()
    # Batch-eval example
    assert "meta-harness run" in text
    # A/B compare example
    assert "meta-harness ab-compare" in text
    # First-run baseline example
    assert "baseline" in text.lower()


def test_load_system_prompt_accepts_explicit_path() -> None:
    a = load_system_prompt()
    b = load_system_prompt(default_nlah_dir())
    assert a == b


# ---------------------------------------------------------------------------
# README content
# ---------------------------------------------------------------------------


def test_readme_documents_all_pipeline_stages() -> None:
    readme = (default_nlah_dir() / "README.md").read_text(encoding="utf-8")
    for stage in ("INTROSPECT", "BATCH_EVAL", "AB_COMPARE", "DELTA", "REPORT", "HANDOFF"):
        assert stage in readme, f"pipeline stage {stage} missing from README.md"


def test_readme_carries_wi4_read_only_block() -> None:
    """WI-4 read-only invariant must be load-bearing in the persona."""
    readme = (default_nlah_dir() / "README.md").read_text(encoding="utf-8")
    assert "read-only" in readme.lower()
    assert "WI-4" in readme


def test_readme_carries_wi5_v02_carry_forward() -> None:
    """WI-5 — the v0.2 subscriber-ACL review carry-forward must be
    explicitly named so the v0.2 plan author can't miss it."""
    readme = (default_nlah_dir() / "README.md").read_text(encoding="utf-8")
    assert "WI-5" in readme
    assert "ADR-012" in readme


# ---------------------------------------------------------------------------
# tools.md content
# ---------------------------------------------------------------------------


def test_tools_md_declares_in_driver_helpers() -> None:
    """v0.1 ships no charter-registered tools; the four in-driver
    helper groups are documented for the LLM's mental model."""
    tools = (default_nlah_dir() / "tools.md").read_text(encoding="utf-8")
    assert "parse_nlah_dir" in tools
    assert "BatchEvalRunner" in tools
    assert "ab_compare" in tools
    assert "compute_batch_deltas" in tools
    assert "flag_regressions" in tools


def test_tools_md_documents_additive_audit_actions() -> None:
    """Per Q6, A.4 emits four additive audit-action entries via the
    F.6 hash-chain. Surface them in tools.md so the LLM's mental
    model reflects the audit trail."""
    tools = (default_nlah_dir() / "tools.md").read_text(encoding="utf-8")
    for action in (
        "meta_harness.batch_eval.started",
        "meta_harness.batch_eval.completed",
        "meta_harness.regression_detected",
        "meta_harness.ab_comparison.completed",
    ):
        assert action in tools, f"audit-action {action} missing from tools.md"
