"""Tests for the Audit Agent's NLAH shim (F.6 Task 10, ADR-007 v1.2).

This file mirrors the test set every post-v1.2 agent ships:

- The shim delegates to `charter.nlah_loader` — no duplicated logic.
- The shim is short (≤35 LOC) — the v1.2 hoist's visible benefit
  vs. D.1's pre-hoist 55-LOC original.
- The NLAH bundle ships with the package: README.md, tools.md, and
  at least one example.
- Standard load-system-prompt assertions: concatenates README +
  tools + examples; tolerates missing optional sections.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from audit.nlah_loader import default_nlah_dir, load_system_prompt

# ---------------------------- shim discipline -----------------------------


def test_shim_is_short_after_v1_2_hoist() -> None:
    """Pre-v1.2 (D.1): 55 LOC. Post-v1.2: ≤35 LOC delegating to
    `charter.nlah_loader`. Asserting the upper bound here makes any
    regression that drags logic back into the per-agent shim trip.
    """
    from audit import nlah_loader

    source = Path(nlah_loader.__file__).read_text()
    line_count = len(source.splitlines())
    assert line_count <= 35, f"shim grew to {line_count} LOC — should remain ≤35 post-v1.2"


def test_shim_imports_charter_canonical_loader() -> None:
    """The shim must reach into `charter.nlah_loader`, not redefine the
    logic locally. Easiest assertion: the source mentions the canonical
    module by name.
    """
    from audit import nlah_loader

    source = Path(nlah_loader.__file__).read_text()
    assert "charter.nlah_loader" in source


# ---------------------------- default NLAH bundle ------------------------


def test_default_nlah_dir_points_inside_package() -> None:
    base = default_nlah_dir()
    assert base.is_dir()
    assert (base / "README.md").is_file()


def test_default_nlah_bundle_ships_tools_and_examples() -> None:
    base = default_nlah_dir()
    assert (base / "tools.md").is_file()
    examples = base / "examples"
    assert examples.is_dir()
    # At least one example so the Few-shot-examples concatenation has data.
    assert any(f.suffix == ".md" for f in examples.iterdir())


def test_load_system_prompt_default_includes_audit_terminology() -> None:
    """The bundled NLAH must mention the agent's name and the action
    constants F.5 emits — these are the cues the LLM uses to translate
    operator NL queries into typed `AuditStore.query` parameters.
    """
    prompt = load_system_prompt()
    assert "Audit Agent" in prompt
    assert "episode_appended" in prompt
    assert "Tools reference" in prompt
    assert "Few-shot examples" in prompt


# ---------------------------- override + concat ---------------------------


def test_load_with_explicit_dir(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# Override NLAH\n\nCustom content.")
    out = load_system_prompt(tmp_path)
    assert "Override NLAH" in out
    assert "Custom content" in out


def test_loader_concatenates_tools_and_examples(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# Header")
    (tmp_path / "tools.md").write_text("# Tool A\n\nDescription")
    examples = tmp_path / "examples"
    examples.mkdir()
    (examples / "001-first.md").write_text("# Example 1")
    (examples / "002-second.md").write_text("# Example 2")

    out = load_system_prompt(tmp_path)
    assert "Header" in out
    assert "Tools reference" in out
    assert "Tool A" in out
    assert "Few-shot examples" in out
    assert out.find("Example 1") < out.find("Example 2")


# ---------------------------- error paths --------------------------------


def test_missing_dir_raises_clearly(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="NLAH directory missing"):
        load_system_prompt(tmp_path / "does-not-exist")
