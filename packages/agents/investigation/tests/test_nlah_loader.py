"""Tests for the Investigation Agent's NLAH shim (D.7 Task 10, ADR-007 v1.2).

D.7 is the **third agent** built natively against v1.2 (after D.3 + F.6).
The shim must remain ≤35 LOC — the v1.2 hoist's visible benefit vs.
D.1's pre-hoist 55-LOC original.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from investigation.nlah_loader import default_nlah_dir, load_system_prompt

# ---------------------------- shim discipline -----------------------------


def test_shim_is_short_after_v1_2_hoist() -> None:
    from investigation import nlah_loader

    source = Path(nlah_loader.__file__).read_text()
    line_count = len(source.splitlines())
    assert line_count <= 35, f"shim grew to {line_count} LOC — should remain ≤35 post-v1.2"


def test_shim_imports_charter_canonical_loader() -> None:
    from investigation import nlah_loader

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
    assert any(f.suffix == ".md" for f in examples.iterdir())


def test_load_system_prompt_default_includes_investigation_terminology() -> None:
    """The NLAH bundle must mention the agent's name, the six-stage pipeline,
    the orchestrator-workers pattern, and the four sub-agent flavors —
    these are the cues the LLM uses to generate consistent hypotheses.
    """
    prompt = load_system_prompt()
    assert "Investigation Agent" in prompt
    assert "Orchestrator-Workers" in prompt or "orchestrator-workers" in prompt.lower()
    # Six-stage pipeline
    for stage in ("SCOPE", "SPAWN", "SYNTHESIZE", "VALIDATE", "PLAN", "HANDOFF"):
        assert stage in prompt
    # Four sub-agent flavors
    for flavor in ("timeline", "ioc_pivot", "asset_enum", "attribution"):
        assert flavor in prompt


# ---------------------------- override + concat ---------------------------


def test_load_with_explicit_dir(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# Override NLAH\n\nCustom content.")
    out = load_system_prompt(tmp_path)
    assert "Override NLAH" in out
    assert "Custom content" in out


def test_loader_concatenates_tools_and_examples(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# Header")
    (tmp_path / "tools.md").write_text("# Tool X\n\nDescription")
    examples = tmp_path / "examples"
    examples.mkdir()
    (examples / "001-first.md").write_text("# Example 1")
    (examples / "002-second.md").write_text("# Example 2")

    out = load_system_prompt(tmp_path)
    assert "Header" in out
    assert "Tools reference" in out
    assert "Tool X" in out
    assert "Few-shot examples" in out
    assert out.find("Example 1") < out.find("Example 2")


# ---------------------------- error paths --------------------------------


def test_missing_dir_raises_clearly(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="NLAH directory missing"):
        load_system_prompt(tmp_path / "does-not-exist")
