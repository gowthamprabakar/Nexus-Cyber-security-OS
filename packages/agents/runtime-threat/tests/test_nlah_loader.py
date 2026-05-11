"""Tests for the Runtime Threat NLAH shim (copy-with-rename of D.2's test set).

These tests exercise the shim end-to-end — every call delegates into
`charter.nlah_loader` under the hood per ADR-007 v1.2. The fact that
this file is identical (modulo package name) to the other agents'
test files is the proof that the shim pattern works.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from runtime_threat.nlah_loader import default_nlah_dir, load_system_prompt

# ---------------------------- default NLAH (shipped with package) -----------


def test_default_nlah_dir_points_inside_package() -> None:
    base = default_nlah_dir()
    assert base.is_dir()
    assert (base / "README.md").is_file()


def test_load_system_prompt_default_includes_all_sections() -> None:
    prompt = load_system_prompt()
    assert "Runtime Threat Agent" in prompt
    assert "Tools reference" in prompt
    assert "Few-shot examples" in prompt
    assert "Shell-in-container" in prompt  # example 01
    assert "Clean cluster" in prompt  # example 02


def test_default_examples_in_lex_order() -> None:
    prompt = load_system_prompt()
    shell_idx = prompt.find("Shell-in-container")
    clean_idx = prompt.find("Clean cluster")
    assert 0 < shell_idx < clean_idx


# ---------------------------- override via nlah_dir argument ---------------


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


def test_loader_omits_optional_sections_when_missing(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# Solo")
    out = load_system_prompt(tmp_path)
    assert out == "# Solo"
    assert "Tools reference" not in out
    assert "Few-shot examples" not in out


# ---------------------------- error paths ---------------------------------


def test_missing_dir_raises_clearly(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="NLAH directory missing"):
        load_system_prompt(tmp_path / "does-not-exist")


def test_missing_readme_raises_clearly(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match=r"README\.md"):
        load_system_prompt(tmp_path)
