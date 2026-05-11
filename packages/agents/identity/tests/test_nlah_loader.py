"""Tests for the Identity NLAH loader (copy-with-rename of D.1's test set)."""

from __future__ import annotations

from pathlib import Path

import pytest
from identity.nlah_loader import default_nlah_dir, load_system_prompt

# ---------------------------- default NLAH (shipped with package) -----------


def test_default_nlah_dir_points_inside_package() -> None:
    base = default_nlah_dir()
    assert base.is_dir()
    assert (base / "README.md").is_file()


def test_load_system_prompt_default_includes_all_sections() -> None:
    prompt = load_system_prompt()
    assert "Identity Agent" in prompt
    assert "Tools reference" in prompt
    assert "Few-shot examples" in prompt
    assert "Admin user without MFA" in prompt  # example 01
    assert "Clean account" in prompt  # example 02


def test_default_examples_in_lex_order() -> None:
    prompt = load_system_prompt()
    admin_idx = prompt.find("Admin user without MFA")
    clean_idx = prompt.find("Clean account")
    assert 0 < admin_idx < clean_idx


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
