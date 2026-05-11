"""Tests for `charter.nlah_loader` — the canonical NLAH loader (ADR-007 v1.2)."""

from __future__ import annotations

from pathlib import Path

import pytest
from charter.nlah_loader import default_nlah_dir, load_system_prompt

# ---------------------------- default_nlah_dir ---------------------------


def test_default_nlah_dir_resolves_adjacent_to_package_file(tmp_path: Path) -> None:
    """Pass any file path and get `<that file's parent>/nlah/` back."""
    pkg_file = tmp_path / "module.py"
    pkg_file.write_text("")
    assert default_nlah_dir(pkg_file) == tmp_path / "nlah"


def test_default_nlah_dir_accepts_string_or_path(tmp_path: Path) -> None:
    pkg_file = tmp_path / "module.py"
    pkg_file.write_text("")
    assert default_nlah_dir(str(pkg_file)) == default_nlah_dir(pkg_file)


# ---------------------------- load_system_prompt -------------------------


def test_loader_with_readme_only(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# Solo")
    assert load_system_prompt(tmp_path) == "# Solo"


def test_loader_concatenates_tools_section(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# Header")
    (tmp_path / "tools.md").write_text("# Tool A\n\nDescription")

    out = load_system_prompt(tmp_path)
    assert "Header" in out
    assert "Tools reference" in out
    assert "Tool A" in out


def test_loader_concatenates_examples_in_lex_order(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# Header")
    examples = tmp_path / "examples"
    examples.mkdir()
    (examples / "001-first.md").write_text("# Example 1")
    (examples / "002-second.md").write_text("# Example 2")

    out = load_system_prompt(tmp_path)
    assert "Few-shot examples" in out
    assert out.find("Example 1") < out.find("Example 2")


def test_loader_omits_optional_sections_when_missing(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# Solo")
    out = load_system_prompt(tmp_path)
    assert "Tools reference" not in out
    assert "Few-shot examples" not in out


def test_loader_handles_empty_examples_dir(tmp_path: Path) -> None:
    """An empty `examples/` directory must not emit the header."""
    (tmp_path / "README.md").write_text("# Solo")
    (tmp_path / "examples").mkdir()
    out = load_system_prompt(tmp_path)
    assert "Few-shot examples" not in out


# ---------------------------- error paths --------------------------------


def test_missing_dir_raises_clearly(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="NLAH directory missing"):
        load_system_prompt(tmp_path / "does-not-exist")


def test_missing_readme_raises_clearly(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match=r"README\.md"):
        load_system_prompt(tmp_path)


def test_loader_accepts_string_path(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# Solo")
    assert load_system_prompt(str(tmp_path)) == "# Solo"
