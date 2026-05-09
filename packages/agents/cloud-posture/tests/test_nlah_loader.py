"""Tests for the NLAH loader."""

from pathlib import Path

import pytest
from cloud_posture.nlah_loader import default_nlah_dir, load_system_prompt


def test_load_system_prompt_includes_mission(tmp_path: Path) -> None:
    nlah_dir = tmp_path / "nlah"
    nlah_dir.mkdir()
    (nlah_dir / "README.md").write_text("# Mission\nDo X.\n")
    (nlah_dir / "tools.md").write_text("## tool A\nUsed for x.\n")

    prompt = load_system_prompt(nlah_dir=nlah_dir)
    assert "# Mission" in prompt
    assert "Do X." in prompt
    assert "tool A" in prompt


def test_load_system_prompt_includes_examples_in_lex_order(tmp_path: Path) -> None:
    nlah_dir = tmp_path / "nlah"
    nlah_dir.mkdir()
    (nlah_dir / "README.md").write_text("# Top\n")
    (nlah_dir / "tools.md").write_text("# Tools\n")
    examples = nlah_dir / "examples"
    examples.mkdir()
    (examples / "b_second.md").write_text("# Example B\nBar.\n")
    (examples / "a_first.md").write_text("# Example A\nFoo.\n")

    prompt = load_system_prompt(nlah_dir=nlah_dir)
    assert "Example A" in prompt
    assert "Example B" in prompt
    # a_first.md must precede b_second.md (sorted lexicographically).
    assert prompt.find("Example A") < prompt.find("Example B")


def test_load_missing_readme_raises_filenotfound(tmp_path: Path) -> None:
    nlah_dir = tmp_path / "nlah"
    nlah_dir.mkdir()
    # No README.md
    with pytest.raises(FileNotFoundError, match=r"README\.md"):
        load_system_prompt(nlah_dir=nlah_dir)


def test_load_missing_directory_raises_filenotfound(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="NLAH directory"):
        load_system_prompt(nlah_dir=tmp_path / "does-not-exist")


def test_tools_section_optional(tmp_path: Path) -> None:
    """A NLAH with no tools.md should still load (not all agents need a tool index)."""
    nlah_dir = tmp_path / "nlah"
    nlah_dir.mkdir()
    (nlah_dir / "README.md").write_text("# README only\n")

    prompt = load_system_prompt(nlah_dir=nlah_dir)
    assert "# README only" in prompt
    assert "Tools reference" not in prompt


def test_examples_section_optional(tmp_path: Path) -> None:
    nlah_dir = tmp_path / "nlah"
    nlah_dir.mkdir()
    (nlah_dir / "README.md").write_text("# README\n")

    prompt = load_system_prompt(nlah_dir=nlah_dir)
    assert "Few-shot examples" not in prompt


def test_default_nlah_dir_resolves_to_packaged_nlah() -> None:
    """The shipped NLAH directory must be discoverable without an explicit path."""
    path = default_nlah_dir()
    assert path.is_dir()
    assert (path / "README.md").is_file()
    assert (path / "tools.md").is_file()
    assert (path / "examples").is_dir()


def test_default_load_works_without_args() -> None:
    """`load_system_prompt()` with no args loads the shipped NLAH."""
    prompt = load_system_prompt()
    assert "Cloud Posture Agent" in prompt
    assert "Tools reference" in prompt
    assert "Few-shot examples" in prompt
    assert "public_s3" in prompt or "S3 bucket" in prompt
