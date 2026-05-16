"""Tests for `remediation.nlah_loader` — ADR-007 v1.2 shim conformance."""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest
from remediation.nlah_loader import default_nlah_dir, load_system_prompt

# ---------------------------- discovery -----------------------------------


def test_default_nlah_dir_resolves_to_package() -> None:
    """Returns the nlah/ directory shipped inside the package."""
    d = default_nlah_dir()
    assert isinstance(d, Path)
    assert d.is_dir()
    assert d.name == "nlah"


def test_default_nlah_dir_contains_readme_tools_examples() -> None:
    """The bundle is a README + tools.md + examples/ — the canonical ADR-007 v1.2 shape."""
    d = default_nlah_dir()
    assert (d / "README.md").is_file()
    assert (d / "tools.md").is_file()
    assert (d / "examples").is_dir()


def test_nlah_bundle_ships_three_examples() -> None:
    """A.1 ships one example per operational tier: recommend / dry-run / execute."""
    d = default_nlah_dir()
    examples = sorted((d / "examples").glob("*.md"))
    assert len(examples) == 3
    names = [e.stem for e in examples]
    assert any("recommend" in n for n in names)
    assert any("dry-run" in n or "dry_run" in n for n in names)
    assert any("execute" in n for n in names)


# ---------------------------- load_system_prompt --------------------------


def test_load_system_prompt_with_default_dir_returns_nonempty_text() -> None:
    """The loader stitches README + tools.md + each example into a single prompt."""
    prompt = load_system_prompt()
    assert isinstance(prompt, str)
    assert len(prompt) > 1000  # README alone is ~3KB; the stitched prompt is bigger
    # The headline content appears.
    assert "Remediation Agent" in prompt
    assert "recommend" in prompt
    assert "dry-run" in prompt or "dry_run" in prompt
    assert "execute" in prompt


def test_load_system_prompt_accepts_string_path() -> None:
    """The loader normalises a `str` argument to a Path (operators may pass either)."""
    prompt_via_str = load_system_prompt(str(default_nlah_dir()))
    prompt_via_path = load_system_prompt(default_nlah_dir())
    assert prompt_via_str == prompt_via_path


def test_load_system_prompt_accepts_custom_dir(tmp_path: Path) -> None:
    """Operators can override the NLAH directory at run time (used by Meta-Harness
    to A/B-test alternative prompts before deploying)."""
    custom_dir = tmp_path / "custom-nlah"
    custom_dir.mkdir()
    (custom_dir / "README.md").write_text("custom remediation agent")
    (custom_dir / "tools.md").write_text("custom tools section")
    (custom_dir / "examples").mkdir()
    (custom_dir / "examples" / "01-test.md").write_text("custom example")

    prompt = load_system_prompt(custom_dir)
    assert "custom remediation agent" in prompt
    assert "custom tools section" in prompt
    assert "custom example" in prompt


# ---------------------------- ADR-007 v1.2 conformance --------------------


def test_nlah_loader_is_21_loc_shim() -> None:
    """A.1 is the 7th native v1.2 agent. The shim must delegate to charter — under
    35 LOC of executable code (the canonical v1.2 threshold)."""
    from remediation import nlah_loader

    source = Path(nlah_loader.__file__).read_text()
    # Count non-blank, non-comment, non-docstring lines.
    in_docstring = False
    loc = 0
    for line in source.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # Toggle docstring state (handles single-line and triple-quote pairs).
        if stripped.startswith(('"""', "'''")):
            in_docstring = not in_docstring
            # If the docstring opens AND closes on the same line, flip back.
            if stripped.count('"""') == 2 or stripped.count("'''") == 2:
                in_docstring = not in_docstring
            continue
        if in_docstring:
            continue
        if stripped.startswith("#"):
            continue
        loc += 1
    assert loc <= 35, f"nlah_loader.py is {loc} LOC; ADR-007 v1.2 threshold is 35"


def test_default_nlah_dir_signature_is_zero_args() -> None:
    """No args — the shim resolves the path from the package's own `__file__`."""
    sig = inspect.signature(default_nlah_dir)
    assert len(sig.parameters) == 0


def test_load_system_prompt_signature_accepts_optional_dir() -> None:
    """One optional argument: `nlah_dir: Path | str | None = None`."""
    sig = inspect.signature(load_system_prompt)
    assert "nlah_dir" in sig.parameters
    assert sig.parameters["nlah_dir"].default is None


# ---------------------------- error contract ------------------------------


def test_load_system_prompt_with_missing_dir_raises(tmp_path: Path) -> None:
    """An NLAH dir that doesn't exist raises clearly — the loader doesn't silently
    produce an empty prompt."""
    missing = tmp_path / "does-not-exist"
    with pytest.raises((FileNotFoundError, ValueError, OSError)):
        load_system_prompt(missing)
