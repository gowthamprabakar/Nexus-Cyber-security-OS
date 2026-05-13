"""Tests for `network_threat.nlah_loader` — D.4's ADR-007 v1.2 shim.

D.4 is the fourth agent shipped natively against v1.2 (D.3 + F.6 + D.7 + D.4).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from network_threat.nlah_loader import default_nlah_dir, load_system_prompt


def test_default_nlah_dir_resolves_to_package() -> None:
    d = default_nlah_dir()
    assert isinstance(d, Path)
    assert d.is_dir()
    assert d.name == "nlah"
    # Must sit inside the network_threat package.
    assert "network_threat" in str(d).split("/")


def test_default_nlah_dir_has_readme() -> None:
    d = default_nlah_dir()
    assert (d / "README.md").is_file()


def test_default_nlah_dir_has_tools_md() -> None:
    d = default_nlah_dir()
    assert (d / "tools.md").is_file()


def test_default_nlah_dir_has_two_examples() -> None:
    d = default_nlah_dir()
    examples = sorted((d / "examples").glob("*.md"))
    assert len(examples) == 2
    assert any("beacon" in e.name for e in examples)
    assert any("dga" in e.name for e in examples)


def test_load_system_prompt_returns_combined() -> None:
    prompt = load_system_prompt()
    # README content shows up.
    assert "Network Threat Agent" in prompt
    # tools.md content shows up.
    assert "read_suricata_alerts" in prompt
    # Examples land in the prompt.
    assert "C2 beacon" in prompt or "C2 beacon detected" in prompt
    assert "DGA" in prompt


def test_load_system_prompt_accepts_explicit_dir(tmp_path: Path) -> None:
    """The shim accepts an explicit `nlah_dir` override (used by tests + tools)."""
    (tmp_path / "README.md").write_text("# Custom\n")
    (tmp_path / "tools.md").write_text("# Custom tools\n")
    (tmp_path / "examples").mkdir()
    (tmp_path / "examples" / "01.md").write_text("Custom example.\n")

    prompt = load_system_prompt(tmp_path)
    assert "Custom" in prompt


def test_load_system_prompt_handles_string_path(tmp_path: Path) -> None:
    """`load_system_prompt` accepts both `Path` and `str`."""
    (tmp_path / "README.md").write_text("# S\n")
    (tmp_path / "tools.md").write_text("# T\n")
    (tmp_path / "examples").mkdir()

    assert "S" in load_system_prompt(str(tmp_path))


def test_loader_is_21_loc_shim() -> None:
    """ADR-007 v1.2 conformance: this module is a ~21-LOC shim, not a reimplementation.

    Counts non-blank, non-comment Python lines (excluding docstring).
    """
    import network_threat.nlah_loader as mod

    source = Path(mod.__file__).read_text(encoding="utf-8")
    in_docstring = False
    code_lines = 0
    for line in source.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith('"""') or stripped.startswith("'''"):
            # Toggle on every triple-quote token (handles single-line + multi-line).
            count = stripped.count('"""') + stripped.count("'''")
            if count == 1:
                in_docstring = not in_docstring
            continue
        if in_docstring:
            continue
        code_lines += 1
    # ADR-007 v1.2 budget: ≤ 35 LOC (per F.6's "27 LOC" reference; D.7 hit 21).
    assert code_lines <= 35, f"nlah_loader.py is {code_lines} LOC; cap is 35 per ADR-007 v1.2"


@pytest.mark.parametrize(
    "name",
    [
        "default_nlah_dir",
        "load_system_prompt",
    ],
)
def test_module_exports(name: str) -> None:
    import network_threat.nlah_loader as mod

    assert hasattr(mod, name)
    assert name in mod.__all__
