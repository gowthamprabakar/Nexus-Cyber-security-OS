"""Tests for `threat_intel.nlah_loader` — D.8's ADR-007 v1.2 shim.

D.8 is the 8th agent shipped natively against v1.2 (D.3 / F.6 / D.7 /
D.4 / multi-cloud-posture / k8s-posture / D.5 / D.8).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from threat_intel.nlah_loader import default_nlah_dir, load_system_prompt


def test_default_nlah_dir_resolves_to_package() -> None:
    d = default_nlah_dir()
    assert isinstance(d, Path)
    assert d.is_dir()
    assert d.name == "nlah"
    assert "threat_intel" in str(d).split("/")


def test_default_nlah_dir_has_readme() -> None:
    assert (default_nlah_dir() / "README.md").is_file()


def test_default_nlah_dir_has_tools_md() -> None:
    assert (default_nlah_dir() / "tools.md").is_file()


def test_default_nlah_dir_has_three_examples() -> None:
    d = default_nlah_dir()
    examples = sorted((d / "examples").glob("*.md"))
    assert len(examples) == 3
    assert any("cve-in-kev" in e.name for e in examples)
    assert any("ioc-match-network" in e.name for e in examples)
    assert any("technique-observed" in e.name for e in examples)


def test_load_system_prompt_returns_combined() -> None:
    prompt = load_system_prompt()
    # README content shows up.
    assert "Threat Intel Agent" in prompt
    assert "CTI analyst" in prompt
    # tools.md content shows up.
    assert "read_nvd_feed" in prompt
    assert "read_cisa_kev" in prompt
    assert "read_mitre_attack" in prompt
    # Examples land in the prompt.
    assert "CVE in CISA KEV" in prompt
    assert "IOC match" in prompt


def test_load_system_prompt_carries_q6_attribution_reminder() -> None:
    """The README explicitly mentions the CC-BY-4.0 attribution requirement."""
    prompt = load_system_prompt()
    assert "CC-BY-4.0" in prompt
    assert "MITRE ATT&CK" in prompt


def test_load_system_prompt_handles_string_path(tmp_path: Path) -> None:
    """`load_system_prompt` accepts both `Path` and `str`."""
    (tmp_path / "README.md").write_text("# S\n")
    (tmp_path / "tools.md").write_text("# T\n")
    (tmp_path / "examples").mkdir()
    assert "S" in load_system_prompt(str(tmp_path))


def test_loader_is_under_35_loc() -> None:
    """ADR-007 v1.2 conformance: this module is a ~21-LOC shim.

    Counts non-blank, non-comment Python lines (excluding docstring).
    """
    import threat_intel.nlah_loader as mod

    source = Path(mod.__file__).read_text(encoding="utf-8")
    in_docstring = False
    code_lines = 0
    for line in source.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith('"""') or stripped.startswith("'''"):
            count = stripped.count('"""') + stripped.count("'''")
            if count == 1:
                in_docstring = not in_docstring
            continue
        if in_docstring:
            continue
        code_lines += 1
    # ADR-007 v1.2 budget: ≤ 35 LOC.
    assert code_lines <= 35, f"nlah_loader.py is {code_lines} LOC; cap is 35 per ADR-007 v1.2"


@pytest.mark.parametrize("name", ["01-cve-in-kev", "02-ioc-match-network", "03-technique-observed"])
def test_example_file_present_and_non_empty(name: str) -> None:
    path = default_nlah_dir() / "examples" / f"{name}.md"
    assert path.is_file()
    assert path.read_text(encoding="utf-8").strip()


def test_readme_documents_cti_analyst_persona() -> None:
    readme = (default_nlah_dir() / "README.md").read_text(encoding="utf-8")
    assert "CTI analyst" in readme
    assert "Agent #12" in readme


def test_tools_md_lists_six_tools() -> None:
    tools = (default_nlah_dir() / "tools.md").read_text(encoding="utf-8")
    # 3 ingest + 3 correlators
    assert "read_nvd_feed" in tools
    assert "read_cisa_kev" in tools
    assert "read_mitre_attack" in tools
    assert "correlate_cve_kev" in tools
    assert "correlate_ioc_network" in tools
    assert "correlate_ioc_runtime" in tools
