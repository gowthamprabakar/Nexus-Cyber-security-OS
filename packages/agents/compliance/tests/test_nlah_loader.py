"""Tests for `compliance.nlah_loader` — D.9's ADR-007 v1.2 shim.

D.9 is the 9th agent shipped natively against v1.2 (D.3 / F.6 / D.7 /
D.4 / multi-cloud-posture / k8s-posture / D.5 / D.8 / D.9).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from compliance.nlah_loader import default_nlah_dir, load_system_prompt


def test_default_nlah_dir_resolves_to_package() -> None:
    d = default_nlah_dir()
    assert isinstance(d, Path)
    assert d.is_dir()
    assert d.name == "nlah"
    assert "compliance" in str(d).split("/")


def test_default_nlah_dir_has_readme() -> None:
    assert (default_nlah_dir() / "README.md").is_file()


def test_default_nlah_dir_has_tools_md() -> None:
    assert (default_nlah_dir() / "tools.md").is_file()


def test_default_nlah_dir_has_three_examples() -> None:
    d = default_nlah_dir()
    examples = sorted((d / "examples").glob("*.md"))
    assert len(examples) == 3
    assert any("cis-iam-fail" in e.name for e in examples)
    assert any("cis-s3-public-fail" in e.name for e in examples)
    assert any("multi-source-control" in e.name for e in examples)


def test_load_system_prompt_returns_combined() -> None:
    prompt = load_system_prompt()
    # README content shows up.
    assert "Compliance Agent" in prompt
    assert "compliance officer" in prompt
    # tools.md content shows up.
    assert "read_cis_aws_benchmark" in prompt
    assert "correlate_cloud_posture" in prompt
    assert "correlate_data_security" in prompt
    assert "aggregate_controls" in prompt
    # Examples land in the prompt.
    assert "CIS 1.10" in prompt
    assert "CIS 2.1.4" in prompt


def test_load_system_prompt_carries_q6_attribution_reminder() -> None:
    """The README + tools.md explicitly mention the CIS Benchmarks®
    attribution + no-verbatim-text posture."""
    prompt = load_system_prompt()
    assert "CIS Benchmarks®" in prompt


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
    import compliance.nlah_loader as mod

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
    assert code_lines <= 35, f"nlah_loader.py is {code_lines} LOC; cap is 35 per ADR-007 v1.2"


@pytest.mark.parametrize(
    "name", ["01-cis-iam-fail", "02-cis-s3-public-fail", "03-multi-source-control"]
)
def test_example_file_present_and_non_empty(name: str) -> None:
    path = default_nlah_dir() / "examples" / f"{name}.md"
    assert path.is_file()
    assert path.read_text(encoding="utf-8").strip()


def test_readme_documents_compliance_officer_persona() -> None:
    readme = (default_nlah_dir() / "README.md").read_text(encoding="utf-8")
    assert "compliance officer" in readme
    assert "Agent #13" in readme


def test_tools_md_lists_full_tool_surface() -> None:
    tools = (default_nlah_dir() / "tools.md").read_text(encoding="utf-8")
    # 1 ingest + 2 correlators + 1 aggregator + 1 scorer + 1 summarizer
    assert "read_cis_aws_benchmark" in tools
    assert "correlate_cloud_posture" in tools
    assert "correlate_data_security" in tools
    assert "aggregate_controls" in tools
    assert "score_findings" in tools
    assert "render_summary" in tools


def test_readme_documents_seven_stage_pipeline() -> None:
    """D.9 has a 7-stage pipeline (INGEST/ENRICH/CORRELATE/AGGREGATE/
    SCORE/SUMMARIZE/HANDOFF). All 7 must appear in the README."""
    readme = (default_nlah_dir() / "README.md").read_text(encoding="utf-8").upper()
    for stage in [
        "INGEST",
        "ENRICH",
        "CORRELATE",
        "AGGREGATE",
        "SCORE",
        "SUMMARIZE",
        "HANDOFF",
    ]:
        assert stage in readme, f"stage {stage} missing from NLAH README"


def test_readme_documents_q6_paraphrase_posture() -> None:
    """README must mention the paraphrase posture so future maintainers
    don't accidentally lift CIS Securesuite text into the YAML."""
    readme = (default_nlah_dir() / "README.md").read_text(encoding="utf-8")
    assert "paraphrased" in readme.lower()
