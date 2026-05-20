"""Tests — ``compliance.tools.cis_aws_benchmark`` (Task 3).

Validates the async YAML loader: error handling on missing /
malformed input, parse path with inline tmp_path fixtures (no
dependency on the Task 4 bundled YAML), CisControl pydantic shape,
ControlMapping fold-in semantics, forgiving-drop on malformed entries.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from compliance.schemas import ControlLevel
from compliance.tools.cis_aws_benchmark import (
    CisAwsBenchmarkReaderError,
    CisControl,
    default_cis_aws_v3_path,
    read_cis_aws_benchmark,
)

_MINIMAL_YAML = """
framework: cis_aws_v3
version: '3.0.0'
controls:
  - control_id: '1.1'
    name: Avoid root user
    level: level_1
    applicability: [aws_iam, aws_root_account]
    required: true
    description: Paraphrased operator summary for control 1.1.
    source_mappings:
      - source_agent: cloud_posture
        source_rule_id: iam_root_account_use
      - source_agent: data_security
        source_rule_id: root_user_with_data_access
  - control_id: '2.1.5'
    name: S3 buckets must block public access
    level: level_2
    applicability: [aws_s3]
    required: false
    description: Paraphrased operator summary for control 2.1.5.
    source_mappings:
      - source_agent: data_security
        source_rule_id: public_bucket
"""


# ---------------------------------------------------------------------------
# default_cis_aws_v3_path
# ---------------------------------------------------------------------------


def test_default_path_points_at_bundled_library() -> None:
    p = default_cis_aws_v3_path()
    assert isinstance(p, Path)
    assert p.name == "cis_aws_v3.yaml"
    assert "compliance" in str(p)
    assert "control_libraries" in str(p)


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_missing_file_raises_reader_error(tmp_path: Path) -> None:
    missing = tmp_path / "does_not_exist.yaml"
    with pytest.raises(CisAwsBenchmarkReaderError, match="not found"):
        await read_cis_aws_benchmark(path=missing)


@pytest.mark.asyncio
async def test_directory_not_file_raises_reader_error(tmp_path: Path) -> None:
    with pytest.raises(CisAwsBenchmarkReaderError, match="not a file"):
        await read_cis_aws_benchmark(path=tmp_path)


@pytest.mark.asyncio
async def test_malformed_yaml_raises_reader_error(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("controls: [not closed list\n", encoding="utf-8")
    with pytest.raises(CisAwsBenchmarkReaderError, match="malformed YAML"):
        await read_cis_aws_benchmark(path=bad)


@pytest.mark.asyncio
async def test_top_level_must_be_mapping(tmp_path: Path) -> None:
    weird = tmp_path / "weird.yaml"
    weird.write_text("- just\n- a\n- list\n", encoding="utf-8")
    with pytest.raises(CisAwsBenchmarkReaderError, match="top-level"):
        await read_cis_aws_benchmark(path=weird)


@pytest.mark.asyncio
async def test_controls_field_must_be_list(tmp_path: Path) -> None:
    weird = tmp_path / "weird.yaml"
    weird.write_text("controls: not_a_list\n", encoding="utf-8")
    with pytest.raises(CisAwsBenchmarkReaderError, match="'controls' field must be a list"):
        await read_cis_aws_benchmark(path=weird)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_minimal_yaml_yields_two_controls(tmp_path: Path) -> None:
    p = tmp_path / "cis.yaml"
    p.write_text(_MINIMAL_YAML, encoding="utf-8")
    controls = await read_cis_aws_benchmark(path=p)
    assert len(controls) == 2
    assert all(isinstance(c, CisControl) for c in controls)


@pytest.mark.asyncio
async def test_control_level_and_required_parsed(tmp_path: Path) -> None:
    p = tmp_path / "cis.yaml"
    p.write_text(_MINIMAL_YAML, encoding="utf-8")
    controls = await read_cis_aws_benchmark(path=p)
    by_id = {c.control_id: c for c in controls}
    assert by_id["1.1"].level == ControlLevel.LEVEL_1
    assert by_id["1.1"].required is True
    assert by_id["2.1.5"].level == ControlLevel.LEVEL_2
    assert by_id["2.1.5"].required is False


@pytest.mark.asyncio
async def test_control_applicability_and_description_preserved(tmp_path: Path) -> None:
    p = tmp_path / "cis.yaml"
    p.write_text(_MINIMAL_YAML, encoding="utf-8")
    controls = await read_cis_aws_benchmark(path=p)
    by_id = {c.control_id: c for c in controls}
    assert by_id["1.1"].applicability == ("aws_iam", "aws_root_account")
    assert "Paraphrased" in by_id["1.1"].description


@pytest.mark.asyncio
async def test_source_mappings_fold_in_enclosing_metadata(tmp_path: Path) -> None:
    """Mappings inherit the enclosing control's id + level + required
    when not overridden inside the mapping entry."""
    p = tmp_path / "cis.yaml"
    p.write_text(_MINIMAL_YAML, encoding="utf-8")
    controls = await read_cis_aws_benchmark(path=p)
    by_id = {c.control_id: c for c in controls}
    mappings_1_1 = by_id["1.1"].source_mappings
    assert len(mappings_1_1) == 2
    assert all(m.control_id == "1.1" for m in mappings_1_1)
    assert all(m.level == ControlLevel.LEVEL_1 for m in mappings_1_1)
    assert all(m.required is True for m in mappings_1_1)
    agents = {m.source_agent for m in mappings_1_1}
    assert agents == {"cloud_posture", "data_security"}


@pytest.mark.asyncio
async def test_source_mapping_can_override_level_and_required(tmp_path: Path) -> None:
    yaml_with_override = """
framework: cis_aws_v3
version: '3.0.0'
controls:
  - control_id: '1.1'
    name: x
    level: level_1
    required: true
    source_mappings:
      - source_agent: cloud_posture
        source_rule_id: iam_root_account_use
        level: level_2
        required: false
"""
    p = tmp_path / "cis.yaml"
    p.write_text(yaml_with_override, encoding="utf-8")
    controls = await read_cis_aws_benchmark(path=p)
    assert len(controls) == 1
    mapping = controls[0].source_mappings[0]
    assert mapping.level == ControlLevel.LEVEL_2
    assert mapping.required is False


# ---------------------------------------------------------------------------
# Forgiving-drop semantics
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unknown_level_value_drops_control(tmp_path: Path) -> None:
    yaml_with_bad_level = """
controls:
  - control_id: '1.1'
    name: x
    level: level_99
  - control_id: '1.2'
    name: y
    level: level_1
"""
    p = tmp_path / "cis.yaml"
    p.write_text(yaml_with_bad_level, encoding="utf-8")
    controls = await read_cis_aws_benchmark(path=p)
    assert [c.control_id for c in controls] == ["1.2"]


@pytest.mark.asyncio
async def test_non_dict_entries_dropped(tmp_path: Path) -> None:
    yaml_with_garbage = """
controls:
  - "this is a string, not a control"
  - control_id: '1.1'
    name: x
    level: level_1
  - 42
"""
    p = tmp_path / "cis.yaml"
    p.write_text(yaml_with_garbage, encoding="utf-8")
    controls = await read_cis_aws_benchmark(path=p)
    assert [c.control_id for c in controls] == ["1.1"]


@pytest.mark.asyncio
async def test_missing_control_id_drops_entry(tmp_path: Path) -> None:
    yaml_missing_id = """
controls:
  - name: missing
    level: level_1
  - control_id: '1.1'
    name: x
    level: level_1
"""
    p = tmp_path / "cis.yaml"
    p.write_text(yaml_missing_id, encoding="utf-8")
    controls = await read_cis_aws_benchmark(path=p)
    assert [c.control_id for c in controls] == ["1.1"]


@pytest.mark.asyncio
async def test_malformed_mapping_dropped_silently(tmp_path: Path) -> None:
    """A mapping entry without source_agent or source_rule_id is dropped;
    the enclosing control still parses."""
    yaml_bad_mapping = """
controls:
  - control_id: '1.1'
    name: x
    level: level_1
    source_mappings:
      - source_agent: cloud_posture
        source_rule_id: iam_root
      - source_agent: ''
      - 'just a string'
      - source_rule_id: orphan
"""
    p = tmp_path / "cis.yaml"
    p.write_text(yaml_bad_mapping, encoding="utf-8")
    controls = await read_cis_aws_benchmark(path=p)
    assert len(controls) == 1
    assert len(controls[0].source_mappings) == 1
    assert controls[0].source_mappings[0].source_rule_id == "iam_root"


# ---------------------------------------------------------------------------
# CisControl pydantic validators
# ---------------------------------------------------------------------------


def test_cis_control_rejects_non_dotted_id() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        CisControl(control_id="abc", name="x", level=ControlLevel.LEVEL_1)


def test_cis_control_accepts_dotted_id_with_underscores_rejected() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        CisControl(control_id="1_1", name="x", level=ControlLevel.LEVEL_1)


def test_cis_control_defaults() -> None:
    c = CisControl(control_id="1.1", name="x", level=ControlLevel.LEVEL_1)
    assert c.required is True
    assert c.applicability == ()
    assert c.source_mappings == ()
    assert c.description == ""
