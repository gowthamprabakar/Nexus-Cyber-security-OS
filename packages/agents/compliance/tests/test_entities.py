"""Tests — ``compliance.entities`` (Task 5).

Verifies the two pydantic entity models that the kg_writer persists
to SemanticStore.
"""

from __future__ import annotations

from compliance.entities import ControlEntity, FrameworkEntity
from compliance.schemas import ComplianceFramework, ControlLevel, ControlMapping

# ---------------------------------------------------------------------------
# FrameworkEntity
# ---------------------------------------------------------------------------


def test_framework_entity_external_id_is_framework_value() -> None:
    f = FrameworkEntity(
        framework=ComplianceFramework.CIS_AWS_V3,
        version="3.0.0",
        name="CIS AWS Foundations Benchmark v3.0",
    )
    assert f.external_id == "cis_aws_v3"


def test_framework_entity_properties_round_trip() -> None:
    f = FrameworkEntity(
        framework=ComplianceFramework.CIS_AWS_V3,
        version="3.0.0",
        name="CIS AWS Foundations Benchmark v3.0",
    )
    props = f.properties()
    assert props == {
        "framework": "cis_aws_v3",
        "version": "3.0.0",
        "name": "CIS AWS Foundations Benchmark v3.0",
    }


# ---------------------------------------------------------------------------
# ControlEntity
# ---------------------------------------------------------------------------


def test_control_entity_external_id_combines_framework_and_control_id() -> None:
    c = ControlEntity(
        framework=ComplianceFramework.CIS_AWS_V3,
        control_id="1.1",
        name="Root user MFA",
        level=ControlLevel.LEVEL_1,
    )
    assert c.external_id == "cis_aws_v3:1.1"


def test_control_entity_distinct_external_id_for_different_controls() -> None:
    a = ControlEntity(
        framework=ComplianceFramework.CIS_AWS_V3,
        control_id="1.1",
        name="x",
        level=ControlLevel.LEVEL_1,
    )
    b = ControlEntity(
        framework=ComplianceFramework.CIS_AWS_V3,
        control_id="2.1.5",
        name="y",
        level=ControlLevel.LEVEL_2,
    )
    assert a.external_id != b.external_id


def test_control_entity_defaults() -> None:
    c = ControlEntity(
        framework=ComplianceFramework.CIS_AWS_V3,
        control_id="1.1",
        name="x",
        level=ControlLevel.LEVEL_1,
    )
    assert c.required is True
    assert c.applicability == []
    assert c.description == ""
    assert c.source_mappings == []


def test_control_entity_properties_round_trip_full_shape() -> None:
    mappings = [
        ControlMapping(
            source_agent="cloud_posture",
            source_rule_id="CSPM-AWS-IAM-001",
            control_id="1.10",
            level=ControlLevel.LEVEL_1,
            required=True,
        ),
        ControlMapping(
            source_agent="data_security",
            source_rule_id="data_security_s3_bucket_public",
            control_id="2.1.4",
            level=ControlLevel.LEVEL_2,
            required=False,
        ),
    ]
    c = ControlEntity(
        framework=ComplianceFramework.CIS_AWS_V3,
        control_id="1.10",
        name="Enable MFA for every IAM user",
        level=ControlLevel.LEVEL_1,
        required=True,
        applicability=["aws_iam"],
        description="Paraphrased operator summary.",
        source_mappings=mappings,
    )
    props = c.properties()
    assert props["framework"] == "cis_aws_v3"
    assert props["control_id"] == "1.10"
    assert props["level"] == "level_1"
    assert props["required"] is True
    assert props["applicability"] == ["aws_iam"]
    assert props["description"] == "Paraphrased operator summary."
    assert isinstance(props["source_mappings"], list)
    assert len(props["source_mappings"]) == 2
    first_mapping = props["source_mappings"][0]
    assert first_mapping["source_agent"] == "cloud_posture"
    assert first_mapping["source_rule_id"] == "CSPM-AWS-IAM-001"
    assert first_mapping["level"] == "level_1"
    assert first_mapping["required"] is True


def test_control_entity_properties_flattens_mapping_override() -> None:
    """A mapping with overridden level/required is flattened verbatim."""
    mapping = ControlMapping(
        source_agent="cloud_posture",
        source_rule_id="CSPM-AWS-EC2-001",
        control_id="5.2",
        level=ControlLevel.LEVEL_2,  # override (5.2 is Level 1 normally)
        required=False,
    )
    c = ControlEntity(
        framework=ComplianceFramework.CIS_AWS_V3,
        control_id="5.2",
        name="x",
        level=ControlLevel.LEVEL_1,
        source_mappings=[mapping],
    )
    props_mapping = c.properties()["source_mappings"][0]
    assert props_mapping["level"] == "level_2"
    assert props_mapping["required"] is False
