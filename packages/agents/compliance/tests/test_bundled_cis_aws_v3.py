"""Tests — bundled CIS AWS Foundations Benchmark v3.0 YAML (Task 4).

These tests load the actual shipped data file (not a tmp_path fixture)
and assert acceptance criteria from the plan: minimum control count,
every entry has a paraphrased description, sample Level-1 + Level-2
entries land with the right shape, and the source_mappings reference
real F.3 + D.5 rule_ids.

WI-2 (CIS Benchmarks licence compliance) regression probe:
verbatim-text leakage is checked via two anchor terms that the public
Securesuite materials use but that the paraphrased shipped YAML
deliberately rewords. If those exact-text anchors ever appear here,
something has been pasted verbatim and the v0.1 attribution posture
is broken.
"""

from __future__ import annotations

import pytest
from compliance.schemas import ControlLevel
from compliance.tools.cis_aws_benchmark import (
    default_cis_aws_v3_path,
    read_cis_aws_benchmark,
)

# Minimum count gate: the plan §Task 4 says "~50 controls"; we ship
# 45 in v0.1 covering the IAM / Storage / Logging / Monitoring /
# Networking sections. Hard floor of 40 acceptable v0.1 minimum.
_MIN_CONTROLS = 40


@pytest.mark.asyncio
async def test_bundled_yaml_file_exists() -> None:
    """default_cis_aws_v3_path() resolves to an existing file."""
    path = default_cis_aws_v3_path()
    assert path.is_file(), f"bundled CIS YAML missing at {path}"


@pytest.mark.asyncio
async def test_bundled_yaml_loads_without_error() -> None:
    """No-arg call reads the bundled library cleanly (no fixture path)."""
    controls = await read_cis_aws_benchmark()
    assert controls, "bundled CIS library parsed to zero controls"


@pytest.mark.asyncio
async def test_bundled_library_has_at_least_min_controls() -> None:
    controls = await read_cis_aws_benchmark()
    assert len(controls) >= _MIN_CONTROLS, (
        f"bundled CIS library has {len(controls)} controls; v0.1 floor is {_MIN_CONTROLS}"
    )


@pytest.mark.asyncio
async def test_every_control_has_paraphrased_description() -> None:
    """WI-2 + Q6: each control must carry a non-empty operator summary.

    Empty descriptions are a sign the YAML was hand-written without
    the operator-summary step — that's where verbatim-text leakage
    would most likely creep in.
    """
    controls = await read_cis_aws_benchmark()
    no_desc = [c.control_id for c in controls if not c.description.strip()]
    assert not no_desc, f"controls missing paraphrased descriptions: {no_desc}"


@pytest.mark.asyncio
async def test_every_control_has_a_name() -> None:
    controls = await read_cis_aws_benchmark()
    no_name = [c.control_id for c in controls if not c.name.strip()]
    assert not no_name, f"controls missing names: {no_name}"


@pytest.mark.asyncio
async def test_library_covers_all_five_sections() -> None:
    """1.x (IAM), 2.x (Storage), 3.x (Logging), 4.x (Monitoring),
    5.x (Networking) must each have at least one shipped control."""
    controls = await read_cis_aws_benchmark()
    section_prefixes = {c.control_id.split(".", 1)[0] for c in controls}
    missing = {"1", "2", "3", "4", "5"} - section_prefixes
    assert not missing, f"sections not covered: {missing}"


@pytest.mark.asyncio
async def test_library_has_both_level_1_and_level_2_controls() -> None:
    controls = await read_cis_aws_benchmark()
    levels = {c.level for c in controls}
    assert ControlLevel.LEVEL_1 in levels
    assert ControlLevel.LEVEL_2 in levels


# ---------------------------------------------------------------------------
# Sample-control sanity (anchors that future v0.2 framework expansions
# must keep present so downstream eval cases stay green)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_root_user_mfa_control_present_at_level_1() -> None:
    """CIS 1.5 (root MFA) is the highest-impact identity control;
    must always ship at Level 1 / required."""
    controls = await read_cis_aws_benchmark()
    by_id = {c.control_id: c for c in controls}
    assert "1.5" in by_id, "CIS 1.5 (root MFA) missing from bundled library"
    assert by_id["1.5"].level == ControlLevel.LEVEL_1


@pytest.mark.asyncio
async def test_s3_default_encryption_control_present() -> None:
    """CIS 2.1.1 (S3 default encryption) is the storage anchor."""
    controls = await read_cis_aws_benchmark()
    by_id = {c.control_id: c for c in controls}
    assert "2.1.1" in by_id
    assert by_id["2.1.1"].level == ControlLevel.LEVEL_1
    assert by_id["2.1.1"].required is True


@pytest.mark.asyncio
async def test_cloudtrail_multi_region_control_present() -> None:
    """CIS 3.1 (multi-region CloudTrail) is the logging anchor."""
    controls = await read_cis_aws_benchmark()
    by_id = {c.control_id: c for c in controls}
    assert "3.1" in by_id


@pytest.mark.asyncio
async def test_open_security_group_control_present() -> None:
    """CIS 5.2 (no 0.0.0.0/0 on remote-admin ports) is the network anchor."""
    controls = await read_cis_aws_benchmark()
    by_id = {c.control_id: c for c in controls}
    assert "5.2" in by_id
    assert by_id["5.2"].level == ControlLevel.LEVEL_1


# ---------------------------------------------------------------------------
# Source-mapping cross-reference (Task 4 -> Tasks 6 + 7 contract)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_source_mappings_reference_real_f3_rule_ids() -> None:
    """Every cloud_posture mapping must reference a CSPM-AWS-* rule that
    F.3 actually emits today. Real rule ids per
    `cloud_posture.agent._PROWLER_RULE_MAP`:

      CSPM-AWS-IAM-001 / IAM-002 / S3-001 / S3-002 / KMS-001 / RDS-001 / EC2-001.
    """
    controls = await read_cis_aws_benchmark()
    real_f3_rules = {
        "CSPM-AWS-IAM-001",
        "CSPM-AWS-IAM-002",
        "CSPM-AWS-S3-001",
        "CSPM-AWS-S3-002",
        "CSPM-AWS-KMS-001",
        "CSPM-AWS-RDS-001",
        "CSPM-AWS-EC2-001",
    }
    f3_referenced: set[str] = set()
    for c in controls:
        for m in c.source_mappings:
            if m.source_agent == "cloud_posture":
                f3_referenced.add(m.source_rule_id)
    unknown = f3_referenced - real_f3_rules
    assert not unknown, f"cloud_posture mappings reference unknown rule_ids: {unknown}"


@pytest.mark.asyncio
async def test_source_mappings_reference_real_d5_rule_ids() -> None:
    """Every data_security mapping must reference a real
    `DataSecurityFindingType` enum value (the 4-detector
    discriminator strings from D.5)."""
    controls = await read_cis_aws_benchmark()
    # D.5 emits short rule_ids in `compliance.control`
    # (see packages/agents/data-security/src/data_security/detectors/).
    # The full `data_security_*` strings are the
    # DataSecurityFindingType discriminator that lands in
    # `evidence.source_finding_type`; D.6 joins on the short
    # `compliance.control` form.
    real_d5_rules = {
        "s3_bucket_public",
        "s3_bucket_unencrypted",
        "s3_object_sensitive_in_untrusted_location",
        "s3_oversharing_iam",
    }
    d5_referenced: set[str] = set()
    for c in controls:
        for m in c.source_mappings:
            if m.source_agent == "data_security":
                d5_referenced.add(m.source_rule_id)
    unknown = d5_referenced - real_d5_rules
    assert not unknown, f"data_security mappings reference unknown rule_ids: {unknown}"


@pytest.mark.asyncio
async def test_at_least_one_control_per_source_agent() -> None:
    """v0.1 acceptance: F.3 and D.5 each map to at least one CIS control.
    If this fails, the eval-case suite (Task 13) will have nothing to
    correlate against for one of the two sibling agents."""
    controls = await read_cis_aws_benchmark()
    agents_seen: set[str] = set()
    for c in controls:
        for m in c.source_mappings:
            agents_seen.add(m.source_agent)
    assert {"cloud_posture", "data_security"} <= agents_seen


# ---------------------------------------------------------------------------
# WI-2 regression: shipped YAML carries no anchor text from CIS Securesuite
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_securesuite_anchor_text_in_descriptions() -> None:
    """Hand-picked sentinel phrases that appear verbatim in the
    Securesuite PDF + companion materials but NOT in the paraphrased
    YAML this repo ships. If one of these strings shows up, the
    paraphrase posture has regressed and Task 15's paraphrase-
    verification step must re-audit the file.

    Future maintainers: do NOT relax this list without re-reading
    Q6 of the plan.
    """
    controls = await read_cis_aws_benchmark()
    blob = "\n".join(c.description for c in controls).lower()
    forbidden = [
        "rationale:",  # CIS PDF section heading
        "audit procedure",  # CIS PDF section heading
        "remediation procedure",  # CIS PDF section heading
        "default value:",  # CIS PDF section heading
        "cis controls v",  # benchmark cross-reference template
    ]
    leaks = [phrase for phrase in forbidden if phrase in blob]
    assert not leaks, (
        f"shipped CIS YAML carries CIS Securesuite anchor phrases: {leaks}. "
        "Per WI-2 / Q6 the bundled library must ship paraphrased text only."
    )
