"""Tests for fabric subject builders (per ADR-004 + ADR-012)."""

import pytest
from shared.fabric.subjects import (
    approvals_subject,
    audit_subject,
    claims_subject,
    commands_subject,
    events_subject,
    findings_subject,
)


def test_events_subject_shape() -> None:
    assert events_subject("tnt-abc", "scan_completed") == ("events.tenant.tnt-abc.scan_completed")


def test_findings_subject_is_stable_hash_for_asset() -> None:
    arn = "arn:aws:s3:::my-bucket"
    a = findings_subject("tnt-abc", arn)
    b = findings_subject("tnt-abc", arn)
    assert a == b
    assert a.startswith("findings.tenant.tnt-abc.asset.")
    asset_hash = a.rsplit(".", 1)[-1]
    assert len(asset_hash) == 16  # truncated sha256 hex
    assert asset_hash.isalnum()


def test_findings_subject_different_assets_differ() -> None:
    a = findings_subject("tnt-abc", "arn:aws:s3:::bucket-a")
    b = findings_subject("tnt-abc", "arn:aws:s3:::bucket-b")
    assert a != b


def test_commands_subject_shape() -> None:
    assert commands_subject("edge-001", "rule_pack_update") == (
        "commands.edge.edge-001.rule_pack_update"
    )


def test_approvals_subject_shape() -> None:
    fid = "01HZX7B0K3M5N9P2Q4R6S8T0V"
    assert approvals_subject("tnt-abc", fid) == (f"approvals.tenant.tnt-abc.finding.{fid}")


def test_audit_subject_shape() -> None:
    assert audit_subject("tnt-abc") == "audit.tenant.tnt-abc"


@pytest.mark.parametrize(
    "bad_tenant",
    ["tnt with space", "tnt:colons", "tnt/slash", "tnt.dot", "tnt*star", ""],
)
def test_invalid_tenant_id_rejected(bad_tenant: str) -> None:
    with pytest.raises(ValueError):
        events_subject(bad_tenant, "x")


def test_invalid_event_type_rejected() -> None:
    with pytest.raises(ValueError):
        events_subject("tnt-abc", "with space")


# ADR-012 — claims.> subject (sixth bus)


def test_claims_subject_shape() -> None:
    assert claims_subject("tnt-abc", "curiosity") == "claims.tenant.tnt-abc.agent.curiosity"


def test_claims_subject_per_agent_scoping() -> None:
    """Different agents in the same tenant get distinct subjects."""
    a = claims_subject("tnt-abc", "curiosity")
    b = claims_subject("tnt-abc", "meta_harness")
    assert a != b
    assert a.startswith("claims.tenant.tnt-abc.agent.")
    assert b.startswith("claims.tenant.tnt-abc.agent.")


def test_claims_subject_per_tenant_scoping() -> None:
    """Same agent in different tenants gets distinct subjects (ACL boundary)."""
    a = claims_subject("tnt-a", "curiosity")
    b = claims_subject("tnt-b", "curiosity")
    assert a != b


def test_claims_subject_invalid_tenant_rejected() -> None:
    with pytest.raises(ValueError, match="tenant_id"):
        claims_subject("tnt with space", "curiosity")


def test_claims_subject_invalid_agent_rejected() -> None:
    with pytest.raises(ValueError, match="agent_id"):
        claims_subject("tnt-abc", "with.dot")


def test_claims_subject_empty_agent_rejected() -> None:
    with pytest.raises(ValueError, match="agent_id"):
        claims_subject("tnt-abc", "")
