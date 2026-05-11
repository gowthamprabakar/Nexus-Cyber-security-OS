"""Tests for `identity.normalizer.normalize_to_findings`."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from identity.normalizer import normalize_to_findings
from identity.schemas import FindingType, IdentityFinding, Severity
from identity.tools.aws_access_analyzer import AccessAnalyzerFinding
from identity.tools.aws_iam import (
    IamGroup,
    IamRole,
    IamUser,
    IdentityListing,
    SimulationDecision,
)
from identity.tools.permission_paths import resolve_effective_grants
from shared.fabric.envelope import NexusEnvelope

NOW = datetime(2026, 5, 11, tzinfo=UTC)
LONG_AGO = NOW - timedelta(days=400)
ALICE = "arn:aws:iam::123456789012:user/alice"
BOB = "arn:aws:iam::123456789012:user/bob"
LAMBDA_ROLE = "arn:aws:iam::123456789012:role/LambdaExecutionRole"
DORMANT_ROLE = "arn:aws:iam::123456789012:role/UnusedRole"


def _envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="corr_xyz",
        tenant_id="cust_test",
        agent_id="identity@0.1.0",
        nlah_version="0.1.0",
        model_pin="deterministic-v0.1",
        charter_invocation_id="invocation_001",
    )


def _user(arn: str, name: str, last_used: datetime | None = NOW) -> IamUser:
    return IamUser(
        arn=arn,
        name=name,
        user_id=f"AIDA-{name.upper()}",
        create_date=NOW,
        last_used_at=last_used,
    )


def _role(arn: str, name: str, last_used: datetime | None = NOW) -> IamRole:
    return IamRole(
        arn=arn,
        name=name,
        role_id=f"AROA-{name.upper()}",
        create_date=NOW,
        last_used_at=last_used,
        assume_role_policy_document={},
    )


def _decision(
    *,
    principal_arn: str,
    action: str,
    decision: str = "allowed",
    matched: tuple[str, ...] = (),
) -> SimulationDecision:
    return SimulationDecision(
        principal_arn=principal_arn,
        action=action,
        resource="*",
        decision=decision,
        matched_statement_ids=matched,
    )


def _basic_listing() -> IdentityListing:
    return IdentityListing(
        users=(_user(ALICE, "alice"), _user(BOB, "bob")),
        roles=(_role(LAMBDA_ROLE, "LambdaExecutionRole"),),
        groups=(
            IamGroup(
                arn="arn:aws:iam::123456789012:group/admins",
                name="admins",
                group_id="AGPA-ADMINS",
                create_date=NOW,
            ),
        ),
    )


def _grants_for(listing: IdentityListing, decisions: list[SimulationDecision]):
    return resolve_effective_grants(listing, decisions)


# ---------------------------- overprivilege ------------------------------


@pytest.mark.asyncio
async def test_overprivilege_finding_emitted_for_admin_grant() -> None:
    listing = _basic_listing()
    grants = _grants_for(
        listing, [_decision(principal_arn=ALICE, action="iam:*", matched=("AdminPolicy",))]
    )

    findings = await normalize_to_findings(
        listing, grants, [], envelope=_envelope(), detected_at=NOW
    )

    overpriv = [f for f in findings if f.finding_type == FindingType.OVERPRIVILEGE]
    assert len(overpriv) == 1
    finding = overpriv[0]
    assert finding.severity == Severity.HIGH
    assert ALICE in finding.principal_arns
    assert finding.evidence["attached_policies"] == ["AdminPolicy"]
    assert finding.evidence["admin_action_count"] == 1


@pytest.mark.asyncio
async def test_no_overprivilege_for_non_admin_grants() -> None:
    listing = _basic_listing()
    grants = _grants_for(listing, [_decision(principal_arn=ALICE, action="s3:GetObject")])

    findings = await normalize_to_findings(
        listing, grants, [], envelope=_envelope(), detected_at=NOW
    )

    assert all(f.finding_type != FindingType.OVERPRIVILEGE for f in findings)


@pytest.mark.asyncio
async def test_no_overprivilege_for_explicit_deny_on_wildcard() -> None:
    listing = _basic_listing()
    grants = _grants_for(
        listing,
        [_decision(principal_arn=ALICE, action="*:*", decision="explicitDeny")],
    )

    findings = await normalize_to_findings(
        listing, grants, [], envelope=_envelope(), detected_at=NOW
    )

    assert all(f.finding_type != FindingType.OVERPRIVILEGE for f in findings)


# ---------------------------- dormant ------------------------------------


@pytest.mark.asyncio
async def test_dormant_user_finding_emitted() -> None:
    listing = IdentityListing(
        users=(_user(ALICE, "alice", last_used=LONG_AGO),),
        roles=(),
        groups=(),
    )

    findings = await normalize_to_findings(listing, [], [], envelope=_envelope(), detected_at=NOW)

    dormant = [f for f in findings if f.finding_type == FindingType.DORMANT]
    assert len(dormant) == 1
    assert dormant[0].severity == Severity.MEDIUM
    assert dormant[0].evidence["days_dormant"] == 400


@pytest.mark.asyncio
async def test_dormant_role_finding_emitted() -> None:
    listing = IdentityListing(
        users=(),
        roles=(_role(DORMANT_ROLE, "UnusedRole", last_used=None),),
        groups=(),
    )

    findings = await normalize_to_findings(listing, [], [], envelope=_envelope(), detected_at=NOW)

    dormant = [f for f in findings if f.finding_type == FindingType.DORMANT]
    assert len(dormant) == 1
    assert dormant[0].evidence["days_dormant"] is None  # never used


@pytest.mark.asyncio
async def test_recently_used_user_does_not_yield_dormant() -> None:
    listing = IdentityListing(users=(_user(ALICE, "alice", last_used=NOW),), roles=(), groups=())

    findings = await normalize_to_findings(listing, [], [], envelope=_envelope(), detected_at=NOW)

    assert all(f.finding_type != FindingType.DORMANT for f in findings)


@pytest.mark.asyncio
async def test_dormant_threshold_is_configurable() -> None:
    """A user used 10 days ago is dormant when threshold = 5 days."""
    listing = IdentityListing(
        users=(_user(ALICE, "alice", last_used=NOW - timedelta(days=10)),),
        roles=(),
        groups=(),
    )

    findings_default = await normalize_to_findings(
        listing, [], [], envelope=_envelope(), detected_at=NOW
    )
    findings_short = await normalize_to_findings(
        listing, [], [], envelope=_envelope(), detected_at=NOW, dormant_threshold_days=5
    )

    assert all(f.finding_type != FindingType.DORMANT for f in findings_default)
    assert any(f.finding_type == FindingType.DORMANT for f in findings_short)


# ---------------------------- external access ----------------------------


@pytest.mark.asyncio
async def test_public_access_finding_marked_critical() -> None:
    aa = AccessAnalyzerFinding(
        id="aa-public",
        resource_arn="arn:aws:s3:::open-bucket",
        resource_type="AWS::S3::Bucket",
        external_principals=("*",),
        actions=("s3:GetObject",),
        is_public=True,
        status="ACTIVE",
        finding_type="ExternalAccess",
        created_at=NOW,
        updated_at=NOW,
    )

    findings = await normalize_to_findings(
        _basic_listing(), [], [aa], envelope=_envelope(), detected_at=NOW
    )

    external = [f for f in findings if f.finding_type == FindingType.EXTERNAL_ACCESS]
    assert len(external) == 1
    assert external[0].severity == Severity.CRITICAL
    assert "*" in external[0].evidence["trusts"]


@pytest.mark.asyncio
async def test_cross_account_finding_high_severity() -> None:
    aa = AccessAnalyzerFinding(
        id="aa-cross",
        resource_arn="arn:aws:s3:::shared-bucket",
        resource_type="AWS::S3::Bucket",
        external_principals=("arn:aws:iam::999999999999:root",),
        actions=("s3:GetObject",),
        is_public=False,
        status="ACTIVE",
        finding_type="ExternalAccess",
        created_at=NOW,
        updated_at=NOW,
    )

    findings = await normalize_to_findings(
        _basic_listing(), [], [aa], envelope=_envelope(), detected_at=NOW
    )

    external = [f for f in findings if f.finding_type == FindingType.EXTERNAL_ACCESS]
    assert len(external) == 1
    assert external[0].severity == Severity.HIGH


# ---------------------------- MFA gap ------------------------------------


@pytest.mark.asyncio
async def test_admin_without_mfa_yields_mfa_gap_finding() -> None:
    listing = _basic_listing()
    grants = _grants_for(listing, [_decision(principal_arn=ALICE, action="iam:*")])

    findings = await normalize_to_findings(
        listing, grants, [], envelope=_envelope(), detected_at=NOW, users_with_mfa=frozenset()
    )

    mfa = [f for f in findings if f.finding_type == FindingType.MFA_GAP]
    assert len(mfa) == 1
    assert mfa[0].severity == Severity.CRITICAL
    assert "iam:*" in mfa[0].evidence["actions_admin"]


@pytest.mark.asyncio
async def test_admin_with_mfa_does_not_yield_mfa_gap() -> None:
    listing = _basic_listing()
    grants = _grants_for(listing, [_decision(principal_arn=ALICE, action="iam:*")])

    findings = await normalize_to_findings(
        listing,
        grants,
        [],
        envelope=_envelope(),
        detected_at=NOW,
        users_with_mfa=frozenset({"alice"}),
    )

    assert all(f.finding_type != FindingType.MFA_GAP for f in findings)


@pytest.mark.asyncio
async def test_non_admin_user_does_not_yield_mfa_gap() -> None:
    listing = _basic_listing()
    grants = _grants_for(listing, [_decision(principal_arn=ALICE, action="s3:GetObject")])

    findings = await normalize_to_findings(
        listing, grants, [], envelope=_envelope(), detected_at=NOW
    )

    assert all(f.finding_type != FindingType.MFA_GAP for f in findings)


# ---------------------------- aggregate / shape --------------------------


@pytest.mark.asyncio
async def test_empty_inputs_yield_no_findings() -> None:
    empty = IdentityListing(users=(), roles=(), groups=())
    findings = await normalize_to_findings(empty, [], [], envelope=_envelope(), detected_at=NOW)
    assert findings == []


@pytest.mark.asyncio
async def test_multi_finding_rollup() -> None:
    """One admin user, one dormant role, one public bucket — three families emitted."""
    listing = IdentityListing(
        users=(_user(ALICE, "alice"),),
        roles=(_role(DORMANT_ROLE, "UnusedRole", last_used=LONG_AGO),),
        groups=(),
    )
    grants = _grants_for(listing, [_decision(principal_arn=ALICE, action="iam:*")])
    aa = AccessAnalyzerFinding(
        id="aa-public",
        resource_arn="arn:aws:s3:::open",
        resource_type="AWS::S3::Bucket",
        external_principals=("*",),
        actions=("s3:GetObject",),
        is_public=True,
        status="ACTIVE",
        finding_type="ExternalAccess",
        created_at=NOW,
        updated_at=NOW,
    )

    findings = await normalize_to_findings(
        listing, grants, [aa], envelope=_envelope(), detected_at=NOW
    )

    families = {f.finding_type for f in findings}
    assert FindingType.OVERPRIVILEGE in families
    assert FindingType.DORMANT in families
    assert FindingType.EXTERNAL_ACCESS in families
    assert FindingType.MFA_GAP in families


@pytest.mark.asyncio
async def test_all_findings_have_envelope() -> None:
    listing = IdentityListing(
        users=(_user(ALICE, "alice", last_used=LONG_AGO),), roles=(), groups=()
    )
    findings = await normalize_to_findings(listing, [], [], envelope=_envelope(), detected_at=NOW)
    for f in findings:
        assert isinstance(f, IdentityFinding)
        assert f.envelope.tenant_id == "cust_test"


@pytest.mark.asyncio
async def test_finding_ids_are_unique() -> None:
    """Two dormant users + two admin users should yield four distinct finding ids."""
    listing = IdentityListing(
        users=(
            _user(ALICE, "alice", last_used=LONG_AGO),
            _user(BOB, "bob", last_used=LONG_AGO),
        ),
        roles=(),
        groups=(),
    )
    grants = _grants_for(
        listing,
        [
            _decision(principal_arn=ALICE, action="iam:*"),
            _decision(principal_arn=BOB, action="*:*"),
        ],
    )
    findings = await normalize_to_findings(
        listing, grants, [], envelope=_envelope(), detected_at=NOW
    )
    ids = [f.finding_id for f in findings]
    assert len(ids) == len(set(ids)), f"duplicate finding ids: {ids}"
