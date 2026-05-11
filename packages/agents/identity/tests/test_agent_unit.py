"""Unit tests for the Identity Agent driver.

All boto3 calls are mocked at the agent module's import level; the test
suite focuses on the agent's wiring of charter + tools + normalizer +
summarizer + schemas, not any boto3-specific behavior.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from charter.contract import BudgetSpec, ExecutionContract
from identity import agent as agent_mod
from identity.agent import build_registry, run
from identity.tools.aws_access_analyzer import AccessAnalyzerFinding
from identity.tools.aws_iam import IamGroup, IamRole, IamUser, IdentityListing

NOW = datetime(2026, 5, 11, tzinfo=UTC)
ADMIN_POLICY = "arn:aws:iam::aws:policy/AdministratorAccess"
READ_ONLY_POLICY = "arn:aws:iam::aws:policy/ReadOnlyAccess"
ALICE = "arn:aws:iam::123456789012:user/alice"
BOB = "arn:aws:iam::123456789012:user/bob"
LAMBDA_ROLE = "arn:aws:iam::123456789012:role/LambdaExecutionRole"
ADMIN_ROLE = "arn:aws:iam::123456789012:role/AdminRole"
ADMINS_GROUP = "arn:aws:iam::123456789012:group/admins"


def _contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="identity",
        customer_id="cust_test",
        task="Scan AWS account 123456789012 identity posture",
        required_outputs=["findings.json", "summary.md"],
        budget=BudgetSpec(
            llm_calls=5,
            tokens=10_000,
            wall_clock_sec=60.0,
            cloud_api_calls=500,
            mb_written=10,
        ),
        permitted_tools=[
            "aws_iam_list_identities",
            "aws_iam_simulate_principal_policy",
            "aws_access_analyzer_findings",
        ],
        completion_condition="findings.json AND summary.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def _user(
    arn: str,
    name: str,
    *,
    last_used: datetime | None = NOW,
    attached: tuple[str, ...] = (),
    groups: tuple[str, ...] = (),
) -> IamUser:
    return IamUser(
        arn=arn,
        name=name,
        user_id=f"AIDA-{name.upper()}",
        create_date=NOW,
        last_used_at=last_used,
        attached_policy_arns=attached,
        group_memberships=groups,
    )


def _role(
    arn: str,
    name: str,
    *,
    last_used: datetime | None = NOW,
    attached: tuple[str, ...] = (),
) -> IamRole:
    return IamRole(
        arn=arn,
        name=name,
        role_id=f"AROA-{name.upper()}",
        create_date=NOW,
        last_used_at=last_used,
        assume_role_policy_document={},
        attached_policy_arns=attached,
    )


def _group(arn: str, name: str, *, attached: tuple[str, ...] = ()) -> IamGroup:
    return IamGroup(
        arn=arn,
        name=name,
        group_id=f"AGPA-{name.upper()}",
        create_date=NOW,
        attached_policy_arns=attached,
    )


def _patch_listing(monkeypatch: pytest.MonkeyPatch, listing: IdentityListing) -> None:
    async def fake_list(**_: Any) -> IdentityListing:
        return listing

    monkeypatch.setattr(agent_mod, "aws_iam_list_identities", fake_list)


def _patch_analyzer(
    monkeypatch: pytest.MonkeyPatch, findings: Sequence[AccessAnalyzerFinding]
) -> None:
    async def fake_aa(**_: Any) -> Sequence[AccessAnalyzerFinding]:
        return tuple(findings)

    monkeypatch.setattr(agent_mod, "aws_access_analyzer_findings", fake_aa)


def _empty_listing() -> IdentityListing:
    return IdentityListing(users=(), roles=(), groups=())


# ---------------------------- registry ----------------------------------


def test_build_registry_includes_three_tools() -> None:
    reg = build_registry()
    known = reg.known_tools()
    assert "aws_iam_list_identities" in known
    assert "aws_iam_simulate_principal_policy" in known
    assert "aws_access_analyzer_findings" in known


# ---------------------------- empty path --------------------------------


@pytest.mark.asyncio
async def test_run_with_empty_account_yields_no_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_listing(monkeypatch, _empty_listing())
    report = await run(_contract(tmp_path))
    assert report.total == 0
    assert (tmp_path / "ws" / "findings.json").is_file()
    assert (tmp_path / "ws" / "summary.md").is_file()


@pytest.mark.asyncio
async def test_empty_findings_json_is_valid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_listing(monkeypatch, _empty_listing())
    await run(_contract(tmp_path))
    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())
    assert payload["agent"] == "identity"
    assert payload["customer_id"] == "cust_test"
    assert payload["findings"] == []


# ---------------------------- admin-no-MFA fixture ----------------------


@pytest.mark.asyncio
async def test_admin_user_without_mfa_yields_two_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A user with AdministratorAccess + no MFA → overprivilege + MFA_GAP findings."""
    listing = IdentityListing(
        users=(_user(ALICE, "alice", attached=(ADMIN_POLICY,)),),
        roles=(),
        groups=(),
    )
    _patch_listing(monkeypatch, listing)

    report = await run(_contract(tmp_path))

    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())
    types = {f["finding_info"]["types"][0] for f in payload["findings"]}
    assert "overprivilege" in types
    assert "mfa_gap" in types
    assert report.total >= 2


@pytest.mark.asyncio
async def test_admin_with_mfa_yields_overprivilege_but_not_mfa_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    listing = IdentityListing(
        users=(_user(ALICE, "alice", attached=(ADMIN_POLICY,)),),
        roles=(),
        groups=(),
    )
    _patch_listing(monkeypatch, listing)

    await run(_contract(tmp_path), users_with_mfa=frozenset({"alice"}))

    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())
    types = {f["finding_info"]["types"][0] for f in payload["findings"]}
    assert "overprivilege" in types
    assert "mfa_gap" not in types


# ---------------------------- group transitivity ------------------------


@pytest.mark.asyncio
async def test_user_inherits_admin_via_group_membership(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Alice has no direct admin; her group does. The agent must still flag her."""
    listing = IdentityListing(
        users=(_user(ALICE, "alice", groups=("admins",)),),
        roles=(),
        groups=(_group(ADMINS_GROUP, "admins", attached=(ADMIN_POLICY,)),),
    )
    _patch_listing(monkeypatch, listing)

    await run(_contract(tmp_path))

    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())
    overpriv = [f for f in payload["findings"] if f["finding_info"]["types"][0] == "overprivilege"]
    # One for alice (transitive), one for the admins group itself.
    overpriv_arns = {p["uid"] for f in overpriv for p in f["affected_principals"]}
    assert ALICE in overpriv_arns
    assert ADMINS_GROUP in overpriv_arns


# ---------------------------- dormant -----------------------------------


@pytest.mark.asyncio
async def test_dormant_role_finding_emitted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    long_ago = NOW - timedelta(days=400)
    listing = IdentityListing(
        users=(),
        roles=(_role(LAMBDA_ROLE, "LambdaExecutionRole", last_used=long_ago),),
        groups=(),
    )
    _patch_listing(monkeypatch, listing)

    await run(_contract(tmp_path))

    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())
    types = [f["finding_info"]["types"][0] for f in payload["findings"]]
    assert "dormant" in types


# ---------------------------- Access Analyzer ---------------------------


@pytest.mark.asyncio
async def test_external_access_finding_flows_through(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_listing(monkeypatch, _empty_listing())
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
    _patch_analyzer(monkeypatch, [aa])

    await run(
        _contract(tmp_path),
        analyzer_arn="arn:aws:access-analyzer:us-east-1:123456789012:analyzer/x",
    )

    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())
    types = [f["finding_info"]["types"][0] for f in payload["findings"]]
    assert "external_access" in types


@pytest.mark.asyncio
async def test_no_analyzer_arn_skips_access_analyzer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When analyzer_arn is None, the Access Analyzer tool must NOT be called."""
    aa_called = False

    async def boom_aa(**_: Any) -> Sequence[AccessAnalyzerFinding]:
        nonlocal aa_called
        aa_called = True
        return ()

    _patch_listing(monkeypatch, _empty_listing())
    monkeypatch.setattr(agent_mod, "aws_access_analyzer_findings", boom_aa)

    await run(_contract(tmp_path))

    assert aa_called is False


# ---------------------------- multi-finding rollup ----------------------


@pytest.mark.asyncio
async def test_mixed_findings_rollup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Admin user (no MFA) + dormant role + public bucket → 4 families."""
    long_ago = NOW - timedelta(days=400)
    listing = IdentityListing(
        users=(_user(ALICE, "alice", attached=(ADMIN_POLICY,)),),
        roles=(_role(LAMBDA_ROLE, "LambdaExecutionRole", last_used=long_ago),),
        groups=(),
    )
    _patch_listing(monkeypatch, listing)
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
    _patch_analyzer(monkeypatch, [aa])

    await run(
        _contract(tmp_path),
        analyzer_arn="arn:aws:access-analyzer:us-east-1:123456789012:analyzer/x",
    )

    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())
    types = {f["finding_info"]["types"][0] for f in payload["findings"]}
    assert {"overprivilege", "dormant", "external_access", "mfa_gap"} <= types


# ---------------------------- output files ------------------------------


@pytest.mark.asyncio
async def test_findings_json_has_class_uid_2004(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    listing = IdentityListing(
        users=(_user(ALICE, "alice", attached=(ADMIN_POLICY,)),),
        roles=(),
        groups=(),
    )
    _patch_listing(monkeypatch, listing)

    await run(_contract(tmp_path))

    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())
    assert payload["findings"]
    assert all(f["class_uid"] == 2004 for f in payload["findings"])


@pytest.mark.asyncio
async def test_summary_md_includes_high_risk_section_when_admin_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    listing = IdentityListing(
        users=(_user(ALICE, "alice", attached=(ADMIN_POLICY,)),),
        roles=(),
        groups=(),
    )
    _patch_listing(monkeypatch, listing)

    await run(_contract(tmp_path))

    summary = (tmp_path / "ws" / "summary.md").read_text()
    assert "# Identity Scan" in summary
    assert "High-risk principals" in summary
    assert ALICE in summary


# ---------------------------- audit chain -------------------------------


@pytest.mark.asyncio
async def test_audit_log_emits_invocation_completed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_listing(monkeypatch, _empty_listing())
    await run(_contract(tmp_path))

    audit_lines = (tmp_path / "ws" / "audit.jsonl").read_text().splitlines()
    actions = [json.loads(line)["action"] for line in audit_lines if line.strip()]
    assert "invocation_started" in actions
    assert "invocation_completed" in actions


@pytest.mark.asyncio
async def test_envelope_attached_to_each_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    listing = IdentityListing(
        users=(_user(ALICE, "alice", attached=(ADMIN_POLICY,)),),
        roles=(),
        groups=(),
    )
    _patch_listing(monkeypatch, listing)
    contract = _contract(tmp_path)
    await run(contract)

    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())
    for f in payload["findings"]:
        envelope = f["nexus_envelope"]
        assert envelope["agent_id"] == "identity"
        assert envelope["tenant_id"] == "cust_test"
        assert envelope["charter_invocation_id"] == contract.delegation_id


# ---------------------------- LLM provider plumbed but unused -----------


@pytest.mark.asyncio
async def test_run_accepts_llm_provider_without_calling_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Signature accepts llm_provider for future iterations; v0.1 doesn't call it."""
    from charter.llm import FakeLLMProvider  # canonical test double; lives in charter.llm

    _patch_listing(monkeypatch, _empty_listing())
    provider = FakeLLMProvider(responses=[])
    await run(_contract(tmp_path), llm_provider=provider)
    assert provider.calls == []
