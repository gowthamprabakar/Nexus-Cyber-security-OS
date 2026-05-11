"""Identity Agent driver — wires charter + tools + normalizer + summarizer.

Mirrors D.1's [`agent.py`](../../../packages/agents/vulnerability/src/vulnerability/agent.py)
shape. ADR-007 pattern check (D.2 risk-down): the agent.run signature
converges across agents — `(contract, *, llm_provider, ...)`. Confirmed
for a third time.

Differences from D.1:

- Three primary tools (IAM listing, IAM simulator, Access Analyzer)
  instead of one (Trivy). The IAM listing + Access Analyzer fetch run
  concurrently via `asyncio.TaskGroup`; the simulator is wired but
  unused in v0.1 because each principal needs per-action evaluation
  and the deterministic v0.1 path derives admin grants directly from
  `IdentityListing.attached_policy_arns` instead.
- The MFA signal is supplied by the caller (`users_with_mfa: frozenset[str]`);
  Phase 1c will pull it from cloud-posture's existing helpers.
- No external HTTP enrichment in the normalizer — every input is local
  to AWS APIs.

The agent imports `charter.llm_adapter.LLMProvider` directly per ADR-007
v1.1 (D.2 Task 10 validation).
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from datetime import UTC, datetime

from charter import Charter, ToolRegistry
from charter.contract import ExecutionContract
from charter.llm import LLMProvider  # canonical Protocol lives in charter.llm
from shared.fabric.correlation import correlation_scope, new_correlation_id
from shared.fabric.envelope import NexusEnvelope

from identity import __version__ as agent_version
from identity.normalizer import normalize_to_findings
from identity.schemas import FindingsReport
from identity.summarizer import render_summary
from identity.tools.aws_access_analyzer import (
    AccessAnalyzerFinding,
    aws_access_analyzer_findings,
)
from identity.tools.aws_iam import (
    IdentityListing,
    aws_iam_list_identities,
    aws_iam_simulate_principal_policy,
)
from identity.tools.permission_paths import EffectiveGrant

DEFAULT_NLAH_VERSION = "0.1.0"
DEFAULT_DORMANT_THRESHOLD_DAYS = 90

# AWS managed admin policy + customer-managed admin pattern.
_ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def build_registry() -> ToolRegistry:
    """Compose the tool universe available to this agent."""
    reg = ToolRegistry()
    reg.register(
        "aws_iam_list_identities",
        aws_iam_list_identities,
        version="0.1.0",
        cloud_calls=20,
    )
    reg.register(
        "aws_iam_simulate_principal_policy",
        aws_iam_simulate_principal_policy,
        version="0.1.0",
        cloud_calls=50,
    )
    reg.register(
        "aws_access_analyzer_findings",
        aws_access_analyzer_findings,
        version="0.1.0",
        cloud_calls=10,
    )
    return reg


def _envelope(
    contract: ExecutionContract,
    *,
    correlation_id: str,
    model_pin: str,
) -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id=correlation_id,
        tenant_id=contract.customer_id,
        agent_id="identity",
        nlah_version=DEFAULT_NLAH_VERSION,
        model_pin=model_pin,
        charter_invocation_id=contract.delegation_id,
    )


async def run(
    contract: ExecutionContract,
    *,
    llm_provider: LLMProvider | None = None,  # plumbed; not called in v0.1
    aws_region: str = "us-east-1",
    profile: str | None = None,
    analyzer_arn: str | None = None,
    users_with_mfa: frozenset[str] = frozenset(),
    dormant_threshold_days: int = DEFAULT_DORMANT_THRESHOLD_DAYS,
) -> FindingsReport:
    """Run the Identity Agent end-to-end under the runtime charter.

    Args:
        contract: The signed `ExecutionContract`.
        llm_provider: Reserved for future LLM-driven flows; not called in v0.1.
        aws_region: For client construction. IAM is global but boto3 needs one.
        profile: Optional AWS named profile.
        analyzer_arn: If set, fetch Access Analyzer findings from this analyzer.
            When None, the agent skips Access Analyzer entirely (no findings).
        users_with_mfa: Set of user *names* known to have MFA. Anything missing
            here + holding admin grants becomes an MFA_GAP finding. Phase 1c
            wires this from cloud-posture's IAM credential-report helpers.
        dormant_threshold_days: Last-used staleness threshold.

    Returns:
        The `FindingsReport`. Side effects: writes `findings.json` and
        `summary.md` to the charter workspace; emits a hash-chained
        audit log at `audit.jsonl`.
    """
    del llm_provider  # reserved for future iterations

    registry = build_registry()
    model_pin = "deterministic"
    correlation_id = new_correlation_id()

    with correlation_scope(correlation_id), Charter(contract, tools=registry) as ctx:
        scan_started = datetime.now(UTC)
        envelope = _envelope(
            contract,
            correlation_id=correlation_id,
            model_pin=model_pin,
        )

        listing, aa_findings = await _fetch_inventory(
            ctx, aws_region=aws_region, profile=profile, analyzer_arn=analyzer_arn
        )

        grants = _synthesize_admin_grants(listing)

        findings = await normalize_to_findings(
            listing,
            grants,
            aa_findings,
            envelope=envelope,
            detected_at=scan_started,
            dormant_threshold_days=dormant_threshold_days,
            users_with_mfa=users_with_mfa,
        )

        report = FindingsReport(
            agent="identity",
            agent_version=agent_version,
            customer_id=contract.customer_id,
            run_id=contract.delegation_id,
            scan_started_at=scan_started,
            scan_completed_at=datetime.now(UTC),
        )
        for f in findings:
            report.add_finding(f)

        ctx.write_output(
            "findings.json",
            report.model_dump_json(indent=2).encode("utf-8"),
        )
        ctx.write_output(
            "summary.md",
            render_summary(report).encode("utf-8"),
        )

        ctx.assert_complete()

    return report


async def _fetch_inventory(
    ctx: Charter,
    *,
    aws_region: str,
    profile: str | None,
    analyzer_arn: str | None,
) -> tuple[IdentityListing, Sequence[AccessAnalyzerFinding]]:
    """Run IAM listing + Access Analyzer fetch concurrently when both apply."""
    async with asyncio.TaskGroup() as tg:
        listing_task = tg.create_task(
            ctx.call_tool(
                "aws_iam_list_identities",
                region=aws_region,
                profile=profile,
            )
        )
        aa_task: asyncio.Task[Sequence[AccessAnalyzerFinding]] | None = (
            tg.create_task(
                ctx.call_tool(
                    "aws_access_analyzer_findings",
                    analyzer_arn=analyzer_arn,
                    region=aws_region,
                    profile=profile,
                )
            )
            if analyzer_arn
            else None
        )
    listing: IdentityListing = listing_task.result()
    aa_findings: Sequence[AccessAnalyzerFinding] = aa_task.result() if aa_task else ()
    return listing, aa_findings


def _synthesize_admin_grants(listing: IdentityListing) -> list[EffectiveGrant]:
    """Emit one `EffectiveGrant(is_admin=True)` per principal with an admin policy.

    Phase 1 v0.1 derives admin grants directly from the listing's attached
    policy ARNs (matching AdministratorAccess or any `*/AdministratorAccess`)
    instead of running the IAM simulator per principal — the simulator wrapper
    is exercised by its own tests and reserved for Phase 2 finer-grained scans.

    Group transitivity is honored: a user inheriting admin via group
    membership gets a grant attributed to the group's admin policy ARN.
    """
    grants: list[EffectiveGrant] = []

    group_admin: dict[str, tuple[str, ...]] = {}
    for grp in listing.groups:
        admin_arns = tuple(a for a in grp.attached_policy_arns if _is_admin_policy(a))
        if admin_arns:
            group_admin[grp.name] = admin_arns

    for user in listing.users:
        direct = [a for a in user.attached_policy_arns if _is_admin_policy(a)]
        inherited: list[str] = []
        for grp_name in user.group_memberships:
            inherited.extend(group_admin.get(grp_name, ()))
        sources = tuple(direct) + tuple(inherited)
        if sources:
            grants.append(_admin_grant(user.arn, sources))

    for role in listing.roles:
        admin = tuple(a for a in role.attached_policy_arns if _is_admin_policy(a))
        if admin:
            grants.append(_admin_grant(role.arn, admin))

    for grp in listing.groups:
        admin = tuple(a for a in grp.attached_policy_arns if _is_admin_policy(a))
        if admin:
            grants.append(_admin_grant(grp.arn, admin))

    return grants


def _admin_grant(principal_arn: str, source_policy_arns: tuple[str, ...]) -> EffectiveGrant:
    return EffectiveGrant(
        principal_arn=principal_arn,
        action="*:*",
        resource_pattern="*",
        effect="Allow",
        source_policy_arns=source_policy_arns,
        is_admin=True,
    )


def _is_admin_policy(arn: str) -> bool:
    """True when the policy ARN is AWS-managed admin or any `*/AdministratorAccess`."""
    return arn == _ADMIN_POLICY_ARN or arn.endswith("/AdministratorAccess")


__all__ = ["build_registry", "run"]
