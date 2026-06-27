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
from typing import Any

from charter import Charter, ToolRegistry
from charter.contract import ExecutionContract
from charter.llm import LLMProvider  # canonical Protocol lives in charter.llm
from charter.memory.graph_types import NodeCategory
from charter.memory.semantic import SemanticStore
from shared.fabric.correlation import correlation_scope, new_correlation_id
from shared.fabric.envelope import NexusEnvelope

from identity import __version__ as agent_version
from identity.kg_writer import KnowledgeGraphWriter
from identity.normalizer import federation_to_findings, normalize_to_findings
from identity.schemas import FindingsReport, IdentityFinding
from identity.summarizer import render_summary
from identity.tools.aws_access_analyzer import (
    AccessAnalyzerFinding,
    aws_access_analyzer_findings,
)
from identity.tools.aws_iam import (
    IdentityListing,
    SimulationDecision,
    aws_iam_list_identities,
    aws_iam_simulate_principal_policy,
)
from identity.tools.federation import (
    detect_aws_oidc_providers,
    detect_aws_saml_providers,
    detect_azure_federated_domains,
    detect_azure_oidc_providers,
)
from identity.tools.permission_paths import EffectiveGrant, resolve_effective_grants

DEFAULT_NLAH_VERSION = "0.1.0"
DEFAULT_DORMANT_THRESHOLD_DAYS = 90

# A-4 (v0.3) curated high-leverage action set (Fork 1a). Simulating every AWS
# action per principal is combinatorially expensive; this bounded risk-weighted
# set captures the privilege-escalation surface (anything-IAM, data-plane S3/EC2,
# role assumption) and keeps the live SimulatePrincipalPolicy cost predictable.
CURATED_RISK_ACTIONS: tuple[str, ...] = ("iam:*", "s3:*", "ec2:*", "sts:AssumeRole")

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
    # A-1 live-loop wiring: SAML/OIDC federation-trust detectors (AWS + Azure).
    reg.register(
        "detect_aws_saml_providers", detect_aws_saml_providers, version="0.2.0", cloud_calls=1
    )
    reg.register(
        "detect_aws_oidc_providers", detect_aws_oidc_providers, version="0.2.0", cloud_calls=2
    )
    reg.register(
        "detect_azure_federated_domains",
        detect_azure_federated_domains,
        version="0.2.0",
        cloud_calls=1,
    )
    reg.register(
        "detect_azure_oidc_providers", detect_azure_oidc_providers, version="0.2.0", cloud_calls=1
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
    detect_federation: bool = False,
    azure_credential_source: str | None = None,
    assess_effective_perms: bool = False,
    semantic_store: SemanticStore | None = None,
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
        detect_federation: A-1 live-loop wiring. When True, detect SAML/OIDC
            federation trusts (AWS via profile/region, Azure via
            ``azure_credential_source``) and emit them through the
            ``federation_to_findings`` second emitter (OCSF 2004), additively
            alongside the AWS-IAM findings. Default False keeps the AWS-IAM
            path byte-identical to pre-A-1.
        azure_credential_source: Optional Azure credential-source hint for the
            Azure federation detectors; ignored unless ``detect_federation``.
        assess_effective_perms: A-4 (v0.3) live-loop wiring. When True, drives the
            IAM ``SimulatePrincipalPolicy`` simulator per principal against the
            curated risk-action set (``CURATED_RISK_ACTIONS``) and resolves the
            decisions into ``EffectiveGrant``s — replacing the v0.1 attached-policy
            pattern-match (``_synthesize_admin_grants``) with simulator-derived
            effective grants. Refines OVERPRIVILEGE with real per-action grants
            (no new OCSF class). Requires live AWS; default False keeps the
            attached-policy path byte-identical to pre-A-4 (offline eval intact).
        semantic_store: v0.4 Stage 1.2 (D.2) opt-in fleet-graph sink. When set,
            the IAM principal inventory (users/roles/groups + managed policies,
            ATTACHED_TO / MEMBER_OF edges) is written via ``KnowledgeGraphWriter``
            after the listing fetch. ``HAS_ACCESS_TO`` stays Stage 3 correlation.
            Default None is inert — no graph writes, ``findings.json`` byte-identical.

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

        # v0.4 Stage 1.2: write the IAM principal inventory to the fleet graph when a
        # SemanticStore is injected. Opt-in — default None is inert (no graph writes),
        # so findings.json + summary.md stay byte-identical. HAS_ACCESS_TO (principal →
        # resource) stays Stage 3 cross-agent correlation.
        if semantic_store is not None:
            kg = KnowledgeGraphWriter(semantic_store, contract.customer_id)
            await kg.record_listing(listing)

        # A-4 (v0.3): drive the effective-perms simulator when enabled (live AWS),
        # else fall back to the v0.1 attached-policy pattern-match (byte-identical).
        if assess_effective_perms:
            grants = await _simulate_effective_grants(
                ctx, listing, profile=profile, aws_region=aws_region
            )
        else:
            grants = _synthesize_admin_grants(listing)

        if semantic_store is not None:
            await _write_access_edges(semantic_store, contract.customer_id, grants)

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

        # A-1 live-loop wiring: additive federation-trust emission (2nd emitter).
        if detect_federation:
            for f in await _detect_federation(
                ctx,
                envelope=envelope,
                profile=profile,
                aws_region=aws_region,
                azure_credential_source=azure_credential_source,
                detected_at=scan_started,
            ):
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


async def _simulate_effective_grants(
    ctx: Charter,
    listing: IdentityListing,
    *,
    profile: str | None,
    aws_region: str,
) -> list[EffectiveGrant]:
    """A-4: simulate effective permissions per principal → resolve to grants.

    Drives ``aws_iam_simulate_principal_policy`` (via ctx.call_tool so the charter
    gates/budgets/audits each call — ADR-016) for every user and role against
    ``CURATED_RISK_ACTIONS``, then flattens the decisions through
    ``resolve_effective_grants``. Users + roles only: the simulator already folds
    in group-inherited policies for a user, so groups need no direct simulation
    (per permission_paths Q3). Returns ``[]`` for an empty listing.
    """
    principal_arns = [u.arn for u in listing.users] + [r.arn for r in listing.roles]
    if not principal_arns:
        return []
    async with asyncio.TaskGroup() as tg:
        tasks = [
            tg.create_task(
                ctx.call_tool(
                    "aws_iam_simulate_principal_policy",
                    principal_arn=arn,
                    actions=list(CURATED_RISK_ACTIONS),
                    resources=("*",),
                    profile=profile,
                    region=aws_region,
                )
            )
            for arn in principal_arns
        ]
    decisions: list[SimulationDecision] = []
    for task in tasks:
        decisions.extend(task.result())
    return list(resolve_effective_grants(listing, decisions))


async def _detect_federation(
    ctx: Charter,
    *,
    envelope: NexusEnvelope,
    profile: str | None,
    aws_region: str,
    azure_credential_source: str | None,
    detected_at: datetime,
) -> list[IdentityFinding]:
    """A-1 live-loop wiring: detect SAML/OIDC federation trusts (AWS + Azure) and
    map them to OCSF 2004 findings via the ``federation_to_findings`` emitter.

    The four detectors dispatch concurrently through the charter; AWS uses
    profile/region, Azure uses the ``credential_source`` seam. This is a second,
    additive emitter — it does not touch the AWS-IAM ``normalize_to_findings``
    path (WI-I5), so the offline AWS eval stays byte-identical.
    """
    async with asyncio.TaskGroup() as tg:
        saml_task = tg.create_task(
            ctx.call_tool("detect_aws_saml_providers", profile=profile, region=aws_region)
        )
        oidc_task = tg.create_task(
            ctx.call_tool("detect_aws_oidc_providers", profile=profile, region=aws_region)
        )
        az_dom_task = tg.create_task(
            ctx.call_tool(
                "detect_azure_federated_domains", credential_source=azure_credential_source
            )
        )
        az_oidc_task = tg.create_task(
            ctx.call_tool("detect_azure_oidc_providers", credential_source=azure_credential_source)
        )
    return federation_to_findings(
        envelope=envelope,
        aws_saml=saml_task.result(),
        aws_oidc=oidc_task.result(),
        azure_federated_domains=az_dom_task.result(),
        azure_oidc=az_oidc_task.result(),
        detected_at=detected_at,
    )


def _statement_grants_admin(statement: dict[str, Any]) -> bool:
    """True when an IAM policy statement is a full wildcard-admin allow (Action ``*``
    on Resource ``*``, Effect Allow) — the inline equivalent of AdministratorAccess."""
    if str(statement.get("Effect", "")) != "Allow":
        return False

    def _has_star(value: Any) -> bool:
        if isinstance(value, str):
            return value == "*"
        if isinstance(value, (list, tuple)):
            return "*" in value
        return False

    return _has_star(statement.get("Action")) and _has_star(statement.get("Resource"))


def _inline_admin_sources(
    inline_policies: tuple[tuple[str, dict[str, Any]], ...],
) -> tuple[str, ...]:
    """v0.4 Stage 1.5 per-role inline-grant evaluation — inspect inline policy
    *documents* (fetched in #723) for wildcard-admin statements. Returns
    ``inline:<name>`` source tokens for each inline policy granting admin. Previously
    inline policies were enumerated by name only, so inline-only admins were missed."""
    sources: list[str] = []
    for name, document in inline_policies:
        statements = document.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        if any(_statement_grants_admin(s) for s in statements if isinstance(s, dict)):
            sources.append(f"inline:{name}")
    return tuple(sources)


def _synthesize_admin_grants(listing: IdentityListing) -> list[EffectiveGrant]:
    """Emit one `EffectiveGrant(is_admin=True)` per principal with an admin grant.

    Phase 1 v0.1 derived admin grants from attached policy ARNs (AdministratorAccess
    or `*/AdministratorAccess`). v0.4 Stage 1.5 adds **inline-grant evaluation**: the
    inline policy documents (#723) are inspected for wildcard-admin statements, so a
    principal that is admin via an inline policy — with no attached admin policy — is
    now caught. The simulator (`_simulate_effective_grants`) remains the gated finer
    path for per-action/per-resource scans.

    Group transitivity is honored for both attached and inline group admin.
    """
    grants: list[EffectiveGrant] = []
    doc_by_arn = {policy.arn: policy.document for policy in listing.policies}

    def _admin_capped(principal: object) -> bool:
        # gap #8: a resolvable boundary that does NOT allow full admin caps the admin grant.
        boundary = _boundary_doc(principal, doc_by_arn)
        return boundary is not None and not _boundary_allows_admin(boundary)

    group_admin: dict[str, tuple[str, ...]] = {}
    for grp in listing.groups:
        admin_sources = tuple(a for a in grp.attached_policy_arns if _is_admin_policy(a))
        admin_sources += _inline_admin_sources(grp.inline_policies)
        if admin_sources:
            group_admin[grp.name] = admin_sources

    for user in listing.users:
        direct = [a for a in user.attached_policy_arns if _is_admin_policy(a)]
        inherited: list[str] = []
        for grp_name in user.group_memberships:
            inherited.extend(group_admin.get(grp_name, ()))
        sources = tuple(direct) + tuple(inherited) + _inline_admin_sources(user.inline_policies)
        if sources and not _admin_capped(user):
            grants.append(_admin_grant(user.arn, sources))

    for role in listing.roles:
        admin = tuple(a for a in role.attached_policy_arns if _is_admin_policy(a))
        admin += _inline_admin_sources(role.inline_policies)
        if admin and not _admin_capped(role):
            grants.append(_admin_grant(role.arn, admin))

    for grp in listing.groups:
        admin = group_admin.get(grp.name, ())
        if admin:
            grants.append(_admin_grant(grp.arn, admin))

    return grants


def _externally_trusted_arns(listing: IdentityListing) -> list[str]:
    """Roles whose trust policy lets a *foreign account* (or `*`) assume them — offline.

    Path-8 signal, derived purely from each role's ``AssumeRolePolicyDocument`` (already in
    the listing). External = an ``Allow`` statement whose principal is either (a) ``Principal.AWS``
    that is a wildcard or an account outside the role's own account, or (b) ``Principal.Federated``
    — an external OIDC/SAML provider (e.g. GitHub Actions OIDC, an external IdP), assumable by
    whoever controls that identity. Service principals (``Principal.Service``) are trust-to-an-
    AWS-service, never external, so they are ignored. Offline counterpart to Access-Analyzer.
    """
    flagged: list[str] = []
    for role in listing.roles:
        own_account = _account_of(role.arn)
        statements = role.assume_role_policy_document.get("Statement") or []
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal")
            if _principal_is_federated(principal) or any(
                account == "*" or account != own_account
                for account in _aws_principal_accounts(principal)
            ):
                flagged.append(role.arn)
                break
    return flagged


def _named_aws_principals(principal: object) -> list[str]:
    """Specific user/role ARNs named in ``Principal.AWS`` (not ``*``, account-root, or service)."""
    if not isinstance(principal, dict):
        return []
    aws = principal.get("AWS")
    values = [aws] if isinstance(aws, str) else list(aws or [])
    return [v for v in values if isinstance(v, str) and (":role/" in v or ":user/" in v)]


def _assume_grants(listing: IdentityListing) -> list[tuple[str, str]]:
    """``(principal_arn, role_arn)`` for each SAME-account named principal a role's trust policy
    lets assume it — the internal role-assumption edges (privilege-escalation, path #13).

    Offline, from each role's ``AssumeRolePolicyDocument``. Cross-account / wildcard / federated
    principals are external trust (path 8, ``_externally_trusted_arns``), not internal escalation.
    Deduped, order-preserving.
    """
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for role in listing.roles:
        own_account = _account_of(role.arn)
        for stmt in role.assume_role_policy_document.get("Statement") or []:
            if stmt.get("Effect") != "Allow":
                continue
            for arn in _named_aws_principals(stmt.get("Principal")):
                grant = (arn, role.arn)
                if _account_of(arn) == own_account and arn != role.arn and grant not in seen:
                    seen.add(grant)
                    out.append(grant)
    return out


def _credential_grants(listing: IdentityListing) -> list[tuple[str, str]]:
    """``(user_arn, access_key_id)`` for every IAM user access key — the credential-ownership
    edges that converge with a credential leaked in source code (path #17). Order-preserving."""
    return [(user.arn, key_id) for user in listing.users for key_id in user.access_key_ids]


def _principal_is_federated(principal: object) -> bool:
    """True when a trust statement allows an external OIDC/SAML federation provider."""
    return isinstance(principal, dict) and bool(principal.get("Federated"))


def _account_of(arn: str) -> str:
    """The 12-digit account id from an ARN (`arn:aws:iam::ACCOUNT:role/x`), or "" if absent."""
    parts = arn.split(":")
    return parts[4] if len(parts) > 4 else ""


def _aws_principal_accounts(principal: object) -> list[str]:
    """Account ids (or `*`) named by a statement's ``Principal.AWS`` — `[]` for service-only.

    ``Principal`` may be ``"*"``, ``{"AWS": "*"|arn|[arns]}``, or ``{"Service": ...}``.
    A bare ``"*"`` (public) and an ``arn:aws:iam::ACCT:root`` both reduce to their account token.
    """
    if principal == "*":
        return ["*"]
    if not isinstance(principal, dict):
        return []
    aws = principal.get("AWS")
    values = [aws] if isinstance(aws, str) else list(aws or [])
    return ["*" if v == "*" else _account_of(v) for v in values]


def _as_list(value: object) -> list[Any]:
    """An IAM ``Action``/``Resource`` field as a list (it may be a bare string)."""
    if value is None:
        return []
    return [value] if isinstance(value, str) else list(value)


def _grants_s3_read(actions: object) -> bool:
    """True if any action reads S3 object data (``*``, ``s3:*``, or an ``s3:get*``)."""
    for action in _as_list(actions):
        if not isinstance(action, str):
            continue
        lowered = action.lower()
        if lowered in {"*", "s3:*"} or lowered.startswith("s3:get"):
            return True
    return False


# --- gap #8: permission-boundary capping (conservative — never suppress on ambiguity) ---


def _boundary_doc(
    principal: object, doc_by_arn: dict[str, dict[str, Any]]
) -> dict[str, Any] | None:
    """The principal's resolvable permission-boundary document, or ``None``.

    ``None`` means *no boundary OR unresolvable* (AWS-managed boundary not in the listing) — the
    callers treat ``None`` as "do not cap", so an unknown boundary never suppresses a finding
    (no false negatives; we only cap when the boundary is known to disallow).
    """
    arn = getattr(principal, "permission_boundary_arn", "")
    return doc_by_arn.get(arn) if arn else None


def _boundary_allows_admin(doc: dict[str, Any]) -> bool:
    """True if the boundary has an ``Allow`` of ``*`` action on ``*`` resource (full admin)."""
    for stmt in doc.get("Statement") or []:
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
            continue
        actions = [a for a in _as_list(stmt.get("Action")) if isinstance(a, str)]
        resources = [r for r in _as_list(stmt.get("Resource")) if isinstance(r, str)]
        if "*" in actions and "*" in resources:
            return True
    return False


def _boundary_allows_s3_read(doc: dict[str, Any], bucket_arn: str) -> bool:
    """True if the boundary allows an S3 read on ``*`` or the given bucket."""
    for stmt in doc.get("Statement") or []:
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
            continue
        if not _grants_s3_read(stmt.get("Action")):
            continue
        for resource in _as_list(stmt.get("Resource")):
            if resource == "*" or bucket_arn in _concrete_bucket_arns([resource]):
                return True
    return False


def _concrete_bucket_arns(resources: object) -> list[str]:
    """Canonical bucket ARNs named by a statement ``Resource`` (object suffix stripped).

    ``arn:aws:s3:::bucket/key/*`` → ``arn:aws:s3:::bucket`` so the grant joins the spine
    bucket node data-security writes. A bare ``*`` (all buckets) is skipped — that is broad,
    not fine-grained-to-a-resource.
    """
    arns: list[str] = []
    for resource in _as_list(resources):
        if not isinstance(resource, str) or not resource.startswith("arn:aws:s3:::"):
            continue
        bucket = resource[len("arn:aws:s3:::") :].split("/", 1)[0]
        if bucket and bucket != "*":
            arns.append(f"arn:aws:s3:::{bucket}")
    return arns


def _fine_grained_grants(listing: IdentityListing) -> list[tuple[str, str]]:
    """Concrete-resource S3 read grants ``(principal_arn, bucket_arn)`` — offline depth.

    Beyond :func:`_synthesize_admin_grants` (admin ``*`` over everything): walks each
    principal's customer-managed + inline policy documents for ``Allow`` statements that grant
    an S3 read action on a **concrete** bucket ARN, emitting a fine-grained (principal, bucket)
    pair. This catches a least-privilege-violating principal — specific access to a sensitive
    bucket, *not* admin — that the admin-only path (1) is blind to. A user's **group-inherited**
    policies are resolved too (access via group membership). Deduped.
    """
    doc_by_arn = {policy.arn: policy.document for policy in listing.policies}
    group_by_name = {group.name: group for group in listing.groups}
    grants: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for principal in (*listing.users, *listing.roles):
        documents = [doc_by_arn[arn] for arn in principal.attached_policy_arns if arn in doc_by_arn]
        documents += [doc for _name, doc in principal.inline_policies]
        # Users inherit their groups' attached + inline policies (roles have no groups).
        for group_name in getattr(principal, "group_memberships", ()):
            group = group_by_name.get(group_name)
            if group is None:
                continue
            documents += [
                doc_by_arn[arn] for arn in group.attached_policy_arns if arn in doc_by_arn
            ]
            documents += [doc for _name, doc in group.inline_policies]
        boundary = _boundary_doc(principal, doc_by_arn)  # gap #8: caps effective access
        for document in documents:
            for stmt in document.get("Statement") or []:
                if stmt.get("Effect") != "Allow" or not _grants_s3_read(stmt.get("Action")):
                    continue
                for bucket_arn in _concrete_bucket_arns(stmt.get("Resource")):
                    # A permissions boundary that does NOT allow this read caps the grant.
                    if boundary is not None and not _boundary_allows_s3_read(boundary, bucket_arn):
                        continue
                    key = (principal.arn, bucket_arn)
                    if key not in seen:
                        seen.add(key)
                        grants.append(key)
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


async def _write_access_edges(
    semantic_store: SemanticStore,
    customer_id: str,
    grants: list[EffectiveGrant],
) -> None:
    """Write IDENTITY --HAS_ACCESS_TO--> CLOUD_RESOURCE for admin-grade principals.

    Drives the offline admin-grant synthesis: an admin (resource_pattern "*") can reach
    every resource, so we expand "*" against the tenant's concrete CLOUD_RESOURCE nodes
    (written by data-security/cloud-posture, keyed by ARN). record_access upserts
    idempotently -> edges land on the existing resource nodes.

    # Bound (v1): admin-grade only. Fine-grained non-admin access needs concrete
    # per-statement Resource extraction (not implemented) + the live SimulatePrincipalPolicy
    # simulator (needs live AWS) -- deferred to a later depth slice.
    """
    admins = [g for g in grants if g.is_admin]
    if not admins:
        return
    resources = await semantic_store.list_entities_by_type(
        tenant_id=customer_id, entity_type=NodeCategory.CLOUD_RESOURCE.value
    )
    if not resources:
        return
    kg = KnowledgeGraphWriter(semantic_store, customer_id)
    await kg.record_access([(g.principal_arn, r.external_id) for g in admins for r in resources])


__all__ = ["build_registry", "run"]
