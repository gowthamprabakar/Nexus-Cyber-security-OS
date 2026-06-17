"""SaaS Security Posture Management (SSPM) agent driver — D.10 / Agent under ADR-007.

v0.4 Stage 2. Discovers SaaS application posture across an org's SaaS estate and emits
OCSF v1.3 Compliance Findings (class_uid 2003, operator Q2). DEPTH-FIRST connector set
(operator Q1: GitHub-org + M365 + Slack) — **GitHub-org wired (PR2)**; M365 + Slack land
in PR3-4; the fleet-graph ``kg_writer`` (SaaS inventory on the coherent ADR-018 spine) in
PR5.

ADR-007 pattern check: the agent ``run`` signature converges across agents —
``(contract, *, llm_provider, ..., semantic_store)``. SSPM follows the reference shape.
"""

from __future__ import annotations

from datetime import UTC, datetime

from charter import Charter, ToolRegistry
from charter.contract import ExecutionContract
from charter.llm import LLMProvider
from charter.memory.semantic import SemanticStore
from shared.fabric.correlation import correlation_scope, new_correlation_id
from shared.fabric.envelope import NexusEnvelope

from sspm import __version__ as agent_version
from sspm.credentials import SaaSCredentialResolver
from sspm.posture.github import evaluate_github_org
from sspm.posture.m365 import evaluate_m365_tenant
from sspm.schemas import FindingsReport
from sspm.tools.github_org import HttpTransport, httpx_transport, read_github_org
from sspm.tools.m365 import GraphClient, build_graph_client, read_m365_tenant

DEFAULT_NLAH_VERSION = "0.1.0"

#: Env vars holding SaaS credentials (resolved per call by SaaSCredentialResolver, never stored).
_GITHUB_TOKEN_ENV = "NEXUS_SSPM_GITHUB_TOKEN"
_M365_CLIENT_ID_ENV = "NEXUS_SSPM_M365_CLIENT_ID"
_M365_CLIENT_SECRET_ENV = "NEXUS_SSPM_M365_CLIENT_SECRET"


def build_registry() -> ToolRegistry:
    """Compose the tool universe available to this agent.

    Each connector reader is ``cloud_calls``-budgeted so the Charter tracks SaaS API
    usage. The Slack reader registers here in PR4.
    """
    reg = ToolRegistry()
    # One logical SaaS scan per connector (several API calls) → representative cloud cost
    # (mirrors the k8s read_cluster_inventory single-invocation convention).
    reg.register("read_github_org", read_github_org, version="0.4.0", cloud_calls=10)
    reg.register("read_m365_tenant", read_m365_tenant, version="0.4.0", cloud_calls=10)
    return reg


def _envelope(contract: ExecutionContract, *, correlation_id: str, model_pin: str) -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id=correlation_id,
        tenant_id=contract.customer_id,
        agent_id="sspm",
        nlah_version=DEFAULT_NLAH_VERSION,
        model_pin=model_pin,
        charter_invocation_id=contract.delegation_id,
    )


def _render_summary(report: FindingsReport) -> str:
    counts = report.count_by_severity()
    lines = [
        "# SaaS Security Posture (SSPM)",
        "",
        f"- Customer: {report.customer_id}",
        f"- Findings: {report.total}",
        f"- By severity: {counts}",
    ]
    return "\n".join(lines) + "\n"


async def run(
    contract: ExecutionContract,
    *,
    llm_provider: LLMProvider | None = None,  # plumbed; not called in v0.4
    github_org: str | None = None,
    github_transport: HttpTransport | None = None,
    github_max_repos: int = 100,
    m365_tenant: str | None = None,
    m365_graph: GraphClient | None = None,
    semantic_store: SemanticStore | None = None,
) -> FindingsReport:
    """Run the SSPM agent end-to-end under the runtime charter.

    Args:
        github_org: When set, scan this GitHub organization's posture (PR2 connector).
            None skips the connector. PAT auth via ``SaaSCredentialResolver`` reads
            ``$NEXUS_SSPM_GITHUB_TOKEN`` per call (never persisted).
        github_transport: Injectable HTTP seam for the GitHub connector (tests pass a
            deterministic fake). Default None → the live httpx-backed transport.
        github_max_repos: Cap on repos enumerated for the GitHub scan.
        m365_tenant: When set, scan this Microsoft 365 tenant's posture (PR3 connector).
            OAuth2 client-credentials via ``SaaSCredentialResolver`` reads
            ``$NEXUS_SSPM_M365_CLIENT_ID`` / ``_SECRET`` per call (never persisted).
        m365_graph: Injectable Microsoft Graph seam for the M365 connector (tests pass a
            fake ``GraphClient``). Default None → the live httpx-backed client.
        semantic_store: opt-in fleet-graph sink (default None inert) consumed by the PR5
            ``kg_writer``; threaded now so the signature is stable.

    Returns:
        The :class:`FindingsReport`. Side effects: writes ``findings.json`` + ``summary.md``
        to the charter workspace and a hash-chained audit log.
    """
    del llm_provider  # reserved
    del semantic_store  # PR5 kg_writer consumes this; threaded for signature stability

    registry = build_registry()
    model_pin = "deterministic"
    correlation_id = new_correlation_id()

    with correlation_scope(correlation_id), Charter(contract, tools=registry) as ctx:
        scan_started = datetime.now(UTC)
        envelope = _envelope(contract, correlation_id=correlation_id, model_pin=model_pin)

        report = FindingsReport(
            agent="sspm",
            agent_version=agent_version,
            customer_id=contract.customer_id,
            run_id=contract.delegation_id,
            scan_started_at=scan_started,
            scan_completed_at=datetime.now(UTC),
        )

        # Connector: GitHub-org (PR2). Routed through the charter proxy (budget + audit;
        # call_tool audits only kwarg KEY names, so the resolver/transport objects — and
        # the PAT resolved inside the connector — never enter the audit log).
        if github_org is not None:
            resolver = SaaSCredentialResolver(provider="github", env={"token": _GITHUB_TOKEN_ENV})
            inventory = await ctx.call_tool(
                "read_github_org",
                org=github_org,
                resolver=resolver,
                transport=github_transport if github_transport is not None else httpx_transport(),
                max_repos=github_max_repos,
            )
            for finding in evaluate_github_org(
                inventory, envelope=envelope, detected_at=scan_started
            ):
                report.add_finding(finding)

        # Connector: Microsoft 365 (PR3). Same charter-proxy routing + secret safety.
        if m365_tenant is not None:
            resolver = SaaSCredentialResolver(
                provider="m365",
                env={"client_id": _M365_CLIENT_ID_ENV, "client_secret": _M365_CLIENT_SECRET_ENV},
            )
            graph = (
                m365_graph if m365_graph is not None else build_graph_client(resolver, m365_tenant)
            )
            m365_inventory = await ctx.call_tool(
                "read_m365_tenant", tenant_id=m365_tenant, graph=graph
            )
            for finding in evaluate_m365_tenant(
                m365_inventory, envelope=envelope, detected_at=scan_started
            ):
                report.add_finding(finding)

        report.scan_completed_at = datetime.now(UTC)
        ctx.write_output("findings.json", report.model_dump_json(indent=2).encode("utf-8"))
        ctx.write_output("summary.md", _render_summary(report).encode("utf-8"))
        ctx.assert_complete()

    return report
