"""Sequenced correlation run: writers populate one shared graph, then D.7 correlates.

NOT the supervisor's parallel dispatch — correlation is inherently ordered (data-security
writes resources + EXPOSES_DATA, then identity links HAS_ACCESS_TO to them, then D.7 reads).
Returns D.7's IncidentReport; the TOXIC_COMBINATION node + OCSF 2005 are persisted in the
shared store. Cloud input is provided by the caller (fixture feed / live readers); graph
writes are real agent code.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from audit.store import AuditStore
from charter.contract import BudgetSpec, ExecutionContract
from charter.memory import SemanticStore
from data_security.agent import run as data_security_run
from identity.agent import run as identity_run
from investigation.agent import run as investigation_run
from investigation.schemas import IncidentReport
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from ulid import ULID

# permitted_tools per agent: mirror each agent's test contract helper exactly.
_DS_TOOLS: list[str] = [
    "read_s3_inventory",
    "read_s3_objects",
    "read_f3_findings",
]
_ID_TOOLS: list[str] = [
    "aws_iam_list_identities",
    "aws_iam_simulate_principal_policy",
    "aws_access_analyzer_findings",
    "detect_aws_saml_providers",
    "detect_aws_oidc_providers",
    "detect_azure_federated_domains",
    "detect_azure_oidc_providers",
]
_D7_TOOLS: list[str] = [
    "audit_trail_query",
    "memory_neighbors_walk",
    "find_related_findings",
    "extract_iocs",
    "map_to_mitre",
    "reconstruct_timeline",
    "synthesize_hypotheses",
]


def _contract(
    tenant: str,
    target: str,
    tools: list[str],
    ws: Path,
    outputs: list[str],
) -> ExecutionContract:
    ws.mkdir(parents=True, exist_ok=True)
    now = datetime.now(UTC)
    return ExecutionContract(
        schema_version="0.1",
        delegation_id=str(ULID()),
        source_agent="correlation_run",
        target_agent=target,
        customer_id=tenant,
        task=f"correlation: {target}",
        required_outputs=outputs,
        budget=BudgetSpec(
            llm_calls=5,
            tokens=20_000,
            wall_clock_sec=120.0,
            cloud_api_calls=50,
            mb_written=20,
        ),
        permitted_tools=tools,
        completion_condition="outputs exist",
        escalation_rules=[],
        workspace=str(ws),
        persistent_root=str(ws / "persistent"),
        created_at=now,
        expires_at=now + timedelta(minutes=10),
    )


async def correlation_run(
    *,
    session_factory: async_sessionmaker[AsyncSession],
    tenant: str,
    ds_inventory_feed: Path | str | None,
    workspace_root: Path,
    ds_objects_feed: Path | str | None = None,
) -> IncidentReport:
    """Run data-security → identity → investigation against a shared graph store.

    Sequence is load-bearing: data-security writes CLOUD_RESOURCE nodes +
    EXPOSES_DATA edges (only for public buckets with classifier hits), identity
    reads those resources and adds HAS_ACCESS_TO edges, investigation correlates.

    `ds_objects_feed`: optional S3 object-sample JSON (same shape as data-security's
    `s3_objects_feed`). Needed for EXPOSES_DATA edges: without classifier hits there
    are no DATA_CLASSIFICATION nodes, so no toxic combination can form. Callers
    testing the happy path should supply a feed with at least one PII-containing
    object in a public bucket.
    """
    store = SemanticStore(session_factory)
    audit_store = AuditStore(session_factory)

    ds_ws = workspace_root / "data_security"
    id_ws = workspace_root / "identity"
    d7_ws = workspace_root / "investigation"

    # 1. data-security: writes CLOUD_RESOURCE nodes + is_public flag + EXPOSES_DATA edges.
    await data_security_run(
        _contract(
            tenant,
            "data_security",
            _DS_TOOLS,
            ds_ws,
            ["findings.json", "report.md"],
        ),
        s3_inventory_feed=ds_inventory_feed,
        s3_objects_feed=ds_objects_feed,
        semantic_store=store,
    )

    # 2. identity: writes IDENTITY nodes + HAS_ACCESS_TO edges (admin → resources in graph).
    await identity_run(
        _contract(
            tenant,
            "identity",
            _ID_TOOLS,
            id_ws,
            ["findings.json", "summary.md"],
        ),
        semantic_store=store,
    )

    # 3. D.7: reads the combined graph + identity findings → persisted toxic combination.
    return await investigation_run(
        _contract(
            tenant,
            "investigation",
            _D7_TOOLS,
            d7_ws,
            ["incident_report.json", "timeline.json", "hypotheses.md", "containment_plan.yaml"],
        ),
        audit_store=audit_store,
        semantic_store=store,
        sibling_workspaces=(ds_ws, id_ws),
        detect_toxic_combinations=True,
    )


__all__ = ["correlation_run"]
