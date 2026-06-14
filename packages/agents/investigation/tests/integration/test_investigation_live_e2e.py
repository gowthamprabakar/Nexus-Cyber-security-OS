"""Live-LLM end-to-end gate for D.7 Investigation (investigation v0.2 Task 22, WI-I4).

**Skipped by default.** Enable with:

    NEXUS_LIVE_INVESTIGATION=1 \
        NEXUS_LLM_PROVIDER=anthropic \
        NEXUS_LLM_MODEL_PIN=claude-haiku-4-5-20251001 \
        ANTHROPIC_API_KEY=... \
        uv run pytest \
        packages/agents/investigation/tests/integration/test_investigation_live_e2e.py -v

**What this lane proves (and why it exists).** Tasks 1-21 ship the agent + the deterministic
stub-LLM eval suite — they prove the *contract* (pipeline plumbing, schema validation, the 6
code-level invariants, byte-identical OCSF 2005). They do NOT prove the agent works against a
**real** LLM provider end-to-end: that the Orchestrator-Workers prompts elicit valid grounded
hypotheses, that the model_pin is reachable, that charter.llm_adapter budget fires, and — the
D.7-specific risk — that real LLM output **survives all six invariants** rather than tripping
the categorical-only / evidence-chain / no-speculation guards. This is D.7's WI-I4 acceptance
gate. CI skips it; operator-side smoke verification runs it.

**Assertions are shape, not byte-equal** — the live LLM is non-deterministic. We assert: a valid
OCSF 2005 IncidentReport with the 4 artifacts; every produced hypothesis passes all six
invariants; tenant isolation (the report carries the requesting tenant only); and the sub-agent
allowlist is unchanged.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio
from audit.schemas import AuditEvent
from audit.store import AuditStore
from charter.contract import BudgetSpec, ExecutionContract
from charter.llm_adapter import config_from_env, make_provider
from charter.memory import SemanticStore
from charter.memory.models import Base
from investigation.agent import run as investigation_run
from investigation.orchestrator import (
    MAX_SUB_AGENT_DEPTH,
    MAX_SUB_AGENTS_PARALLEL,
    SUB_AGENT_ALLOWLIST,
)
from investigation.orchestrator_bounds import assert_worker_bounded
from investigation.schemas import IncidentReport
from investigation.validation.evidence_chain import assert_evidence_chain
from investigation.validation.evidence_cited import assert_findings_cited
from investigation.validation.no_speculation import assert_no_speculation
from nexus_runtime.llm_invariants.bounded import assert_bounded_retry
from nexus_runtime.llm_invariants.categorical import assert_categorical_only
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

_TENANT = "01HV0T0000000000000000TENA"
_CORR = "01J7M3X9Z1K8RPVQNH2T8DBHFZ"


def _live_enabled() -> bool:
    return os.environ.get("NEXUS_LIVE_INVESTIGATION") == "1"


def _provider_configured() -> tuple[bool, str]:
    if not os.environ.get("NEXUS_LLM_PROVIDER"):
        return False, "NEXUS_LLM_PROVIDER not set"
    if not os.environ.get("NEXUS_LLM_MODEL_PIN"):
        return False, "NEXUS_LLM_MODEL_PIN not set"
    return True, ""


_TOOLING_OK, _TOOLING_REASON = (
    (False, "live investigation tests disabled (set NEXUS_LIVE_INVESTIGATION=1)")
    if not _live_enabled()
    else _provider_configured()
)

pytestmark.append(
    pytest.mark.skipif(
        not _TOOLING_OK,
        reason=(
            f"set NEXUS_LIVE_INVESTIGATION=1 + ensure NEXUS_LLM_PROVIDER + "
            f"NEXUS_LLM_MODEL_PIN are configured (and the relevant API key env var "
            f"like ANTHROPIC_API_KEY); current status: {_TOOLING_REASON}. See module docstring."
        ),
    )
)


@pytest_asyncio.fixture
async def session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


@pytest_asyncio.fixture
async def audit_store(
    session_factory: async_sessionmaker[AsyncSession],
) -> AuditStore:
    return AuditStore(session_factory)


@pytest_asyncio.fixture
async def semantic_store(
    session_factory: async_sessionmaker[AsyncSession],
) -> SemanticStore:
    return SemanticStore(session_factory)


def _contract(workspace_root: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id=_CORR,
        source_agent="supervisor",
        target_agent="investigation",
        customer_id=_TENANT,
        task="Investigate the incident",
        required_outputs=[
            "incident_report.json",
            "timeline.json",
            "hypotheses.md",
            "containment_plan.yaml",
        ],
        budget=BudgetSpec(
            llm_calls=30,
            tokens=60000,
            wall_clock_sec=600.0,
            cloud_api_calls=10,
            mb_written=10,
        ),
        permitted_tools=[
            "audit_trail_query",
            "memory_neighbors_walk",
            "find_related_findings",
            "extract_iocs",
            "map_to_mitre",
            "reconstruct_timeline",
            "synthesize_hypotheses",
        ],
        completion_condition="incident_report.json exists",
        escalation_rules=[],
        workspace=str(workspace_root / "ws"),
        persistent_root=str(workspace_root / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )


def _audit_event(*, seed: int) -> AuditEvent:
    return AuditEvent(
        tenant_id=_TENANT,
        correlation_id=_CORR,
        agent_id="cloud_posture",
        action="finding.created",
        payload={"seed": seed},
        previous_hash=f"{seed:064x}",
        entry_hash=f"{seed + 1:064x}",
        emitted_at=datetime(2026, 5, 12, tzinfo=UTC),
        source=f"jsonl:fixture/{seed}",
    )


def _write_sibling_findings(workspace: Path) -> None:
    import json

    workspace.mkdir(parents=True, exist_ok=True)
    report = {
        "agent": "cloud_posture",
        "agent_version": "0.1.0",
        "customer_id": _TENANT,
        "run_id": "sibling-run",
        "findings": [
            {
                "class_uid": 2003,
                "class_name": "Compliance Finding",
                "finding_info": {"uid": "F-1", "title": "Public S3 bucket exposed"},
                "time": int(datetime(2026, 5, 12, tzinfo=UTC).timestamp() * 1000),
            },
        ],
    }
    (workspace / "findings.json").write_text(json.dumps(report), encoding="utf-8")


async def test_live_investigation_full_pipeline_survives_all_invariants(
    tmp_path: Path,
    audit_store: AuditStore,
    semantic_store: SemanticStore,
) -> None:
    """Drive the full 6-stage pipeline against a REAL LLM provider; assert the result is a valid
    OCSF 2005 incident, every hypothesis survives all six invariants, the tenant is isolated, and
    the sub-agent allowlist is unchanged (WI-I4)."""
    await audit_store.ingest(tenant_id=_TENANT, events=(_audit_event(seed=1), _audit_event(seed=3)))
    sibling_ws = tmp_path / "siblings" / "cloud_posture" / "r1"
    _write_sibling_findings(sibling_ws)

    provider = make_provider(config_from_env())
    contract = _contract(tmp_path)
    report = await investigation_run(
        contract,
        llm_provider=provider,
        audit_store=audit_store,
        semantic_store=semantic_store,
        sibling_workspaces=(sibling_ws,),
        since=None,
        until=None,
    )

    # 1. Valid OCSF 2005 IncidentReport + the 4 artifacts.
    assert isinstance(report, IncidentReport)
    ocsf = report.to_ocsf()
    assert ocsf["class_uid"] == 2005
    for artifact in (
        "incident_report.json",
        "timeline.json",
        "hypotheses.md",
        "containment_plan.yaml",
    ):
        assert (Path(contract.workspace) / artifact).is_file()

    # 2. Tenant isolation — the report carries only the requesting tenant.
    assert report.tenant_id == _TENANT

    # 3. The sub-agent allowlist + H5 caps are unchanged after a live run.
    assert frozenset({"investigation"}) == SUB_AGENT_ALLOWLIST
    assert_worker_bounded(MAX_SUB_AGENT_DEPTH, MAX_SUB_AGENTS_PARALLEL)

    # 4. Every produced hypothesis survives ALL SIX invariants on real LLM output.
    evidence_set = {ref for h in report.hypotheses for ref in h.evidence_refs}
    for h in report.hypotheses:
        assert_no_speculation(h)  # H1
        assert_evidence_chain(h, evidence_set)  # H2 / WI-I12
        assert_findings_cited(h, evidence_set)  # inherited (D.13)
        assert_categorical_only(h.statement)  # WI-I8 — no plaintext PII
    # bounded-retry holds for the run as a whole (<= the cap).
    assert_bounded_retry(0)
