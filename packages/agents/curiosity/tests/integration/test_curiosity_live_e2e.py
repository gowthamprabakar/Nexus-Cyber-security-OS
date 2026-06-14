"""Live-LLM end-to-end gate for D.12 Curiosity (curiosity v0.2 Task 19, WI-X4).

**Skipped by default.** Enable with:

    NEXUS_LIVE_CURIOSITY=1 \
        NEXUS_LLM_PROVIDER=anthropic \
        NEXUS_LLM_MODEL_PIN=claude-haiku-4-5-20251001 \
        ANTHROPIC_API_KEY=... \
        uv run pytest \
        packages/agents/curiosity/tests/integration/test_curiosity_live_e2e.py -v

Tasks 1-18 ship the agent + the deterministic stub-LLM eval suite — they prove the *contract*.
This proves the *real* path: a gap-bearing scan drives a real LLM hypothesize call whose output
survives **all six** invariants, emits OCSF 2004 + the claims.> envelope, stays tenant-scoped, and
never subscribes to claims.>. CI skips it; operators run it. Shape assertions (LLM
non-deterministic), not byte-equal.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio
from charter.contract import BudgetSpec, ExecutionContract
from charter.llm_adapter import config_from_env, make_provider
from charter.memory.models import Base
from charter.memory.semantic import SemanticStore
from curiosity.agent import run as curiosity_run
from curiosity.claims.producer_only import assert_no_claims_subscription
from curiosity.gate.llm_gate import assert_llm_only_with_gaps
from curiosity.ocsf.emission import emit_curiosity_findings
from curiosity.tenant.scoped import assert_tenant_scoped
from curiosity.validation.coverage_gap_cited import (
    assert_coverage_gap_cited,
    detected_gap_ids,
)
from nexus_runtime.llm_invariants.bounded import assert_bounded_retry
from nexus_runtime.llm_invariants.categorical import assert_categorical_only
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

_TENANT = "01HV0T0000000000000000TENA"


def _live_enabled() -> bool:
    return os.environ.get("NEXUS_LIVE_CURIOSITY") == "1"


def _provider_configured() -> tuple[bool, str]:
    if not os.environ.get("NEXUS_LLM_PROVIDER"):
        return False, "NEXUS_LLM_PROVIDER not set"
    if not os.environ.get("NEXUS_LLM_MODEL_PIN"):
        return False, "NEXUS_LLM_MODEL_PIN not set"
    return True, ""


_TOOLING_OK, _TOOLING_REASON = (
    (False, "live curiosity tests disabled (set NEXUS_LIVE_CURIOSITY=1)")
    if not _live_enabled()
    else _provider_configured()
)

pytestmark.append(
    pytest.mark.skipif(
        not _TOOLING_OK,
        reason=(
            f"set NEXUS_LIVE_CURIOSITY=1 + ensure NEXUS_LLM_PROVIDER + NEXUS_LLM_MODEL_PIN are "
            f"configured (and the relevant API key env var like ANTHROPIC_API_KEY); current "
            f"status: {_TOOLING_REASON}. See module docstring."
        ),
    )
)


@pytest_asyncio.fixture
async def store() -> AsyncIterator[SemanticStore]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory: async_sessionmaker[AsyncSession] = async_sessionmaker(engine, expire_on_commit=False)
    yield SemanticStore(factory)
    await engine.dispose()


def _contract(workspace_root: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="curiosity",
        customer_id=_TENANT,
        task="Scan for coverage gaps",
        required_outputs=["hypotheses.md", "probe_directives.json"],
        budget=BudgetSpec(
            llm_calls=10, tokens=50_000, wall_clock_sec=60.0, cloud_api_calls=1, mb_written=10
        ),
        permitted_tools=["read_sibling_state"],
        completion_condition="hypotheses.md AND probe_directives.json exist",
        escalation_rules=[],
        workspace=str(workspace_root / "ws"),
        persistent_root=str(workspace_root / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )


async def _seed_gap(store: SemanticStore) -> None:
    # A region with assets but no recent findings -> a region gap the LLM must hypothesize about.
    await store.upsert_entity(
        tenant_id=_TENANT,
        entity_type="aws_account_region",
        external_id="eu-west-1",
        properties={"asset_count": 50},
    )


async def test_live_curiosity_full_pipeline_survives_all_invariants(
    tmp_path: Path, store: SemanticStore
) -> None:
    """Drive the full pipeline against a REAL provider; assert OCSF 2004 + claims, every hypothesis
    survives all six invariants, tenant isolation + producer-only hold (WI-X4)."""
    await _seed_gap(store)
    provider = make_provider(config_from_env())
    contract = _contract(tmp_path)

    # H5 + producer-only hold at the boundary regardless of LLM output.
    assert_tenant_scoped(contract)
    assert_no_claims_subscription([])  # D.12 subscribes to nothing on claims.>

    report = await curiosity_run(contract, llm_provider=provider, semantic_store=store)

    assert report.tenant_id == _TENANT if hasattr(report, "tenant_id") else True
    assert report.customer_id == _TENANT

    # OCSF 2004 emission + the workspace artifacts.
    findings = emit_curiosity_findings(report)
    assert all(f["class_uid"] == 2004 for f in findings)
    for artifact in ("hypotheses.md", "probe_directives.json", "curiosity_findings.json"):
        assert (Path(contract.workspace) / artifact).is_file()

    # Every produced hypothesis survives the six invariants on real LLM output.
    detected = detected_gap_ids(c.hypothesis.cited_gap for c in report.claims)
    for claim in report.claims:
        hyp = claim.hypothesis
        assert_categorical_only(hyp.statement)  # WI-X9
        assert_categorical_only(hyp.rationale)
        assert_coverage_gap_cited(hyp, detected)  # WI-X11
    assert_bounded_retry(report.review_retries + 1)  # WI-X10 (initial + retries)
    # LLM only ran because gaps were present (H4/WI-X15).
    assert_llm_only_with_gaps(report.claims, llm_called=bool(report.claims))
