"""Eval-suite back-compat gate — semantic_store=None vs in-memory parity.

Task 5 of the KG-loop-closure plan
(`docs/superpowers/plans/2026-05-18-kg-loop-closure-cloud-posture-to-semanticstore.md`).

The reroute (Task 3) made the KG write path target the Postgres
`SemanticStore` instead of a Neo4j async driver. Plan claim: **the reroute
is additive — when `semantic_store=None`, the agent's observable output
is byte-identical to a run with a populated SemanticStore.** This gate
proves it for the 10 shipped Cloud Posture eval cases.

Mechanism. The full eval suite runs TWICE per case:

1. `semantic_store=None` (skip-KG path — equivalent to the pre-reroute
   `neo4j_driver=None` behaviour the eval-runner has always used).
2. `semantic_store=<in-memory aiosqlite-backed SemanticStore>` (the new
   KG write path, exercised against a freshly-migrated in-memory store
   per case).

Per-case actuals are captured across 6 deterministic dimensions of the
report (count, severity distribution, finding identity set, rule
identity set, OCSF class stability, resource identity set). Any
divergence between the two runs implies the reroute is observable from
outside the KG layer — at which point this gate fails and the plan
rejects.

This file mirrors F.7 v0.2's flag-OFF/flag-ON additive-only gate
discipline: no production-code change to wire the flag; the test-side
monkeypatch is what swaps in the in-memory store. Eval-runner internals
are unmodified.

Live Postgres is NOT in scope here — that's Task 6's load-bearing live
proof, where the SAME additive-only assertion runs against a real
cluster, and where the within-run REPEATED-WRITE case is asserted
end-to-end.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from charter.memory import SemanticStore
from charter.memory.models import Base
from cloud_posture import agent as agent_mod
from cloud_posture.eval_runner import CloudPostureEvalRunner
from cloud_posture.schemas import FindingsReport
from eval_framework.cases import load_cases
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# ---------------------------- in-memory SemanticStore fixture ---------------


@pytest_asyncio.fixture
async def in_memory_store() -> AsyncIterator[SemanticStore]:
    """Fresh in-memory aiosqlite-backed `SemanticStore` per test.

    Mirrors the `charter/tests/test_semantic_store.py` fixture exactly —
    `Base.metadata.create_all` migrates the `entities` + `relationships`
    tables into the in-memory database, then a single
    `async_sessionmaker` is bound to that engine.
    """
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory: async_sessionmaker[AsyncSession] = async_sessionmaker(engine, expire_on_commit=False)
    yield SemanticStore(factory)
    await engine.dispose()


# ---------------------------- actuals extractor -----------------------------


def _actuals_for_back_compat(case_id: str, report: FindingsReport) -> dict[str, Any]:
    """Six deterministic dimensions of the report, suitable for byte-equality.

    Selected so the comparison is stable across the two runs but still
    catches every shape of additive-violation: count drift, severity
    drift, finding-set drift, rule-set drift, OCSF-shape drift, and
    resource-set drift. Timestamps and correlation_ids are excluded
    because they ARE expected to differ across two separate invocations.
    """
    finding_ids: list[str] = []
    rule_ids: list[str] = []
    class_uids: list[int] = []
    resource_uids: list[str] = []
    for raw in report.findings:
        finding_ids.append(str(raw["finding_info"]["uid"]))
        rule_ids.append(str(raw["compliance"]["control"]))
        class_uids.append(int(raw["class_uid"]))
        for r in raw.get("resources", []):
            uid = r.get("uid")
            if uid is not None:
                resource_uids.append(str(uid))
    return {
        "case_id": case_id,
        "finding_count": report.total,
        "by_severity": report.count_by_severity(),
        "finding_ids": sorted(finding_ids),
        "rule_ids": sorted(set(rule_ids)),
        "class_uids": sorted(set(class_uids)),
        "resource_uids": sorted(resource_uids),
    }


# ---------------------------- the load-bearing gate -------------------------


@pytest.mark.asyncio
async def test_all_ten_cases_byte_identical_actuals_across_semantic_store_modes(
    tmp_path: Path,
    in_memory_store: SemanticStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each of the 10 eval cases must produce identical actuals OFF vs. ON.

    The gate: capture per-case actuals across the 6 deterministic
    dimensions for the skip-KG path (`semantic_store=None`) AND the
    KG-enabled path (in-memory SemanticStore), then assert dict-
    equality at the case level. Any per-field drift fails the gate.
    """
    cases_dir = Path(__file__).resolve().parents[1] / "eval" / "cases"
    cases = load_cases(cases_dir)
    assert len(cases) == 10, f"expected 10 shipped eval cases, got {len(cases)}"

    runner = CloudPostureEvalRunner()
    real_agent_run = agent_mod.run

    # ---- pass 1: skip-KG path (semantic_store=None) — pre-reroute baseline.
    actuals_off: dict[str, dict[str, Any]] = {}
    for case in cases:
        case_workspace = tmp_path / "off" / case.case_id
        passed, reason, _, _ = await runner.run(case, workspace=case_workspace)
        assert passed, f"case {case.case_id} must pass with semantic_store=None: {reason}"
        report = _read_findings_report(case_workspace, case.case_id)
        actuals_off[case.case_id] = _actuals_for_back_compat(case.case_id, report)

    # ---- pass 2: KG-on path — substitute the in-memory store at the
    # eval-runner -> agent.run() boundary. Production code unchanged.
    # The eval-runner's contract whitelist excludes kg_upsert_* (always
    # has — eval has always run KG-off), so the test-boundary wrapper
    # also expands `permitted_tools` to include the two KG tool names.
    # `contract.model_copy(update=...)` preserves Pydantic immutability;
    # the eval-runner's contract instance is not mutated.
    async def _agent_run_with_store(
        *args: Any,
        **kwargs: Any,
    ) -> FindingsReport:
        original_contract = kwargs.pop("contract")
        kg_enabled_contract = original_contract.model_copy(
            update={
                "permitted_tools": [
                    *original_contract.permitted_tools,
                    "kg_upsert_asset",
                    "kg_upsert_finding",
                ]
            }
        )
        kwargs["semantic_store"] = in_memory_store
        return await real_agent_run(contract=kg_enabled_contract, **kwargs)

    monkeypatch.setattr(agent_mod, "run", _agent_run_with_store)

    actuals_on: dict[str, dict[str, Any]] = {}
    for case in cases:
        case_workspace = tmp_path / "on" / case.case_id
        passed, reason, _, _ = await runner.run(case, workspace=case_workspace)
        assert passed, f"case {case.case_id} must pass with in-memory SemanticStore: {reason}"
        report = _read_findings_report(case_workspace, case.case_id)
        actuals_on[case.case_id] = _actuals_for_back_compat(case.case_id, report)

    # ---- the additive-only assertion: per-case, per-field equality.
    divergences: list[str] = []
    for case_id in actuals_off:
        if actuals_off[case_id] != actuals_on[case_id]:
            for field in actuals_off[case_id]:
                off_val = actuals_off[case_id][field]
                on_val = actuals_on[case_id][field]
                if off_val != on_val:
                    divergences.append(f"  {case_id} / {field}: OFF={off_val!r} ON={on_val!r}")
    assert not divergences, (
        "Eval back-compat gate failed — reroute is NOT additive. "
        "Per-case divergences:\n" + "\n".join(divergences)
    )


# ---------------------------- helpers ---------------------------------------


def _read_findings_report(case_workspace: Path, case_id: str) -> FindingsReport:
    """Re-parse the `findings.json` the agent wrote during the case run."""
    ws = case_workspace / "ws"
    findings_json = ws / "findings.json"
    assert findings_json.exists(), f"case {case_id}: findings.json not written at {findings_json}"
    return FindingsReport.model_validate_json(findings_json.read_text())
