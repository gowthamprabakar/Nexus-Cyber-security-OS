"""``CuriosityEvalRunner`` — the canonical ``EvalRunner`` for D.12.

Per Task 12 of the D.12 v0.1 plan. Mirrors D.13's
``synthesis.eval_runner`` shape: synthesises a mocked
``SemanticStore`` from fixture entity dicts, mocks a
``JetStreamClient`` for ``claims.>`` publish-shape inspection,
instantiates a deterministic stub ``LLMProvider`` from inline
``llm_responses``, runs ``curiosity.agent.run``, then compares
the resulting ``CuriosityReport`` to ``case.expected``.

**Stub LLM provider (Task 14).** Canned LLM outputs live in
``eval/stub_responses/<case_id>/responses.json`` (a JSON array of
strings). The runner loads them per case_id. The legacy inline
``fixture.llm_responses`` key is still honoured as a fallback for
external case authors who haven't migrated yet.

The split lets stub responses evolve independently of the case
fixture: byte-equal eval outputs across reruns are the WI-3
acceptance gate.

**Stub SemanticStore.** Built from fixture's ``regions`` +
``finding_aggregates`` lists. ``list_entities_by_type`` dispatches
on the entity_type to return the right slice; ``upsert_entity``
records the call for the eval to count.

**Stub JetStreamClient.** ``publish`` records each call so the
eval can verify the count + payload shape on ``claims.>``.

Fixture keys (under ``fixture``):

- ``regions: list[dict]`` — aws_account_region entity rows (each
  with external_id + properties).
- ``finding_aggregates: list[dict]`` — finding_aggregate entity rows.
- ``llm_responses: list[str]`` — **legacy** inline canned LLM
  responses. Now superseded by per-case ``stub_responses/<case_id>/
  responses.json``; kept as a fallback for external case authors
  who haven't migrated.
- ``semantic_store: bool`` — when False, the runner passes
  ``semantic_store=None`` to ``curiosity.agent.run`` (default
  True so the runner exercises the persistence path).
- ``js_client: bool`` — when False, passes ``js_client=None``
  (default True so the runner exercises the publish path).

Expected keys (under ``expected``):

- ``total_claims: int``
- ``review_retries: int``
- ``total_gaps_addressed: int``
- ``markdown_contains: list[str]``
- ``markdown_excludes: list[str]`` — load-bearing for the Q6 case.
- ``probe_directives_count: int``
- ``semantic_store_upsert_count: int``
- ``fabric_publish_count: int``

Registered via the ``[project.entry-points."nexus_eval_runners"]``
hook in ``pyproject.toml`` (shipped in Task 1).
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

from charter.contract import BudgetSpec, ExecutionContract
from charter.llm import FakeLLMProvider, LLMProvider, LLMResponse, TokenUsage
from charter.memory.semantic import EntityRow, SemanticStore
from eval_framework.cases import EvalCase
from eval_framework.runner import RunOutcome
from shared.fabric import JetStreamClient

from curiosity import agent as agent_mod
from curiosity.schemas import CuriosityReport


class CuriosityEvalRunner:
    """Reference ``EvalRunner`` for the Curiosity Agent (D.12)."""

    @property
    def agent_name(self) -> str:
        return "curiosity"

    async def run(
        self,
        case: EvalCase,
        *,
        workspace: Path,
        llm_provider: LLMProvider | None = None,
    ) -> RunOutcome:
        workspace.mkdir(parents=True, exist_ok=True)
        contract = _build_contract(case, workspace)
        report, store_mock, js_mock = await _run_case_async(
            case, contract, llm_provider=llm_provider
        )

        passed, failure_reason = _evaluate(
            case, report, contract, store_mock=store_mock, js_mock=js_mock
        )
        actuals: dict[str, Any] = {
            "total_claims": report.total_claims,
            "review_retries": report.review_retries,
            "total_gaps_addressed": report.total_gaps_addressed,
            "semantic_store_upsert_count": _count_hypothesis_upserts(store_mock),
            "fabric_publish_count": _count_publishes(js_mock),
        }
        audit_log_path = Path(contract.workspace) / "audit.jsonl"
        return (
            passed,
            failure_reason,
            actuals,
            audit_log_path if audit_log_path.exists() else None,
        )


# ---------------------------------------------------------------------------
# Run helpers
# ---------------------------------------------------------------------------


async def _run_case_async(
    case: EvalCase,
    contract: ExecutionContract,
    *,
    llm_provider: LLMProvider | None,
) -> tuple[CuriosityReport, AsyncMock | None, AsyncMock | None]:
    fixture = case.fixture
    use_store = bool(fixture.get("semantic_store", True))
    use_js = bool(fixture.get("js_client", True))

    store_mock = _build_semantic_store_mock(fixture) if use_store else None
    js_mock = _build_js_client_mock() if use_js else None
    canned_responses = _resolve_canned_responses(case)
    provider = llm_provider or _build_stub_provider(canned_responses)

    report = await agent_mod.run(
        contract=contract,
        llm_provider=provider,
        semantic_store=cast(SemanticStore, store_mock) if store_mock is not None else None,
        js_client=cast(JetStreamClient, js_mock) if js_mock is not None else None,
    )
    return report, store_mock, js_mock


def _build_contract(case: EvalCase, workspace_root: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="curiosity",
        customer_id="cust_eval",
        task=case.description or case.case_id,
        required_outputs=["hypotheses.md", "probe_directives.json"],
        budget=BudgetSpec(
            llm_calls=10,
            tokens=50_000,
            wall_clock_sec=60.0,
            cloud_api_calls=1,
            mb_written=10,
        ),
        permitted_tools=["read_sibling_state"],
        completion_condition="hypotheses.md AND probe_directives.json exist",
        escalation_rules=[],
        workspace=str(workspace_root / "ws"),
        persistent_root=str(workspace_root / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )


_STUB_RESPONSES_ROOT = Path(__file__).parent.parent.parent / "eval" / "stub_responses"


def _resolve_canned_responses(case: EvalCase) -> list[str]:
    """Locate canned LLM responses for ``case``.

    Precedence:

    1. ``eval/stub_responses/<case_id>/responses.json`` — the Task 14
       layout (canonical for v0.1+).
    2. ``fixture.llm_responses`` — legacy inline fallback for cases
       authored before the Task 14 refactor.
    3. ``[]`` — no canned responses (runner will short-circuit the
       LLM call on empty gaps; useful for clean-run / threshold
       cases).
    """
    case_dir = _STUB_RESPONSES_ROOT / case.case_id
    responses_file = case_dir / "responses.json"
    if responses_file.is_file():
        raw = json.loads(responses_file.read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            raise ValueError(
                f"stub_responses/{case.case_id}/responses.json must be a JSON list, "
                f"got {type(raw).__name__}"
            )
        return [str(r) for r in raw]
    legacy_inline = case.fixture.get("llm_responses")
    if isinstance(legacy_inline, list):
        return [str(r) for r in legacy_inline]
    return []


def _build_stub_provider(responses: Iterable[str]) -> FakeLLMProvider:
    """Build a deterministic stub LLMProvider from canned response texts."""
    canned = [
        LLMResponse(
            text=text,
            stop_reason="end_turn",
            usage=TokenUsage(input_tokens=100, output_tokens=50),
            model_pin="claude-haiku-4-5-20251001",
        )
        for text in responses
    ]
    return FakeLLMProvider(canned)


def _build_semantic_store_mock(fixture: dict[str, Any]) -> AsyncMock:
    """Build an AsyncMock(spec=SemanticStore) that returns the fixture's
    region + finding_aggregate rows for ``list_entities_by_type`` and
    records ``upsert_entity`` calls for the eval to count."""
    region_rows = [
        _entity_row(
            entity_type="aws_account_region",
            external_id=str(r.get("external_id", r.get("region", "us-east-1"))),
            properties=dict(r.get("properties") or r),
            tenant_id="cust_eval",
        )
        for r in (fixture.get("regions") or [])
    ]
    aggregate_rows = [
        _entity_row(
            entity_type="finding_aggregate",
            external_id=str(a.get("external_id", f"agg-{i}")),
            properties=dict(a.get("properties") or a),
            tenant_id="cust_eval",
        )
        for i, a in enumerate(fixture.get("finding_aggregates") or [])
    ]
    rows_by_type: dict[str, list[EntityRow]] = {
        "aws_account_region": region_rows,
        "finding_aggregate": aggregate_rows,
    }
    entity_ids: dict[tuple[str, str], str] = {}

    async def fake_list(*, tenant_id: str, entity_type: str) -> list[EntityRow]:
        del tenant_id
        return list(rows_by_type.get(entity_type, []))

    async def fake_upsert(
        *,
        tenant_id: str,
        entity_type: str,
        external_id: str,
        properties: dict[str, Any] | None = None,
    ) -> str:
        del tenant_id, properties
        key = (entity_type, external_id)
        if key not in entity_ids:
            entity_ids[key] = f"ent_{entity_type}_{len(entity_ids)}"
        return entity_ids[key]

    store = AsyncMock(spec=SemanticStore)
    store.list_entities_by_type.side_effect = fake_list
    store.upsert_entity.side_effect = fake_upsert
    return store


def _entity_row(
    *,
    entity_type: str,
    external_id: str,
    properties: dict[str, Any],
    tenant_id: str,
) -> EntityRow:
    """Drop region/asset_count helpers — entity construction is loose
    because the fixture YAML is operator-authored."""
    # Strip helper keys the fixture might inline that don't belong in
    # the property dict.
    props = {k: v for k, v in properties.items() if k not in {"external_id"}}
    return EntityRow(
        entity_id=f"ent_{external_id}",
        tenant_id=tenant_id,
        entity_type=entity_type,
        external_id=external_id,
        properties=props,
        created_at=datetime(2026, 5, 21, tzinfo=UTC),
    )


def _build_js_client_mock() -> AsyncMock:
    client = AsyncMock(spec=JetStreamClient)
    client.publish = AsyncMock(return_value=MagicMock(stream="claims", seq=1))
    return client


# ---------------------------------------------------------------------------
# Evaluation helpers
# ---------------------------------------------------------------------------


def _evaluate(
    case: EvalCase,
    report: CuriosityReport,
    contract: ExecutionContract,
    *,
    store_mock: AsyncMock | None,
    js_mock: AsyncMock | None,
) -> tuple[bool, str | None]:
    expected = case.expected

    expected_claims = expected.get("total_claims")
    if expected_claims is not None and report.total_claims != int(expected_claims):
        return (
            False,
            f"total_claims expected {expected_claims}, got {report.total_claims}",
        )

    expected_retries = expected.get("review_retries")
    if expected_retries is not None and report.review_retries != int(expected_retries):
        return (
            False,
            f"review_retries expected {expected_retries}, got {report.review_retries}",
        )

    expected_gaps = expected.get("total_gaps_addressed")
    if expected_gaps is not None and report.total_gaps_addressed != int(expected_gaps):
        return (
            False,
            f"total_gaps_addressed expected {expected_gaps}, got {report.total_gaps_addressed}",
        )

    markdown_path = Path(contract.workspace) / "hypotheses.md"
    md_required = expected.get("markdown_contains") or []
    if md_required:
        markdown = markdown_path.read_text(encoding="utf-8")
        for sub in md_required:
            if str(sub) not in markdown:
                return False, f"hypotheses.md missing required substring: {sub!r}"

    md_excluded = expected.get("markdown_excludes") or []
    if md_excluded:
        markdown = markdown_path.read_text(encoding="utf-8")
        for sub in md_excluded:
            if str(sub) in markdown:
                return False, f"hypotheses.md must NOT contain substring: {sub!r}"

    expected_directive_count = expected.get("probe_directives_count")
    if expected_directive_count is not None:
        directives_path = Path(contract.workspace) / "probe_directives.json"
        parsed = json.loads(directives_path.read_text(encoding="utf-8"))
        actual_count = len(parsed.get("directives", []))
        if actual_count != int(expected_directive_count):
            return (
                False,
                f"probe_directives_count expected {expected_directive_count}, got {actual_count}",
            )

    expected_upsert_count = expected.get("semantic_store_upsert_count")
    if expected_upsert_count is not None:
        actual = _count_hypothesis_upserts(store_mock)
        if actual != int(expected_upsert_count):
            return (
                False,
                f"semantic_store_upsert_count expected {expected_upsert_count}, got {actual}",
            )

    expected_publish_count = expected.get("fabric_publish_count")
    if expected_publish_count is not None:
        actual = _count_publishes(js_mock)
        if actual != int(expected_publish_count):
            return (
                False,
                f"fabric_publish_count expected {expected_publish_count}, got {actual}",
            )

    return True, None


def _count_hypothesis_upserts(store_mock: AsyncMock | None) -> int:
    if store_mock is None:
        return 0
    return sum(
        1
        for c in store_mock.upsert_entity.await_args_list
        if c.kwargs.get("entity_type") == "hypothesis"
    )


def _count_publishes(js_mock: AsyncMock | None) -> int:
    if js_mock is None:
        return 0
    return int(js_mock.publish.await_count)


__all__ = ["CuriosityEvalRunner"]
