"""`SynthesisEvalRunner` — the canonical `EvalRunner` for D.13.

Per Task 11 of the D.13 v0.1 plan. Mirrors D.6 / D.8's
``eval_runner.py`` shape: synthesises sibling-workspace
``findings.json`` files from the case fixture, builds an
``ExecutionContract`` rooted at the suite-supplied workspace,
instantiates a deterministic stub ``LLMProvider`` from the
fixture's canned responses, calls ``synthesis.agent.run``, then
compares the resulting ``SynthesisReport`` to ``case.expected``.

**Stub LLM provider (Task 13).** Canned LLM outputs live in
``eval/stub_responses/<case_id>/responses.json`` (a JSON array of
strings). The runner loads them per case_id. The legacy inline
``fixture.llm_responses`` key is still honoured as a fallback for
external case authors who haven't migrated yet.

The split lets stub responses evolve independently of the case
fixture: byte-equal eval outputs across reruns are the WI-3
acceptance gate.

Fixture keys (under ``fixture``):

- ``investigation_findings: list[dict]`` — D.7 OCSF finding dicts.
- ``compliance_findings: list[dict]`` — D.6 OCSF finding dicts.
- ``cloud_posture_findings: list[dict]`` — F.3 OCSF finding dicts.
- ``llm_responses: list[str]`` — **legacy** inline canned LLM
  responses. Now superseded by per-case ``stub_responses/<case_id>/
  responses.json``; kept as a fallback path for external case
  authors who haven't migrated.
- ``omit_workspace: list[str]`` — names of sibling-workspace
  paths to leave None (rather than synthesise from empty list).

Expected keys (under ``expected``):

- ``section_count: int``
- ``review_retries: int``
- ``cited_finding_count: int``
- ``narrative_md_contains: list[str]``
- ``executive_summary_md_contains: list[str]``
- ``narrative_md_excludes: list[str]`` — load-bearing for the Q6
  case (verifies the leaked substring is NOT in the rendered MD).

Registered via the ``[project.entry-points."nexus_eval_runners"]``
hook in ``pyproject.toml`` (shipped in Task 1).
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from charter.contract import BudgetSpec, ExecutionContract
from charter.llm import FakeLLMProvider, LLMProvider, LLMResponse, TokenUsage
from eval_framework.cases import EvalCase
from eval_framework.runner import RunOutcome

from synthesis import agent as agent_mod
from synthesis.schemas import SynthesisReport


class SynthesisEvalRunner:
    """Reference ``EvalRunner`` for the Synthesis Agent (D.13)."""

    @property
    def agent_name(self) -> str:
        return "synthesis"

    async def run(
        self,
        case: EvalCase,
        *,
        workspace: Path,
        llm_provider: LLMProvider | None = None,
    ) -> RunOutcome:
        workspace.mkdir(parents=True, exist_ok=True)
        contract = _build_contract(case, workspace)
        report = await _run_case_async(case, contract, llm_provider=llm_provider)

        passed, failure_reason = _evaluate(case, report, contract)
        actuals: dict[str, Any] = {
            "section_count": report.total_sections,
            "review_retries": report.review_retries,
            "cited_finding_count": report.total_cited_findings,
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
) -> SynthesisReport:
    fixture = case.fixture
    ws_root = Path(contract.workspace).parent
    ws_root.mkdir(parents=True, exist_ok=True)

    omit = set(fixture.get("omit_workspace") or [])
    inv_ws = _maybe_write_workspace(
        ws_root / "_inv", fixture.get("investigation_findings"), omit, name="investigation"
    )
    cmp_ws = _maybe_write_workspace(
        ws_root / "_cmp", fixture.get("compliance_findings"), omit, name="compliance"
    )
    cp_ws = _maybe_write_workspace(
        ws_root / "_cp", fixture.get("cloud_posture_findings"), omit, name="cloud_posture"
    )

    canned_responses = _resolve_canned_responses(case)
    provider = llm_provider or _build_stub_provider(canned_responses)

    return await agent_mod.run(
        contract=contract,
        llm_provider=provider,
        investigation_workspace=inv_ws,
        compliance_workspace=cmp_ws,
        cloud_posture_workspace=cp_ws,
    )


def _build_contract(case: EvalCase, workspace_root: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="synthesis",
        customer_id="cust_eval",
        task=case.description or case.case_id,
        required_outputs=["narrative.md", "executive_summary.md"],
        budget=BudgetSpec(
            llm_calls=20,
            tokens=50_000,
            wall_clock_sec=60.0,
            cloud_api_calls=1,
            mb_written=10,
        ),
        permitted_tools=["read_sibling_workspaces"],
        completion_condition="narrative.md AND executive_summary.md exist",
        escalation_rules=[],
        workspace=str(workspace_root / "ws"),
        persistent_root=str(workspace_root / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )


def _maybe_write_workspace(
    path: Path,
    findings: list[dict[str, Any]] | None,
    omit: set[str],
    *,
    name: str,
) -> Path | None:
    """Write a sibling workspace findings.json; return None to skip."""
    if name in omit:
        return None
    if not findings:
        return None
    path.mkdir(parents=True, exist_ok=True)
    (path / "findings.json").write_text(
        json.dumps({"findings": findings}, default=str),
        encoding="utf-8",
    )
    return path


_STUB_RESPONSES_ROOT = Path(__file__).parent.parent.parent / "eval" / "stub_responses"


def _resolve_canned_responses(case: EvalCase) -> list[str]:
    """Locate canned LLM responses for ``case``.

    Precedence:

    1. ``eval/stub_responses/<case_id>/responses.json`` — the Task 13
       layout (canonical for v0.1+).
    2. ``fixture.llm_responses`` — legacy inline fallback for cases
       authored before the Task 13 refactor.
    3. ``[]`` — no canned responses (runner will fail on the first
       LLM call; useful for negative tests).
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
    """Build a deterministic stub LLMProvider from canned response texts.

    Each response is wrapped in an ``LLMResponse`` with fixed token
    accounting (100/50 in/out) so reruns are byte-equal.
    """
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


# ---------------------------------------------------------------------------
# Evaluation helpers
# ---------------------------------------------------------------------------


def _evaluate(
    case: EvalCase, report: SynthesisReport, contract: ExecutionContract
) -> tuple[bool, str | None]:
    expected = case.expected

    expected_section_count = expected.get("section_count")
    if expected_section_count is not None and report.total_sections != int(expected_section_count):
        return (
            False,
            f"section_count expected {expected_section_count}, got {report.total_sections}",
        )

    expected_retries = expected.get("review_retries")
    if expected_retries is not None and report.review_retries != int(expected_retries):
        return (
            False,
            f"review_retries expected {expected_retries}, got {report.review_retries}",
        )

    expected_cited = expected.get("cited_finding_count")
    if expected_cited is not None and report.total_cited_findings != int(expected_cited):
        return (
            False,
            f"cited_finding_count expected {expected_cited}, got {report.total_cited_findings}",
        )

    narrative_path = Path(contract.workspace) / "narrative.md"
    summary_path = Path(contract.workspace) / "executive_summary.md"

    md_required = expected.get("narrative_md_contains") or []
    if md_required:
        narrative_md = narrative_path.read_text(encoding="utf-8")
        for sub in md_required:
            if str(sub) not in narrative_md:
                return False, f"narrative.md missing required substring: {sub!r}"

    md_excluded = expected.get("narrative_md_excludes") or []
    if md_excluded:
        narrative_md = narrative_path.read_text(encoding="utf-8")
        for sub in md_excluded:
            if str(sub) in narrative_md:
                return False, f"narrative.md must NOT contain substring: {sub!r}"

    summary_required = expected.get("executive_summary_md_contains") or []
    if summary_required:
        summary_md = summary_path.read_text(encoding="utf-8")
        for sub in summary_required:
            if str(sub) not in summary_md:
                return False, f"executive_summary.md missing required substring: {sub!r}"

    return True, None


__all__ = ["SynthesisEvalRunner"]
