"""``AISPMEvalRunner`` — the canonical ``EvalRunner`` for the D.11 AI-SPM agent (PR6).

Brings D.11 to fleet eval parity (mirrors the D.10 SSPM / appsec runners). Each case
fixture drives the cloud connectors (+ optional Garak probe) with **structured** data; the
runner builds deterministic fakes and injects them into ``agent.run`` via the connector
seams, then reads ``findings.json`` and compares to ``case.expected``.

Fixture keys (under ``fixture``):
- ``aws: {account_id, sagemaker_endpoints: [...], sagemaker_notebooks: [...],
  bedrock_logging_enabled, bedrock_guardrails}``
- ``azure: {subscription_id, accounts: [...]}``
- ``gcp: {project_id, endpoints: [...]}``
- ``probe: {target, provider, garak_entries: [...]}`` — drives the gated Garak path via an
  injected fake runner (no live probe).

Comparison shape (under ``expected``): ``finding_count: int`` + ``by_type: {discriminator: int}``.

Registered via ``pyproject.toml`` ``[project.entry-points."nexus_eval_runners"]``.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from charter.contract import BudgetSpec, ExecutionContract
from charter.llm import LLMProvider
from eval_framework.cases import EvalCase
from eval_framework.runner import RunOutcome

from aispm import agent as agent_mod

_PERMITTED = ["discover_aws_ai", "discover_azure_ai", "discover_gcp_ai", "probe_garak"]


class _FakeAws:
    def __init__(self, fx: dict[str, Any]) -> None:
        self._fx = fx

    def sagemaker_endpoints(self) -> list[dict[str, Any]]:
        return list(self._fx.get("sagemaker_endpoints", []))

    def sagemaker_notebooks(self) -> list[dict[str, Any]]:
        return list(self._fx.get("sagemaker_notebooks", []))

    def bedrock_logging_enabled(self) -> bool | None:
        return self._fx.get("bedrock_logging_enabled")

    def bedrock_guardrail_count(self) -> int:
        return int(self._fx.get("bedrock_guardrails", 0))


class _FakeAzure:
    def __init__(self, fx: dict[str, Any]) -> None:
        self._fx = fx

    def openai_accounts(self) -> list[dict[str, Any]]:
        return list(self._fx.get("accounts", []))


class _FakeGcp:
    def __init__(self, fx: dict[str, Any]) -> None:
        self._fx = fx

    def vertex_endpoints(self) -> list[dict[str, Any]]:
        return list(self._fx.get("endpoints", []))


class _FakeGarak:
    def __init__(self, entries: list[dict[str, Any]]) -> None:
        self._entries = entries

    async def probe(self, *, target: str) -> list[dict[str, Any]]:
        return self._entries


class AISPMEvalRunner:
    """Reference ``EvalRunner`` for the AI-SPM agent."""

    @property
    def agent_name(self) -> str:
        return "aispm"

    async def run(
        self,
        case: EvalCase,
        *,
        workspace: Path,
        llm_provider: LLMProvider | None = None,
    ) -> RunOutcome:
        del llm_provider  # AI-SPM discovery is deterministic; no LLM in the loop
        workspace.mkdir(parents=True, exist_ok=True)
        contract = _build_contract(case, workspace)
        fx = case.fixture

        kwargs: dict[str, Any] = {}
        if "aws" in fx:
            kwargs["aws_account_id"] = str(fx["aws"].get("account_id", "acct"))
            kwargs["aws_reader"] = _FakeAws(fx["aws"])
        if "azure" in fx:
            kwargs["azure_subscription_id"] = str(fx["azure"].get("subscription_id", "sub"))
            kwargs["azure_reader"] = _FakeAzure(fx["azure"])
        if "gcp" in fx:
            kwargs["gcp_project_id"] = str(fx["gcp"].get("project_id", "proj"))
            kwargs["gcp_reader"] = _FakeGcp(fx["gcp"])
        if "probe" in fx:
            kwargs["probe_target"] = str(fx["probe"]["target"])
            kwargs["probe_provider"] = str(fx["probe"].get("provider", "bedrock"))
            kwargs["garak_runner"] = _FakeGarak(list(fx["probe"].get("garak_entries", [])))

        await agent_mod.run(contract, **kwargs)

        ws = Path(contract.workspace)
        findings = _read_findings(ws)
        by_type = Counter(f["finding_info"]["types"][0] for f in findings)
        actuals: dict[str, Any] = {"finding_count": len(findings), "by_type": dict(by_type)}
        passed, reason = _evaluate(case, len(findings), by_type)
        audit = ws / "audit.jsonl"
        return passed, reason, actuals, audit if audit.exists() else None


def _read_findings(workspace: Path) -> list[dict[str, Any]]:
    path = workspace / "findings.json"
    if not path.is_file():
        return []
    doc = json.loads(path.read_text(encoding="utf-8"))
    out: list[dict[str, Any]] = doc.get("findings", [])
    return out


def _build_contract(case: EvalCase, workspace_root: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="aispm",
        customer_id="cust_eval",
        task=case.description or case.case_id,
        required_outputs=["findings.json", "summary.md"],
        budget=BudgetSpec(
            llm_calls=1, tokens=1, wall_clock_sec=60.0, cloud_api_calls=200, mb_written=10
        ),
        permitted_tools=_PERMITTED,
        completion_condition="findings.json AND summary.md exist",
        escalation_rules=[],
        workspace=str(workspace_root / "ws"),
        persistent_root=str(workspace_root / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )


def _evaluate(case: EvalCase, finding_count: int, by_type: Counter[str]) -> tuple[bool, str | None]:
    expected_count = case.expected.get("finding_count")
    if expected_count is not None and finding_count != int(expected_count):
        return False, f"finding_count expected {expected_count}, got {finding_count}"
    for disc, want in (case.expected.get("by_type") or {}).items():
        actual = by_type.get(str(disc), 0)
        if actual != int(want):
            return False, f"by_type '{disc}' expected {want}, got {actual}"
    return True, None


__all__ = ["AISPMEvalRunner"]
