"""Regression: A.1 rollback MUST route through ctx.call_tool — never a direct import.

The v0.2 Quality Audit (PR #622, 2026-06-13) found that `validator.rollback` invoked
`apply_patch` via a raw import (validator.py:202), bypassing the charter proxy on the
remediation rollback path: the rollback `kubectl patch` (a real cluster mutation) executed with
no cloud_api_calls budget charge, no tool_call audit entry, and no permitted_tools check — on the
one agent that mutates customer infrastructure. PR-A1 routed rollback through `ctx.call_tool`
(same surface as Stage-5 EXECUTE). These tests prevent recurrence.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from charter import BudgetExhausted, Charter, ToolNotPermitted
from charter.contract import BudgetSpec, ExecutionContract
from remediation.action_classes._common import wrap_container_patch
from remediation.agent import build_registry
from remediation.schemas import RemediationActionType, RemediationArtifact
from remediation.tools import kubectl_executor as kc_mod
from remediation.validator import rollback

NOW = datetime(2026, 6, 13, 12, 0, 0, tzinfo=UTC)


def _artifact() -> RemediationArtifact:
    leaf = {"securityContext": {"runAsNonRoot": True}}
    from k8s_posture.tools.manifests import ManifestFinding

    finding = ManifestFinding(
        rule_id="run-as-root",
        rule_title="Run As Root",
        severity="high",
        workload_kind="Deployment",
        workload_name="frontend",
        namespace="production",
        container_name="nginx",
        manifest_path="cluster:///production/Deployment/frontend",
        detected_at=NOW,
    )
    return RemediationArtifact(
        action_type=RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        api_version="apps/v1",
        kind="Deployment",
        namespace="production",
        name="frontend",
        patch_strategy="strategic",
        patch_body=wrap_container_patch(finding, leaf),
        inverse_patch_body=wrap_container_patch(
            finding, {"securityContext": {"runAsNonRoot": None}}
        ),
        source_finding_uid="run-as-root",
        correlation_id="corr-test",
    )


def _ctx(
    tmp_path: Path, *, permitted: tuple[str, ...] = ("apply_patch",), cloud: int = 20
) -> Charter:
    contract = ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="remediation",
        customer_id="cust_test",
        task="rollback proxy regression",
        required_outputs=["x"],
        budget=BudgetSpec(
            llm_calls=1, tokens=1, wall_clock_sec=60.0, cloud_api_calls=cloud, mb_written=10
        ),
        permitted_tools=list(permitted),
        completion_condition="x",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "persistent"),
        created_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )
    return Charter(contract, tools=build_registry())


def _patch_kubectl(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_run(cmd: Sequence[str]) -> tuple[int, str, str]:
        return 0, "{}", ""

    monkeypatch.setattr(kc_mod, "_run", fake_run)
    monkeypatch.setattr(kc_mod, "_kubectl_binary", lambda: "/usr/local/bin/kubectl")


@pytest.mark.asyncio
async def test_rollback_emits_tool_call_audit_entry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Rollback dispatched through ctx.call_tool emits a charter tool_call audit entry for
    apply_patch — proof the rollback traverses the proxy (was absent before PR-A1)."""
    _patch_kubectl(monkeypatch)
    with _ctx(tmp_path) as ctx:
        result = await rollback(ctx, _artifact())
    assert result.succeeded
    audit = Path(tmp_path / "ws" / "audit.jsonl")
    entries = [json.loads(line) for line in audit.read_text().splitlines() if line.strip()]
    tool_calls = [e for e in entries if e.get("action") == "tool_call"]
    assert any(e["payload"]["tool"] == "apply_patch" for e in tool_calls)


@pytest.mark.asyncio
async def test_rollback_charges_cloud_budget(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Rollback now spends cloud_api_calls budget (was uncharged before PR-A1): with a 1-call
    budget the first rollback succeeds (charges the call) and the second exhausts it."""
    _patch_kubectl(monkeypatch)
    with _ctx(tmp_path, cloud=1) as ctx:
        first = await rollback(ctx, _artifact())  # charges cloud_api_calls -> 0 remaining
        assert first.succeeded
        with pytest.raises(BudgetExhausted) as exc:
            await rollback(ctx, _artifact())  # no budget left -> exhausted
    assert exc.value.dimension == "cloud_api_calls"


@pytest.mark.asyncio
async def test_rollback_respects_permitted_tools(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """If apply_patch is not in permitted_tools, rollback raises ToolNotPermitted (the same
    whitelist gate Stage-5 EXECUTE enforces)."""
    _patch_kubectl(monkeypatch)
    with (
        _ctx(tmp_path, permitted=("read_findings",)) as ctx,
        pytest.raises(ToolNotPermitted) as exc,
    ):
        await rollback(ctx, _artifact())
    assert exc.value.tool == "apply_patch"
