"""Tests — Task 9 CF #2 retrofit to skill_lifecycle ``_safely_*`` helpers.

Before Task 9 both helpers swallowed failures into a bare ``_LOG.warning`` (no
audit-chain event). The retrofit makes every degradation path emit
``meta_harness.skill.effectiveness_error`` (distinguished by ``stage``), matching
Task 7b's compilation_factory pattern — while still logging + returning ``None``.
Underlying operations are monkeypatched; no real LLM / eval-gate runs.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from charter.audit import AuditEntry, AuditLog
from meta_harness import skill_lifecycle as lc
from meta_harness.schemas import EvalGateResult
from meta_harness.skill_eval_gate import SkillEvalGateError

_ANY: Any = object()


def _audit(tmp: Path) -> AuditLog:
    return AuditLog(tmp / "audit.jsonl", agent="meta_harness", run_id="t9")


def _entries(audit: AuditLog) -> list[dict[str, Any]]:
    if not audit.path.is_file():
        return []
    out: list[dict[str, Any]] = []
    for line in audit.path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            e = AuditEntry.from_json(line)
            out.append({"action": e.action, "payload": e.payload})
    return out


def _error_entries(audit: AuditLog) -> list[dict[str, Any]]:
    return [e for e in _entries(audit) if e["action"] == "meta_harness.skill.effectiveness_error"]


def _eval_result() -> EvalGateResult:
    return EvalGateResult(
        skill_id="iam/x",
        target_agent="investigation",
        baseline_pass_rate=0.5,
        candidate_pass_rate=0.8,
        per_case_regressions=(),
        passed=True,
        evaluated_at=datetime(2026, 6, 7, 12, 0, 0, tzinfo=UTC),
    )


# --------------------------------------------------------------- _write_candidate_safely


@pytest.mark.asyncio
async def test_write_candidate_happy_no_audit_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def _ok(**_k: Any) -> Any:
        return SimpleNamespace(skill_id="iam/x")

    monkeypatch.setattr(lc, "write_skill_candidate", _ok)
    audit = _audit(tmp_path)
    result = await lc._write_candidate_safely(
        trigger=SimpleNamespace(agent_id="investigation"),
        workspace_root=tmp_path,
        llm_provider=_ANY,
        audit_log=audit,
    )
    assert result is not None
    assert _error_entries(audit) == []  # success → no degradation event


@pytest.mark.asyncio
async def test_write_candidate_cf2_emits_and_returns_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def _boom(**_k: Any) -> Any:
        raise RuntimeError("compose exploded")

    monkeypatch.setattr(lc, "write_skill_candidate", _boom)
    audit = _audit(tmp_path)
    result = await lc._write_candidate_safely(
        trigger=SimpleNamespace(agent_id="investigation"),
        workspace_root=tmp_path,
        llm_provider=_ANY,
        audit_log=audit,
    )
    assert result is None  # CF #2: degrade, don't raise
    errors = _error_entries(audit)
    assert len(errors) == 1
    payload = errors[0]["payload"]
    assert payload["agent_id"] == "investigation"
    assert payload["stage"] == "write_skill_candidate"
    assert payload["fallback"] == "legacy_path"
    assert "compose exploded" in payload["exception_message"]


# --------------------------------------------------------------- _run_eval_gate_safely


def _patch_gate(monkeypatch: pytest.MonkeyPatch, *, gate: Any) -> None:
    monkeypatch.setattr(lc, "load_cases", lambda _root: ["case"])
    if isinstance(gate, Exception):

        async def _raise(**_k: Any) -> Any:
            raise gate

        monkeypatch.setattr(lc, "run_skill_eval_gate", _raise)
    else:

        async def _ret(**_k: Any) -> Any:
            return gate

        monkeypatch.setattr(lc, "run_skill_eval_gate", _ret)


async def _run_gate(tmp_path: Path, audit: AuditLog) -> Any:
    scorecard: Any = SimpleNamespace(agent_id="investigation")  # helper only reads .agent_id
    return await lc._run_eval_gate_safely(
        candidate=SimpleNamespace(skill_id="iam/x"),
        scorecard=scorecard,
        workspace_root=tmp_path,
        cases_resolver=lambda _a: tmp_path,
        eval_runner_loader=lambda _a: _ANY,
        llm_provider=_ANY,
        audit_log=audit,
    )


@pytest.mark.asyncio
async def test_eval_gate_happy_no_audit_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_gate(monkeypatch, gate=_eval_result())
    audit = _audit(tmp_path)
    result = await _run_gate(tmp_path, audit)
    assert result is not None
    assert _error_entries(audit) == []


@pytest.mark.asyncio
async def test_eval_gate_unevaluable_emits_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_gate(monkeypatch, gate=SkillEvalGateError("no cases"))
    audit = _audit(tmp_path)
    result = await _run_gate(tmp_path, audit)
    assert result is None
    errors = _error_entries(audit)
    assert len(errors) == 1
    assert errors[0]["payload"]["stage"] == "eval_gate_unevaluable"
    assert errors[0]["payload"]["agent_id"] == "investigation"


@pytest.mark.asyncio
async def test_eval_gate_generic_error_emits_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_gate(monkeypatch, gate=RuntimeError("runner blew up"))
    audit = _audit(tmp_path)
    result = await _run_gate(tmp_path, audit)
    assert result is None
    errors = _error_entries(audit)
    assert len(errors) == 1
    assert errors[0]["payload"]["stage"] == "eval_gate"
    assert "runner blew up" in errors[0]["payload"]["exception_message"]


# --------------------------------------------------------------- emit helper shape


def test_emit_cf2_error_payload_shape(tmp_path: Path) -> None:
    audit = _audit(tmp_path)
    lc._emit_cf2_error(
        audit, agent_id="cloud_posture", stage="demo", exc=ValueError("x"), tenant_id="acme"
    )
    errors = _error_entries(audit)
    assert len(errors) == 1
    p = errors[0]["payload"]
    assert p["agent_id"] == "cloud_posture"
    assert p["tenant_id"] == "acme"
    assert p["stage"] == "demo"
    assert p["error_type"] == "demo_failed"
    assert "stack_trace" in p
    # Reuses the existing constant (Q7 — no new audit actions).
    assert errors[0]["action"] == "meta_harness.skill.effectiveness_error"
    # sanity: payload is JSON-serialisable
    json.dumps(p)
