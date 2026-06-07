"""Tests — Task 6 orchestrator adjudication (`skill_lifecycle._adjudicate_dspy_candidate`).

The pure pass-rate comparator (`adjudicate_pass_rates`) is covered in
`test_dspy_skill_creator.py`. Here we test the orchestrator helper that
eval-gates the DSPy candidate and picks the winner vs the legacy result:
DSPy-wins / legacy-wins / tie / CF #2 (DSPy eval-gate failure), plus the **R1
winner-restore** added in Task 7b (the factory overwrote the legacy SKILL.md at
the canonical path, so legacy-proceeds paths must restore it). The eval-gate +
`write_skill_md` are monkeypatched — no real suite run, no real file IO.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from charter.audit import AuditEntry, AuditLog
from meta_harness import skill_lifecycle as lc
from meta_harness.schemas import EvalGateResult

# Eval-gate deps are monkeypatched away; these stubs are never invoked.
_ANY: Any = object()


def _audit(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "lc-audit.jsonl", agent="meta_harness", run_id="t6")


def _eval_result(
    pass_rate: float, *, skill_id: str = "iam/x", agent: str = "investigation"
) -> EvalGateResult:
    return EvalGateResult(
        skill_id=skill_id,
        target_agent=agent,
        baseline_pass_rate=0.5,
        candidate_pass_rate=pass_rate,
        per_case_regressions=(),
        passed=True,
        evaluated_at=datetime(2026, 6, 7, 12, 0, 0, tzinfo=UTC),
    )


def _scorecard() -> Any:
    # The helper only reads ``.agent_id`` off the scorecard.
    return SimpleNamespace(agent_id="investigation")


def _dspy_candidate(skill_id: str = "iam/dspy") -> Any:
    # The helper only reads ``.skill_id`` off the DSPy candidate.
    return SimpleNamespace(skill_id=skill_id)


def _legacy_candidate(skill_id: str = "iam/legacy") -> Any:
    # The helper reads ``.skill_id`` and (for restore) ``.skill`` + ``.shadow_path``.
    return SimpleNamespace(
        skill_id=skill_id,
        skill=SimpleNamespace(name="legacy"),
        shadow_path="shadow/legacy/SKILL.md",
    )


def _patch_gate_and_restore(
    monkeypatch: pytest.MonkeyPatch, gate_result: EvalGateResult | None
) -> list[Any]:
    """Stub the eval-gate result + record any legacy-restore writes."""

    async def _fake_gate(**_kwargs: Any) -> EvalGateResult | None:
        return gate_result

    restored: list[Any] = []
    monkeypatch.setattr(lc, "_run_eval_gate_safely", _fake_gate)
    monkeypatch.setattr(lc, "write_skill_md", lambda skill, path: restored.append((skill, path)))
    return restored


def _audit_actions(audit_log: AuditLog) -> list[str]:
    if not audit_log.path.is_file():
        return []
    return [
        AuditEntry.from_json(line).action
        for line in audit_log.path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


async def _adjudicate(tmp_path: Path, legacy_pr: float, audit: AuditLog) -> Any:
    return await lc._adjudicate_dspy_candidate(
        legacy_eval_result=_eval_result(legacy_pr, skill_id="iam/legacy"),
        legacy_candidate=_legacy_candidate(),
        dspy_candidate=_dspy_candidate(),
        scorecard=_scorecard(),
        workspace_root=tmp_path,
        cases_resolver=_ANY,
        eval_runner_loader=_ANY,
        llm_provider=_ANY,
        audit_log=audit,
    )


@pytest.mark.asyncio
async def test_dspy_wins_keeps_dspy_skill_md(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    restored = _patch_gate_and_restore(monkeypatch, _eval_result(0.90, skill_id="iam/dspy"))
    audit = _audit(tmp_path)
    won = await _adjudicate(tmp_path, 0.80, audit)
    assert won is not None
    winning_candidate, winning_eval = won
    assert winning_candidate.skill_id == "iam/dspy"
    assert winning_eval.candidate_pass_rate == 0.90
    assert "meta_harness.skill.eval_gate_completed" in _audit_actions(audit)
    assert restored == []  # DSPy won → no legacy restore; DSPy SKILL.md stays


@pytest.mark.asyncio
async def test_legacy_wins_restores_legacy_skill_md(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    restored = _patch_gate_and_restore(monkeypatch, _eval_result(0.60, skill_id="iam/dspy"))
    won = await _adjudicate(tmp_path, 0.80, _audit(tmp_path))
    assert won is None  # legacy wins
    assert len(restored) == 1  # legacy SKILL.md restored at canonical path
    assert restored[0][1] == Path("shadow/legacy/SKILL.md")


@pytest.mark.asyncio
async def test_tie_restores_legacy_skill_md(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    restored = _patch_gate_and_restore(monkeypatch, _eval_result(0.80, skill_id="iam/dspy"))
    won = await _adjudicate(tmp_path, 0.80, _audit(tmp_path))
    assert won is None  # tie → legacy (Q3 safety default)
    assert len(restored) == 1  # legacy restored


@pytest.mark.asyncio
async def test_dspy_eval_gate_failure_restores_legacy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CF #2 — DSPy eval-gate returns None → restore legacy, no crash, legacy proceeds."""
    restored = _patch_gate_and_restore(monkeypatch, None)
    audit = _audit(tmp_path)
    won = await _adjudicate(tmp_path, 0.80, audit)
    assert won is None
    assert len(restored) == 1  # legacy restored even on eval-gate failure
    # No eval_gate_completed for DSPy (the gate never produced a result).
    assert "meta_harness.skill.eval_gate_completed" not in _audit_actions(audit)
