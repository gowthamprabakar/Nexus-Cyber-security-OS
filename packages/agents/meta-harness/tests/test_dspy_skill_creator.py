"""Tests — `meta_harness.dspy_skill_creator` (v0.2.5 Task 5).

Offline / stubbed: NO real GEPA compilation against a live LLM (the live
round-trip is `test_dspy_skill_creator_live.py`, gated by NEXUS_LIVE_DSPY=1).
Covers the parallel-composer machinery: trainset pre-filtering (Q5-a fix),
CF #2 graceful-degradation, the stub adjudication, and the optional-dependency
gating contract.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from charter.audit import AuditEntry, AuditLog
from charter.llm import FakeLLMProvider, LLMResponse, TokenUsage

dspy = pytest.importorskip("dspy")  # the [dspy] extra (installed in CI via --all-extras)

from meta_harness import dspy_skill_creator as mod  # noqa: E402
from meta_harness.dspy_skill_creator import (  # noqa: E402
    ParallelSkillResult,
    build_compilation_trainset,
    run_parallel_skill_create,
)

_MODULE_SRC = Path(mod.__file__).read_text(encoding="utf-8")


# --------------------------------------------------------------------------- helpers


def _provider() -> FakeLLMProvider:
    return FakeLLMProvider(
        [LLMResponse(text="x", stop_reason="stop", usage=TokenUsage(), provider_id="fake")],
        provider_id="fake",
    )


def _audit(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl", agent="meta_harness", run_id="t5")


def _write_effectiveness_sidecar(
    workspace_root: Path,
    agent_id: str,
    skill_id: str,
    *,
    global_score: float | None,
    confidence: float,
    tenant_id: str = "default",
) -> None:
    path = (
        workspace_root / ".nexus" / "deployed-skills" / agent_id / skill_id / "effectiveness.json"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    axes = (
        {
            "adoption": {"score": 0.9, "confidence": 0.9},
            "outcome": {"score": 0.8, "confidence": 0.9},
            "feedback": {"score": 0.85, "confidence": 0.9},
        }
        if confidence > 0.0
        else None
    )
    payload: dict[str, object] = {
        "skill_id": skill_id,
        "agent_id": agent_id,
        "tenant_id": tenant_id,
        "global_score": global_score,
        "confidence": confidence,
        "by_agent": {},
        "by_tenant": {},
        "axes_breakdown": axes,
        "reason": None if confidence > 0.0 else "insufficient_data",
        "computed_at": "2026-06-05T12:00:00+00:00",
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def _audit_actions(audit_log: AuditLog) -> list[str]:
    if not audit_log.path.is_file():
        return []
    out = []
    for line in audit_log.path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            out.append(AuditEntry.from_json(line).action)
    return out


# --------------------------------------------------------------------------- optional-dep


def test_no_top_level_dspy_import() -> None:
    """Leaf must import cleanly without the [dspy] extra — no module-level dspy."""
    for line in _MODULE_SRC.splitlines():
        module_level = bool(line) and not line[0].isspace()
        s = line.strip()
        flagged = s in ("import dspy", "import gepa") or s.startswith(("import dspy ", "from dspy"))
        assert not (module_level and flagged), f"top-level dspy import: {s!r}"


def test_leaf_module_discipline() -> None:
    """No upward imports into lifecycle/writer/eval_gate/approval."""
    for forbidden in ("skill_lifecycle", "skill_writer", "skill_eval_gate", "skill_approval"):
        assert f"import {forbidden}" not in _MODULE_SRC, f"forbidden import: {forbidden}"
        assert f"meta_harness.{forbidden}" not in _MODULE_SRC, f"forbidden ref: {forbidden}"


# --------------------------------------------------------------------------- trainset pre-filter (Q5-a)


def test_trainset_excludes_unscored_skills(tmp_path: Path) -> None:
    agent_id = "investigation"
    _write_effectiveness_sidecar(tmp_path, agent_id, "cat/scored", global_score=0.8, confidence=0.9)
    # "cat/unscored" → no sidecar; "cat/zeroconf" → confidence 0.0
    _write_effectiveness_sidecar(
        tmp_path, agent_id, "cat/zeroconf", global_score=None, confidence=0.0
    )
    result = build_compilation_trainset(
        [("cat/scored", "trace A"), ("cat/unscored", "trace B"), ("cat/zeroconf", "trace C")],
        agent_id,
        workspace_root=tmp_path,
    )
    assert result.included_skill_ids == ("cat/scored",)
    assert set(result.skipped_skill_ids) == {"cat/unscored", "cat/zeroconf"}
    assert len(result.trainset) == 1


def test_trainset_examples_have_inputs(tmp_path: Path) -> None:
    agent_id = "investigation"
    _write_effectiveness_sidecar(tmp_path, agent_id, "cat/s", global_score=0.7, confidence=0.8)
    result = build_compilation_trainset([("cat/s", "the trace")], agent_id, workspace_root=tmp_path)
    ex = result.trainset[0]
    assert ex.trace == "the trace"
    assert ex.agent_id == agent_id
    assert set(ex.inputs().keys()) == {"trace", "agent_id"}


def test_trainset_empty_when_nothing_scored(tmp_path: Path) -> None:
    result = build_compilation_trainset(
        [("cat/a", "t"), ("cat/b", "t")], "investigation", workspace_root=tmp_path
    )
    assert result.trainset == []
    assert result.included_skill_ids == ()
    assert set(result.skipped_skill_ids) == {"cat/a", "cat/b"}


def test_trainset_tenant_scoping(tmp_path: Path) -> None:
    agent_id = "investigation"
    _write_effectiveness_sidecar(
        tmp_path, agent_id, "cat/s", global_score=0.7, confidence=0.8, tenant_id="acme"
    )
    # default tenant → excluded; acme tenant → included
    assert (
        build_compilation_trainset(
            [("cat/s", "t")], agent_id, workspace_root=tmp_path
        ).included_skill_ids
        == ()
    )
    assert build_compilation_trainset(
        [("cat/s", "t")], agent_id, workspace_root=tmp_path, tenant_id="acme"
    ).included_skill_ids == ("cat/s",)


# --------------------------------------------------------------------------- DSPy module shape


def test_skill_creator_module_signature_shape() -> None:
    module = mod._build_skill_creator_module()
    assert isinstance(module, dspy.Module)
    sig = module.extract.predictors()[0].signature
    assert set(sig.input_fields) == {"trace", "agent_id"}
    assert "skill_md" in sig.output_fields  # (ChainOfThought also adds "reasoning")


# --------------------------------------------------------------------------- parallel path + CF #2


def test_parallel_dspy_failure_falls_back_to_legacy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CF #2 — DSPy path raises → legacy proceeds, error emitted to audit chain."""

    def _boom(*a: Any, **k: Any) -> Any:
        raise RuntimeError("compilation exploded")

    monkeypatch.setattr(mod, "create_compiled_composer", _boom)
    audit = _audit(tmp_path)
    result = run_parallel_skill_create(
        trace="t",
        agent_id="investigation",
        model_pin="deepseek-chat",
        provider=_provider(),
        workspace_root=tmp_path,
        audit_log=audit,
        legacy_skill_md="# Legacy skill",
        trainset=[],
    )
    assert isinstance(result, ParallelSkillResult)
    assert result.dspy_skill_md is None
    assert "compilation exploded" in (result.dspy_error or "")
    assert "meta_harness.skill.effectiveness_error" in _audit_actions(audit)


def test_parallel_dspy_success_records_both(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both candidates captured; winner-selection is the orchestrator's job (Task 6)."""

    class _Compiled:
        def __call__(self, *, trace: str, agent_id: str) -> Any:
            return dspy.Prediction(skill_md="# DSPy skill")

    monkeypatch.setattr(mod, "create_compiled_composer", lambda *a, **k: _Compiled())
    result = run_parallel_skill_create(
        trace="t",
        agent_id="investigation",
        model_pin="deepseek-chat",
        provider=_provider(),
        workspace_root=tmp_path,
        audit_log=_audit(tmp_path),
        legacy_skill_md="# Legacy skill",
        trainset=[object()],
    )
    assert result.dspy_skill_md == "# DSPy skill"
    assert result.legacy_skill_md == "# Legacy skill"
    assert result.dspy_error is None


def test_parallel_empty_dspy_output_is_treated_as_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Compiled:
        def __call__(self, *, trace: str, agent_id: str) -> Any:
            return dspy.Prediction(skill_md="")

    monkeypatch.setattr(mod, "create_compiled_composer", lambda *a, **k: _Compiled())
    result = run_parallel_skill_create(
        trace="t",
        agent_id="investigation",
        model_pin="m",
        provider=_provider(),
        workspace_root=tmp_path,
        audit_log=_audit(tmp_path),
        legacy_skill_md="# Legacy",
        trainset=[object()],
    )
    assert result.dspy_skill_md is None or result.dspy_skill_md == ""
    assert result.dspy_error is not None


# --------------------------------------------------------------------------- adjudication (Task 6)


def test_adjudicate_dspy_wins_when_strictly_higher() -> None:
    winning, meta = mod.adjudicate_pass_rates(0.80, 0.90, "# Legacy", "# DSPy")
    assert winning == "# DSPy"
    assert meta["winner"] == "dspy"
    assert meta["delta"] == pytest.approx(0.10)
    assert meta["legacy_pass_rate"] == 0.80 and meta["dspy_pass_rate"] == 0.90


def test_adjudicate_legacy_wins_when_higher() -> None:
    winning, meta = mod.adjudicate_pass_rates(0.90, 0.70, "# Legacy", "# DSPy")
    assert winning == "# Legacy"
    assert meta["winner"] == "legacy"
    assert meta["delta"] == pytest.approx(-0.20)


def test_adjudicate_tie_goes_to_legacy() -> None:
    """Q3 safety default — DSPy must strictly beat legacy to win."""
    winning, meta = mod.adjudicate_pass_rates(0.80, 0.80, "# Legacy", "# DSPy")
    assert winning == "# Legacy"
    assert meta["winner"] == "legacy"
    assert meta["delta"] == pytest.approx(0.0)


def test_agent_id_propagates_to_dspy_call(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    class _Compiled:
        def __call__(self, *, trace: str, agent_id: str) -> Any:
            seen["trace"] = trace
            seen["agent_id"] = agent_id
            return dspy.Prediction(skill_md="# S")

    monkeypatch.setattr(mod, "create_compiled_composer", lambda *a, **k: _Compiled())
    run_parallel_skill_create(
        trace="the-trace",
        agent_id="data_security",
        model_pin="m",
        provider=_provider(),
        workspace_root=tmp_path,
        audit_log=_audit(tmp_path),
        legacy_skill_md="# L",
        trainset=[object()],
    )
    assert seen == {"trace": "the-trace", "agent_id": "data_security"}
