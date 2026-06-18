"""Tests — Task 7b DSPy candidate factory (offline; DSPy compile mocked).

Covers the factory's control flow against the real cadence controller:
cadence-no / lock-unavailable / empty-trainset / compile-failure (CF #2) /
success (+ canonical-path materialisation, cadence-state update, lock release),
plus the default-OFF feature flag. No real DSPy/LLM — ``create_compiled_composer``
is monkeypatched; the materialisation uses the real ``skill_format`` round-trip.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from charter.audit import AuditEntry, AuditLog
from meta_harness import compilation_factory as cf
from meta_harness.compilation_cadence import CompilationCadenceController
from meta_harness.schemas import SkillCandidate
from meta_harness.skill_format import parse_skill_md_content
from meta_harness.skill_triggers import SkillTrigger

_AGENT = "investigation"
_SKILL_ID = "iam-privesc/aws_iam_privesc_via_assumed_role"
_NOW = datetime(2026, 6, 7, 12, 0, 0, tzinfo=UTC)
_PROVIDER: Any = object()  # provider is unused (create_compiled_composer mocked / flag-gated)

_LEGACY_SKILL_MD = """---
name: aws_iam_privesc_via_assumed_role
description: Detect IAM privilege escalation via cross-account role chain.
version: 0.1.0
platforms:
  - nexus
target_agent: investigation
category: iam-privesc
created_by: meta_harness@v0.2.0
provenance:
  - [audit/r_eval.jsonl, deadbeefcafebabe]
eval_gate_status: not_run
deployment_status: candidate
---

LEGACY body — follow the chain head-first.
"""

_DSPY_SKILL_MD = """---
name: aws_iam_privesc_via_assumed_role
description: DSPY-OPTIMIZED detection of cross-account role-chain privesc.
version: 0.1.0
platforms:
  - nexus
target_agent: investigation
category: iam-privesc
created_by: meta_harness@v0.2.0
provenance:
  - [audit/r_eval.jsonl, deadbeefcafebabe]
eval_gate_status: not_run
deployment_status: candidate
---

DSPY-OPTIMIZED body — structured numbered steps.
"""


def _audit(tmp: Path) -> AuditLog:
    return AuditLog(tmp / "audit.jsonl", agent="meta_harness", run_id="t7b")


def _trigger() -> SkillTrigger:
    return SkillTrigger(
        agent_id=_AGENT,
        run_id="run-1",
        tool_sequence_hash="hh",
        tool_names=("collect", "analyze"),
        audit_entry_hashes=("e1",),
    )


def _legacy_candidate(tmp: Path) -> SkillCandidate:
    shadow = tmp / ".nexus" / "candidate-skills" / _AGENT / _SKILL_ID / "SKILL.md"
    return SkillCandidate(
        skill_id=_SKILL_ID,
        skill=parse_skill_md_content(_LEGACY_SKILL_MD),
        shadow_path=str(shadow),
        tool_sequence_hash="hh",
        emitted_at=_NOW,
    )


def _seed_effectiveness(tmp: Path, *, global_score: float = 0.7, confidence: float = 0.9) -> None:
    path = tmp / ".nexus" / "deployed-skills" / _AGENT / _SKILL_ID / "effectiveness.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "skill_id": _SKILL_ID,
                "agent_id": _AGENT,
                "tenant_id": "default",
                "global_score": global_score,
                "confidence": confidence,
                "by_agent": {},
                "by_tenant": {},
                "axes_breakdown": {
                    "adoption": {"score": 0.9, "confidence": 0.9},
                    "outcome": {"score": 0.8, "confidence": 0.9},
                    "feedback": {"score": 0.85, "confidence": 0.9},
                },
                "reason": None,
                "computed_at": "2026-06-01T12:00:00+00:00",
            }
        ),
        encoding="utf-8",
    )


class _FakeCompiled:
    def __call__(self, *, trace: str, agent_id: str) -> Any:
        return SimpleNamespace(skill_md=_DSPY_SKILL_MD)


def _factory(tmp: Path, controller: CompilationCadenceController) -> Any:
    return cf.make_dspy_candidate_factory(
        _PROVIDER,
        cadence_controller=controller,
        model_pin="deepseek-chat",
        workspace_root=tmp,
        audit_log=_audit(tmp),
    )


def _audit_actions(tmp: Path) -> list[str]:
    p = tmp / "audit.jsonl"
    if not p.is_file():
        return []
    return [
        AuditEntry.from_json(line).action for line in p.read_text().splitlines() if line.strip()
    ]


# --------------------------------------------------------------------------- no-go paths


@pytest.mark.asyncio
async def test_returns_none_when_cadence_says_no(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    called = {"compile": False}
    monkeypatch.setattr(
        cf, "create_compiled_composer", lambda *a, **k: called.__setitem__("compile", True)
    )
    _seed_effectiveness(tmp_path, global_score=0.9)  # healthy effectiveness (> 0.4)
    controller = CompilationCadenceController(workspace_root=tmp_path)
    controller.record_compilation(_AGENT)  # recent compile (real now) → cron not due, 0 new skills
    factory = _factory(tmp_path, controller)
    result = await factory(
        SimpleNamespace(agent_id=_AGENT), _legacy_candidate(tmp_path), _trigger()
    )
    assert result is None  # no trigger fires
    assert called["compile"] is False


@pytest.mark.asyncio
async def test_returns_none_when_lock_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    called = {"compile": False}
    monkeypatch.setattr(
        cf, "create_compiled_composer", lambda *a, **k: called.__setitem__("compile", True)
    )
    controller = CompilationCadenceController(workspace_root=tmp_path)  # never compiled → cron due
    assert await controller.try_acquire(_AGENT) is True  # pre-hold the lock
    factory = _factory(tmp_path, controller)
    result = await factory(
        SimpleNamespace(agent_id=_AGENT), _legacy_candidate(tmp_path), _trigger()
    )
    assert result is None
    assert called["compile"] is False


@pytest.mark.asyncio
async def test_returns_none_on_empty_trainset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    called = {"compile": False}
    monkeypatch.setattr(
        cf, "create_compiled_composer", lambda *a, **k: called.__setitem__("compile", True)
    )
    # No effectiveness seeded → the (skill_id, trace) example is filtered → empty trainset.
    controller = CompilationCadenceController(workspace_root=tmp_path)  # cron due
    factory = _factory(tmp_path, controller)
    result = await factory(
        SimpleNamespace(agent_id=_AGENT), _legacy_candidate(tmp_path), _trigger()
    )
    assert result is None
    assert called["compile"] is False
    assert await controller.try_acquire(_AGENT) is True  # lock released


# --------------------------------------------------------------------------- CF #2 failure


@pytest.mark.asyncio
async def test_compile_failure_falls_back_to_legacy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _boom(*a: Any, **k: Any) -> Any:
        raise RuntimeError("compile exploded")

    monkeypatch.setattr(cf, "create_compiled_composer", _boom)
    _seed_effectiveness(tmp_path)
    controller = CompilationCadenceController(workspace_root=tmp_path)
    factory = _factory(tmp_path, controller)
    result = await factory(
        SimpleNamespace(agent_id=_AGENT), _legacy_candidate(tmp_path), _trigger()
    )
    assert result is None
    assert "meta_harness.skill.effectiveness_error" in _audit_actions(tmp_path)
    assert await controller.try_acquire(_AGENT) is True  # lock released in finally


# --------------------------------------------------------------------------- success


@pytest.mark.asyncio
async def test_success_produces_candidate_at_canonical_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cf, "create_compiled_composer", lambda *a, **k: _FakeCompiled())
    _seed_effectiveness(tmp_path)
    controller = CompilationCadenceController(workspace_root=tmp_path)
    legacy = _legacy_candidate(tmp_path)
    factory = _factory(tmp_path, controller)

    result = await factory(SimpleNamespace(agent_id=_AGENT), legacy, _trigger())

    assert result is not None
    assert result.skill_id == _SKILL_ID  # pinned to legacy identity
    # DSPy content written at the legacy canonical shadow path (clean overwrite).
    written = Path(legacy.shadow_path).read_text(encoding="utf-8")
    assert "DSPY-OPTIMIZED" in written
    # Cadence state advanced (record_compilation).
    assert controller.load_state(_AGENT).last_compile_at is not None
    # Lock released.
    assert await controller.try_acquire(_AGENT) is True


# --------------------------------------------------------------------------- feature flag


def test_default_factory_disabled_when_flag_unset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(cf.ENV_PRODUCTION_FLAG, raising=False)
    factory = cf.make_default_dspy_factory(
        _PROVIDER, model_pin="deepseek-chat", workspace_root=tmp_path, audit_log=_audit(tmp_path)
    )
    assert factory is None  # default-OFF → skill_lifecycle receives None (legacy-only)


def test_default_factory_enabled_when_flag_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(cf.ENV_PRODUCTION_FLAG, "1")
    factory = cf.make_default_dspy_factory(
        _PROVIDER, model_pin="deepseek-chat", workspace_root=tmp_path, audit_log=_audit(tmp_path)
    )
    assert factory is not None and callable(factory)


# ----------------------------------------------- Track C C-1: SemanticStore storage


class _FakeStore:
    """Minimal SemanticStore double capturing upsert_entity calls."""

    def __init__(self) -> None:
        self.upserts: list[dict[str, Any]] = []

    async def upsert_entity(
        self,
        *,
        tenant_id: str,
        entity_type: str,
        external_id: str,
        properties: dict[str, Any] | None = None,
    ) -> str:
        self.upserts.append(
            {
                "tenant_id": tenant_id,
                "entity_type": entity_type,
                "external_id": external_id,
                "properties": properties,
            }
        )
        return external_id

    async def list_entities_by_type(self, *, tenant_id: str, entity_type: str) -> list[Any]:
        # T2 (Phase 4a-2): the SkillTraceStore reads history through this; no persisted
        # traces in this double → empty history (the current trigger's example carries the run).
        return []


@pytest.mark.asyncio
async def test_success_records_compilation_to_semantic_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """C-1 / Q-C1-2: a successful compilation upserts a dspy_compilation entity."""
    monkeypatch.setattr(cf, "create_compiled_composer", lambda *a, **k: _FakeCompiled())
    _seed_effectiveness(tmp_path)
    controller = CompilationCadenceController(workspace_root=tmp_path)
    legacy = _legacy_candidate(tmp_path)
    store = _FakeStore()
    factory = cf.make_dspy_candidate_factory(
        _PROVIDER,
        cadence_controller=controller,
        model_pin="deepseek-chat",
        workspace_root=tmp_path,
        audit_log=_audit(tmp_path),
        semantic_store=store,
    )

    result = await factory(SimpleNamespace(agent_id=_AGENT), legacy, _trigger())

    assert result is not None
    assert len(store.upserts) == 1
    rec = store.upserts[0]
    assert rec["entity_type"] == "dspy_compilation"
    assert rec["external_id"] == f"{_AGENT}:{_SKILL_ID}"
    assert rec["properties"]["skill_id"] == _SKILL_ID
    assert rec["properties"]["model_pin"] == "deepseek-chat"


@pytest.mark.asyncio
async def test_success_without_store_still_produces_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """C-1: semantic_store=None → no recording, candidate path unaffected."""
    monkeypatch.setattr(cf, "create_compiled_composer", lambda *a, **k: _FakeCompiled())
    _seed_effectiveness(tmp_path)
    controller = CompilationCadenceController(workspace_root=tmp_path)
    legacy = _legacy_candidate(tmp_path)
    factory = _factory(tmp_path, controller)  # no semantic_store

    result = await factory(SimpleNamespace(agent_id=_AGENT), legacy, _trigger())

    assert result is not None


def test_default_factory_accepts_semantic_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """C-1: make_default_dspy_factory threads semantic_store when flag is set."""
    monkeypatch.setenv(cf.ENV_PRODUCTION_FLAG, "1")
    factory = cf.make_default_dspy_factory(
        _PROVIDER,
        model_pin="deepseek-chat",
        workspace_root=tmp_path,
        audit_log=_audit(tmp_path),
        semantic_store=_FakeStore(),
    )
    assert factory is not None and callable(factory)
