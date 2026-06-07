"""LIVE full-pipeline test — v0.2.5 Task 7b.

Exercises the production compilation path the factory wires together, against
real DeepSeek:

    cadence fires (manual) → per-agent lock acquired → DSPy compile (DeepSeek)
    → materialise a SkillCandidate at the legacy canonical shadow path → lock
    released → cadence state advanced.

Gated behind ``NEXUS_LIVE_DSPY=1`` + ``NEXUS_LLM_API_KEY`` (SKIPPED in CI). The
key is read **only** from the env var. The factory is the new 7b surface; the
eval-gate / adjudication / CF #2 / restore paths are covered offline
(``test_compilation_factory.py`` + ``test_task6_adjudication.py``), and Task 5's
``test_dspy_skill_creator_live.py`` covers compile-depth + token cost.

Operator run:

    NEXUS_LIVE_DSPY=1 NEXUS_DSPY_PRODUCTION=1 \
      NEXUS_LLM_API_KEY=<deepseek-key> \
      uv run pytest packages/agents/meta-harness/tests/test_full_pipeline_live.py -v -s
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

_LIVE = os.environ.get("NEXUS_LIVE_DSPY") == "1"
_HAS_KEY = bool(os.environ.get("NEXUS_LLM_API_KEY"))

pytestmark = pytest.mark.skipif(
    not (_LIVE and _HAS_KEY),
    reason="set NEXUS_LIVE_DSPY=1 and NEXUS_LLM_API_KEY=<deepseek-key> to run the live pipeline test",
)

pytest.importorskip("dspy")

from charter.audit import AuditLog  # noqa: E402
from charter.llm import LLMProvider  # noqa: E402
from charter.llm_adapter import LLMConfig, make_provider  # noqa: E402
from meta_harness.compilation_cadence import CompilationCadenceController  # noqa: E402
from meta_harness.compilation_factory import make_dspy_candidate_factory  # noqa: E402
from meta_harness.schemas import SkillCandidate  # noqa: E402
from meta_harness.skill_format import parse_skill_md_content  # noqa: E402
from meta_harness.skill_triggers import SkillTrigger  # noqa: E402

_BASE_URL = os.environ.get("NEXUS_LLM_BASE_URL", "https://api.deepseek.com/v1")
_MODEL_PIN = os.environ.get("NEXUS_LLM_MODEL_PIN", "deepseek-chat")
_AGENT = "investigation"
_SKILL_ID = "iam-privesc/aws_iam_privesc_via_assumed_role"

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

LEGACY body — follow the cross-account AssumeRole chain head-first.
"""


def _provider() -> LLMProvider:
    return make_provider(
        LLMConfig(
            provider="openai-compatible",
            model_pin=_MODEL_PIN,
            base_url=_BASE_URL,
            provider_id="deepseek",
            api_key=os.environ["NEXUS_LLM_API_KEY"],
        )
    )


def _seed_score(workspace: Path) -> None:
    path = workspace / ".nexus" / "deployed-skills" / _AGENT / _SKILL_ID / "effectiveness.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "skill_id": _SKILL_ID,
                "agent_id": _AGENT,
                "tenant_id": "default",
                "global_score": 0.8,
                "confidence": 0.9,
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


def _legacy_candidate(workspace: Path) -> SkillCandidate:
    from datetime import UTC, datetime

    shadow = workspace / ".nexus" / "candidate-skills" / _AGENT / _SKILL_ID / "SKILL.md"
    shadow.parent.mkdir(parents=True, exist_ok=True)
    shadow.write_text(_LEGACY_SKILL_MD, encoding="utf-8")
    return SkillCandidate(
        skill_id=_SKILL_ID,
        skill=parse_skill_md_content(_LEGACY_SKILL_MD),
        shadow_path=str(shadow),
        tool_sequence_hash="hh",
        emitted_at=datetime.now(UTC),
    )


@pytest.mark.asyncio
async def test_live_full_pipeline(tmp_path: Path) -> None:
    """Cadence (manual) → lock → DeepSeek compile → materialise → candidate."""
    _seed_score(tmp_path)  # scored skill so the trainset is non-empty
    legacy = _legacy_candidate(tmp_path)
    trigger = SkillTrigger(
        agent_id=_AGENT,
        run_id="live-run",
        tool_sequence_hash="hh",
        tool_names=("collect_cloudtrail", "trace_assume_role_chain", "score_privesc"),
        audit_entry_hashes=("e1", "e2"),
    )
    audit_log = AuditLog(tmp_path / "audit.jsonl", agent="meta_harness", run_id="live")

    controller = CompilationCadenceController(workspace_root=tmp_path)
    controller.request_manual(_AGENT)  # force the cadence to fire

    factory = make_dspy_candidate_factory(
        _provider(),
        cadence_controller=controller,
        model_pin=_MODEL_PIN,
        workspace_root=tmp_path,
        audit_log=audit_log,
    )

    started = time.monotonic()
    scorecard: Any = SimpleNamespace(agent_id=_AGENT)  # factory only reads .agent_id
    result: Any = await factory(scorecard, legacy, trigger)
    duration = time.monotonic() - started

    assert result is not None, "factory returned None — cadence/lock/compile did not complete"
    assert result.skill_id == _SKILL_ID
    written = Path(legacy.shadow_path).read_text(encoding="utf-8")
    assert written.strip(), "DSPy SKILL.md was not written at the canonical path"
    # Cadence state advanced; lock released.
    assert controller.load_state(_AGENT).last_compile_at is not None
    assert await controller.try_acquire(_AGENT) is True

    print(
        f"\n[LIVE PIPELINE] cadence=manual lock=ok compiled=ok materialized=ok "
        f"skill_id={result.skill_id} duration={duration:.1f}s model={_MODEL_PIN}"
    )
    print(f"[LIVE PIPELINE] DSPy SKILL.md (first 400 chars):\n{written[:400]}")
