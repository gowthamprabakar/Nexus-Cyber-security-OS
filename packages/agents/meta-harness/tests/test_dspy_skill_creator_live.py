"""LIVE DSPy compilation test — v0.2.5 Task 5 (empirical #3 + #4).

Gated behind ``NEXUS_LIVE_DSPY=1`` (matches the NEXUS_LIVE_POSTGRES / NEXUS_LIVE_NATS
pattern) — SKIPPED in CI and in any environment without the env flag + an API key.
The API key is read **only** from the ``NEXUS_LLM_API_KEY`` env var; it is never
stored in this file.

Operator run (DeepSeek V4 Pro), per the Task 5 plan:

    NEXUS_LIVE_DSPY=1 \
      NEXUS_LLM_API_KEY=<deepseek-key> \
      uv run pytest packages/agents/meta-harness/tests/test_dspy_skill_creator_live.py -v -s

Verifies:
- #3  a DSPy SKILL_CREATE program compiles end-to-end against DeepSeek and
      produces valid ``skill_md`` for a sample trace.
- #4  reports token usage for ONE bounded compilation cycle (cost visibility).
      NOTE: this test bounds the budget via ``max_metric_calls`` to keep the
      run cheap; the production default is ``auto="medium"`` (Q2), whose cost is
      higher — extrapolate accordingly / re-run with auto="medium" for the true
      cadence cost.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

_LIVE = os.environ.get("NEXUS_LIVE_DSPY") == "1"
_HAS_KEY = bool(os.environ.get("NEXUS_LLM_API_KEY"))

pytestmark = pytest.mark.skipif(
    not (_LIVE and _HAS_KEY),
    reason="set NEXUS_LIVE_DSPY=1 and NEXUS_LLM_API_KEY=<deepseek-key> to run the live DSPy test",
)

dspy = pytest.importorskip("dspy")

from charter.audit import AuditLog  # noqa: E402
from charter.llm import LLMProvider  # noqa: E402
from charter.llm_adapter import LLMConfig, make_provider  # noqa: E402
from meta_harness.dspy_skill_creator import (  # noqa: E402
    build_compilation_trainset,
    create_compiled_composer,
)

_DEEPSEEK_BASE_URL = os.environ.get("NEXUS_LLM_BASE_URL", "https://api.deepseek.com/v1")
_MODEL_PIN = os.environ.get("NEXUS_LLM_MODEL_PIN", "deepseek-chat")


def _deepseek_provider() -> LLMProvider:
    return make_provider(
        LLMConfig(
            provider="openai-compatible",
            model_pin=_MODEL_PIN,
            base_url=_DEEPSEEK_BASE_URL,
            provider_id="deepseek",
            api_key=os.environ["NEXUS_LLM_API_KEY"],
        )
    )


def _seed_score(workspace: Path, agent_id: str, skill_id: str) -> None:
    path = workspace / ".nexus" / "deployed-skills" / agent_id / skill_id / "effectiveness.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "skill_id": skill_id,
                "agent_id": agent_id,
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
                "computed_at": "2026-06-05T12:00:00+00:00",
            }
        ),
        encoding="utf-8",
    )


def test_live_deepseek_compile_round_trip(tmp_path: Path) -> None:
    agent_id = "investigation"
    skill_id = "iam-privesc/role-chain"
    _seed_score(tmp_path, agent_id, skill_id)

    sample_trace = (
        "Agent investigated a cross-account AssumeRole chain: "
        "sts:AssumeRole from acct A -> role R1 -> role R2 with admin policy. "
        "Flagged as privilege escalation. Outcome: confirmed finding."
    )
    build = build_compilation_trainset(
        [(skill_id, sample_trace)], agent_id, workspace_root=tmp_path
    )
    assert build.included_skill_ids == (skill_id,), "pre-filter should include the scored skill"

    audit = AuditLog(tmp_path / "audit.jsonl", agent="meta_harness", run_id="live")
    provider = _deepseek_provider()

    compiled = create_compiled_composer(
        provider,
        agent_id=agent_id,
        model_pin=_MODEL_PIN,
        workspace_root=tmp_path,
        audit_log=audit,
        trainset=build.trainset,
        seed=7,
        auto=None,
        max_metric_calls=10,  # bounded for cost; production default is auto="medium"
    )

    prediction = compiled(trace=sample_trace, agent_id=agent_id)
    skill_md = prediction.skill_md
    assert isinstance(skill_md, str) and skill_md.strip(), "compiled program produced no skill_md"

    # #4 cost visibility — token usage from the DSPy LM history.
    lm = compiled.extract.lm or dspy.settings.lm
    history = getattr(lm, "history", []) or []
    total_tokens = sum(
        (h.get("usage") or {}).get("total_tokens", 0) for h in history if isinstance(h, dict)
    )
    print(f"\n[LIVE DSPy] calls={len(history)} total_tokens={total_tokens} model={_MODEL_PIN}")
    print(f"[LIVE DSPy] sample skill_md (first 400 chars):\n{skill_md[:400]}")
