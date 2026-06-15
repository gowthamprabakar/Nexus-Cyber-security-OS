"""Trigger detection for skill creation — Task 6 of A.4 v0.2.

**Hoisted (Track C C-2 PR1).** The implementation now lives in the
``nexus_runtime`` canary package (``nexus_runtime.hermes.skill_trigger``) so the
LLM-narration trio (D.13 / D.7 / D.12) can detect skill triggers without importing
this meta-harness agent. The logic is pure stdlib; this module re-exports the
canonical symbols verbatim, so every existing ``from meta_harness.skill_triggers
import …`` and its tests stay byte-identical.

See the canonical module for the full 3-condition gate documentation and the C2-B
opt-in ``include_llm_stages`` extension.
"""

from __future__ import annotations

from nexus_runtime.hermes.skill_trigger import (
    MIN_TOOL_CALL_COUNT,
    SkillTrigger,
    compute_tool_sequence_hash,
    count_completion_failures,
    count_llm_stages,
    detect_skill_trigger,
    extract_activity_sequence,
    extract_tool_calls,
)

__all__ = [
    "MIN_TOOL_CALL_COUNT",
    "SkillTrigger",
    "compute_tool_sequence_hash",
    "count_completion_failures",
    "count_llm_stages",
    "detect_skill_trigger",
    "extract_activity_sequence",
    "extract_tool_calls",
]
