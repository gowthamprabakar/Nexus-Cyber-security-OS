"""Hermes Phase 1 primitives (Track C C-2 PR1 hoist).

Pure-stdlib skill-trigger detection + a dependency-injected skill-candidate
persistence helper, hoisted into the ``nexus_runtime`` canary so the LLM-narration
trio (D.13 / D.7 / D.12) can detect and propose skills without importing the
meta-harness agent. ``meta_harness`` re-exports ``skill_trigger`` to keep its
callers byte-identical.
"""

from nexus_runtime.hermes.candidate_store import (
    SKILL_CANDIDATE_ENTITY_TYPE,
    upsert_skill_candidate,
)
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
    "SKILL_CANDIDATE_ENTITY_TYPE",
    "SkillTrigger",
    "compute_tool_sequence_hash",
    "count_completion_failures",
    "count_llm_stages",
    "detect_skill_trigger",
    "extract_activity_sequence",
    "extract_tool_calls",
    "upsert_skill_candidate",
]
