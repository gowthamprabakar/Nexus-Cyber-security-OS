"""Skill-trigger detection — Hermes Phase 1 primitive (Track C C-2 PR1 hoist).

Hoisted verbatim from ``meta_harness.skill_triggers`` (A.4 v0.2 Task 6) into the
``nexus_runtime`` canary package so the LLM-narration trio (D.13 / D.7 / D.12)
can detect their own skill-creation triggers WITHOUT importing the meta-harness
agent. The detection logic is **pure stdlib** (``hashlib`` + ``collections.abc``),
so it belongs in the ``dependencies = []`` runtime canary; ``meta_harness`` now
re-exports these symbols, keeping its callers and tests byte-identical.

Implements the **3-condition gate** from Q3 of the A.4 v0.2 plan:

1. **Activity count ≥ 5** in the run (Hermes baseline).
2. **Run completed successfully** — no audit entries with action ending in
   ``.failure`` or ``.escalation.raised``.
3. **Pattern is novel** vs the agent's deployed skill library —
   ``tool_sequence_hash`` is not already in the deployed-hash set.

**C2-B extension (LLM-stage counting).** The original gate counted only
``ctx.call_tool`` entries (``payload["tool_name"]``). The LLM-heavy narration
agents do their work through LLM stages, not tool calls, so the tool-only gate
never fired for them. ``detect_skill_trigger`` now takes an **opt-in**
``include_llm_stages`` flag (default ``False`` → byte-identical to the original):
when set, LLM-stage entries (``action`` ending in ``.llm.call_completed``, the
canonical per-agent telemetry from ``providers/cost_tracking``) count as
first-class activity and join the ordered sequence that drives both the
count gate and the novelty hash. With the flag off, every code path is the
original verbatim logic.

**Audit-entry shape.** Each entry is read as a ``Mapping[str, Any]`` — duck-typed
against the F.6 audit chain JSON-Lines format (``action: str``, ``payload: dict``,
``entry_hash: str``). Tool-call entries carry ``payload["tool_name"]``; LLM-stage
entries carry an ``action`` ending in ``.llm.call_completed``.

**Conservative-by-design.** The novelty hash is a deterministic SHA-256 over the
colon-joined activity sequence. It won't extract paraphrases of existing skills or
detect "same shape, different names" — deferred to v0.3 LLM-aided similarity, the
same doctrine the original module declared.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from typing import Any

#: Minimum activity count for the run to qualify as a trigger candidate.
MIN_TOOL_CALL_COUNT = 5

#: Action-name suffixes that disqualify a run from triggering skill creation.
_FAILURE_ACTION_SUFFIXES: tuple[str, ...] = (".failure", ".escalation.raised")

#: Action-name suffix that marks a completed LLM stage (C2-B). The canonical
#: per-agent telemetry action is ``"<agent_id>.llm.call_completed"`` emitted by
#: each LLM agent's ``providers/cost_tracking`` (D.13 / D.7 / D.12).
_LLM_STAGE_ACTION_SUFFIX = ".llm.call_completed"

#: Empty-input hash sentinel — kept stable so tests can assert it without
#: re-hashing.
_EMPTY_SEQUENCE_HASH = hashlib.sha256(b"").hexdigest()


@dataclass(frozen=True)
class SkillTrigger:
    """3-condition gate result — Task 7 ``skill_writer`` consumes this.

    All fields populated from the audit chain entries that justified the
    trigger. ``audit_entry_hashes`` becomes the entry-hash half of the
    deployed ``Skill.provenance`` tuples when Task 7 promotes this trigger
    into a ``SkillCandidate`` (Q2 of the plan).

    When the trigger was detected with ``include_llm_stages=True``,
    ``tool_names`` carries the combined activity sequence (tool names plus an
    ``llm:<action>`` marker per LLM stage, in run order) — the same sequence
    that produced ``tool_sequence_hash``.
    """

    agent_id: str
    run_id: str
    tool_sequence_hash: str
    tool_names: tuple[str, ...]
    audit_entry_hashes: tuple[str, ...]


def compute_tool_sequence_hash(tool_names: Sequence[str]) -> str:
    """Deterministic SHA-256 of the colon-joined tool names.

    Matches the formula in Q3 of the v0.2 plan:
    ``SHA-256(":".join(tool_names_in_order))``. Empty input hashes to the
    SHA-256 of the empty byte string — stable, well-defined.
    """
    if not tool_names:
        return _EMPTY_SEQUENCE_HASH
    payload = ":".join(tool_names).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def extract_tool_calls(audit_entries: Sequence[Mapping[str, Any]]) -> tuple[str, ...]:
    """Pull the in-order sequence of tool names from the audit chain.

    An entry counts as a tool call when its ``payload`` dict carries a
    ``"tool_name"`` key (the v0.2 convention — any agent that wants A.4's
    trigger detector to see its tool calls populates this field). Non-string
    values and missing keys are silently skipped so the function is robust
    against partial / experimental emissions.
    """
    names: list[str] = []
    for entry in audit_entries:
        payload = entry.get("payload")
        if not isinstance(payload, Mapping):
            continue
        tool_name = payload.get("tool_name")
        if isinstance(tool_name, str) and tool_name:
            names.append(tool_name)
    return tuple(names)


def count_llm_stages(audit_entries: Sequence[Mapping[str, Any]]) -> int:
    """Count completed LLM stages in the audit chain (C2-B).

    An entry counts as an LLM stage when its ``action`` ends with
    ``.llm.call_completed`` — the canonical per-agent LLM telemetry action.
    Non-string actions and missing keys are silently skipped.
    """
    count = 0
    for entry in audit_entries:
        action = entry.get("action")
        if isinstance(action, str) and action.endswith(_LLM_STAGE_ACTION_SUFFIX):
            count += 1
    return count


def extract_activity_sequence(
    audit_entries: Sequence[Mapping[str, Any]],
    *,
    include_llm_stages: bool,
) -> tuple[str, ...]:
    """In-order activity sequence: tool calls, plus LLM stages when opted in.

    With ``include_llm_stages=False`` this is exactly ``extract_tool_calls``.
    With it ``True``, each LLM-stage entry contributes an ``"llm:<action>"``
    marker in run order, interleaved with tool names — so a pure-LLM run
    produces a non-empty, novelty-distinguishable sequence.
    """
    if not include_llm_stages:
        return extract_tool_calls(audit_entries)
    sequence: list[str] = []
    for entry in audit_entries:
        payload = entry.get("payload")
        if isinstance(payload, Mapping):
            tool_name = payload.get("tool_name")
            if isinstance(tool_name, str) and tool_name:
                sequence.append(tool_name)
                continue
        action = entry.get("action")
        if isinstance(action, str) and action.endswith(_LLM_STAGE_ACTION_SUFFIX):
            sequence.append(f"llm:{action}")
    return tuple(sequence)


def count_completion_failures(audit_entries: Sequence[Mapping[str, Any]]) -> int:
    """Count audit entries whose ``action`` ends with a failure suffix.

    Failure suffixes are ``.failure`` and ``.escalation.raised`` per Q3
    condition #2. Used as a binary gate (``count == 0`` means clean run) but
    exposed as a count for diagnostic visibility.
    """
    count = 0
    for entry in audit_entries:
        action = entry.get("action")
        if not isinstance(action, str):
            continue
        for suffix in _FAILURE_ACTION_SUFFIXES:
            if action.endswith(suffix):
                count += 1
                break
    return count


def detect_skill_trigger(
    *,
    agent_id: str,
    run_id: str,
    audit_entries: Sequence[Mapping[str, Any]],
    deployed_tool_sequence_hashes: AbstractSet[str],
    include_llm_stages: bool = False,
) -> SkillTrigger | None:
    """Apply Q3's 3-condition gate; return a trigger or ``None``.

    The deployed-hash set is supplied by the caller — Task 9's registry
    (``<workspace>/.nexus/skill-class-registry.json``) is its canonical source
    post-Task 9, but this stays decoupled so it's independently testable.

    ``include_llm_stages`` (C2-B, default ``False``) opts the LLM-narration
    agents into counting their LLM stages as activity. With it off, the logic
    is the original tool-only gate, byte-identical.

    Returns ``None`` (not raises) when any condition fails — the driver treats
    "no trigger" as a routine outcome, not an error.
    """
    activity = extract_activity_sequence(audit_entries, include_llm_stages=include_llm_stages)
    if len(activity) < MIN_TOOL_CALL_COUNT:
        return None
    if count_completion_failures(audit_entries) > 0:
        return None
    tool_sequence_hash = compute_tool_sequence_hash(activity)
    if tool_sequence_hash in deployed_tool_sequence_hashes:
        return None
    audit_entry_hashes: list[str] = []
    for entry in audit_entries:
        entry_hash = entry.get("entry_hash")
        if isinstance(entry_hash, str) and entry_hash:
            audit_entry_hashes.append(entry_hash)
    return SkillTrigger(
        agent_id=agent_id,
        run_id=run_id,
        tool_sequence_hash=tool_sequence_hash,
        tool_names=activity,
        audit_entry_hashes=tuple(audit_entry_hashes),
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
