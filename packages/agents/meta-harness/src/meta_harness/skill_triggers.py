"""Trigger detection for skill creation — Task 6 of A.4 v0.2.

Implements the **3-condition gate** from Q3 of the v0.2 plan
(``docs/superpowers/plans/2026-05-22-a-4-meta-harness-v0-2.md``):

1. **Tool-call count ≥ 5** in the run (Hermes baseline).
2. **Run completed successfully** — no audit entries with action ending
   in ``.failure`` or ``.escalation.raised``.
3. **Pattern is novel** vs the agent's deployed skill library —
   ``tool_sequence_hash`` is not already in the deployed-hash set.

When all three hold, returns a ``SkillTrigger`` that Task 7
(``skill_writer.py``) consumes to construct a ``SkillCandidate`` via
LLM composition. When any condition fails, returns ``None``.

**Audit-entry shape.** The module reads each entry as a ``Mapping[str,
Any]`` — duck-typed against the F.6 audit chain JSON-Lines format
(``action: str``, ``payload: dict``, ``entry_hash: str``). Callers
(Task 13 driver) hand off entries already loaded via the audit-agent
``audit_jsonl_read`` reader or ``AuditStore.query``. Module-internal
filtering uses ``payload["tool_name"]`` to identify tool-call entries —
the convention any agent that wants to feed A.4's trigger detector
follows.

**Conservative-by-design.** The novelty hash matches by deterministic
SHA-256 over the colon-joined tool names. Won't extract paraphrases of
existing skills (acceptable — duplicates worse than missed near-
duplicates in v0.2). Won't detect "same shape, different tool names"
— deferred to v0.3 LLM-aided similarity (N3 Curator wave).

Decoupled from Task 9 ``skill_registry``: the caller passes the
deployed-hash set in directly, so this module is fully testable in
isolation without a registry implementation.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from typing import Any

#: Minimum tool-call count for the run to qualify as a trigger candidate.
MIN_TOOL_CALL_COUNT = 5

#: Action-name suffixes that disqualify a run from triggering skill creation.
_FAILURE_ACTION_SUFFIXES: tuple[str, ...] = (".failure", ".escalation.raised")

#: Empty-input hash sentinel — kept stable so tests can assert it without
#: re-hashing.
_EMPTY_SEQUENCE_HASH = hashlib.sha256(b"").hexdigest()


@dataclass(frozen=True)
class SkillTrigger:
    """3-condition gate result — Task 7 ``skill_writer`` consumes this.

    All fields populated from the audit chain entries that justified
    the trigger. ``audit_entry_hashes`` becomes the entry-hash half of
    the deployed ``Skill.provenance`` tuples when Task 7 promotes this
    trigger into a ``SkillCandidate`` (Q2 of the plan).
    """

    agent_id: str
    run_id: str
    tool_sequence_hash: str
    tool_names: tuple[str, ...]
    audit_entry_hashes: tuple[str, ...]


def compute_tool_sequence_hash(tool_names: Sequence[str]) -> str:
    """Deterministic SHA-256 of the colon-joined tool names.

    Matches the formula in Q3 of the v0.2 plan:
    ``SHA-256(":".join(tool_names_in_order))``. Empty input hashes to
    the SHA-256 of the empty byte string — stable, well-defined.
    """
    if not tool_names:
        return _EMPTY_SEQUENCE_HASH
    payload = ":".join(tool_names).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def extract_tool_calls(audit_entries: Sequence[Mapping[str, Any]]) -> tuple[str, ...]:
    """Pull the in-order sequence of tool names from the audit chain.

    An entry counts as a tool call when its ``payload`` dict carries a
    ``"tool_name"`` key (the v0.2 convention — any agent that wants
    A.4's trigger detector to see its tool calls populates this field).
    Non-string values and missing keys are silently skipped so the
    function is robust against partial / experimental emissions.
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


def count_completion_failures(audit_entries: Sequence[Mapping[str, Any]]) -> int:
    """Count audit entries whose ``action`` ends with a failure suffix.

    Failure suffixes are ``.failure`` and ``.escalation.raised`` per
    Q3 condition #2. Used as a binary gate (``count == 0`` means clean
    run) but exposed as a count for diagnostic visibility.
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
) -> SkillTrigger | None:
    """Apply Q3's 3-condition gate; return a trigger or ``None``.

    The deployed-hash set is supplied by the caller — Task 9's registry
    (``<workspace>/.nexus/skill-class-registry.json``) is its
    canonical source post-Task 9, but Task 6 stays decoupled so it's
    independently testable.

    Returns ``None`` (not raises) when any condition fails — the driver
    treats "no trigger" as a routine outcome, not an error.
    """
    tool_names = extract_tool_calls(audit_entries)
    if len(tool_names) < MIN_TOOL_CALL_COUNT:
        return None
    if count_completion_failures(audit_entries) > 0:
        return None
    tool_sequence_hash = compute_tool_sequence_hash(tool_names)
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
        tool_names=tool_names,
        audit_entry_hashes=tuple(audit_entry_hashes),
    )


__all__ = [
    "MIN_TOOL_CALL_COUNT",
    "SkillTrigger",
    "compute_tool_sequence_hash",
    "count_completion_failures",
    "detect_skill_trigger",
    "extract_tool_calls",
]
