"""Tests for the hoisted Hermes skill-trigger primitive (Track C C-2 PR1).

Covers the pure-stdlib detector hoisted from meta_harness plus the C2-B opt-in
``include_llm_stages`` extension. The byte-identical default-path behavior is also
exercised by the meta-harness suite (which re-imports these symbols).
"""

from __future__ import annotations

from typing import Any

from nexus_runtime.hermes import (
    MIN_TOOL_CALL_COUNT,
    SkillTrigger,
    compute_tool_sequence_hash,
    count_completion_failures,
    count_llm_stages,
    detect_skill_trigger,
    extract_activity_sequence,
    extract_tool_calls,
)


def _tool_entry(tool_name: str, *, entry_hash: str = "h") -> dict[str, Any]:
    return {
        "action": "investigation.tool_invoked",
        "payload": {"tool_name": tool_name},
        "entry_hash": entry_hash,
    }


def _llm_entry(*, agent_id: str = "investigation", entry_hash: str = "lh") -> dict[str, Any]:
    return {
        "action": f"{agent_id}.llm.call_completed",
        "payload": {"llm_call_count": 1},
        "entry_hash": entry_hash,
    }


def _tool_run(n: int) -> list[dict[str, Any]]:
    return [_tool_entry(f"t{i}", entry_hash=f"h{i}") for i in range(n)]


# --- pure helpers (byte-identical hoist) -----------------------------------


def test_compute_tool_sequence_hash_empty_is_stable() -> None:
    import hashlib

    assert compute_tool_sequence_hash(()) == hashlib.sha256(b"").hexdigest()


def test_compute_tool_sequence_hash_order_sensitive() -> None:
    assert compute_tool_sequence_hash(["a", "b"]) != compute_tool_sequence_hash(["b", "a"])


def test_extract_tool_calls_skips_non_tool_entries() -> None:
    entries = [_tool_entry("alpha"), _llm_entry(), {"action": "x", "payload": {}}]
    assert extract_tool_calls(entries) == ("alpha",)


def test_count_completion_failures_matches_suffixes() -> None:
    entries = [
        {"action": "x.failure"},
        {"action": "y.escalation.raised"},
        {"action": "z.ok"},
        {"action": 123},  # non-string skipped
    ]
    assert count_completion_failures(entries) == 2


# --- default path: byte-identical to the original tool-only gate -------------


def test_trigger_fires_on_five_distinct_tools() -> None:
    trigger = detect_skill_trigger(
        agent_id="investigation",
        run_id="r1",
        audit_entries=_tool_run(MIN_TOOL_CALL_COUNT),
        deployed_tool_sequence_hashes=set(),
    )
    assert isinstance(trigger, SkillTrigger)
    assert trigger.tool_names == tuple(f"t{i}" for i in range(MIN_TOOL_CALL_COUNT))
    assert trigger.audit_entry_hashes == tuple(f"h{i}" for i in range(MIN_TOOL_CALL_COUNT))


def test_no_trigger_below_threshold() -> None:
    assert (
        detect_skill_trigger(
            agent_id="a",
            run_id="r",
            audit_entries=_tool_run(MIN_TOOL_CALL_COUNT - 1),
            deployed_tool_sequence_hashes=set(),
        )
        is None
    )


def test_no_trigger_on_failure_entry() -> None:
    entries = [*_tool_run(MIN_TOOL_CALL_COUNT), {"action": "investigation.failure"}]
    assert (
        detect_skill_trigger(
            agent_id="a", run_id="r", audit_entries=entries, deployed_tool_sequence_hashes=set()
        )
        is None
    )


def test_no_trigger_when_pattern_already_deployed() -> None:
    entries = _tool_run(MIN_TOOL_CALL_COUNT)
    seen = compute_tool_sequence_hash(tuple(f"t{i}" for i in range(MIN_TOOL_CALL_COUNT)))
    assert (
        detect_skill_trigger(
            agent_id="a",
            run_id="r",
            audit_entries=entries,
            deployed_tool_sequence_hashes={seen},
        )
        is None
    )


def test_llm_entries_do_not_count_by_default() -> None:
    """Default path ignores LLM stages — a pure-LLM run never triggers."""
    entries = [_llm_entry(entry_hash=f"l{i}") for i in range(MIN_TOOL_CALL_COUNT)]
    assert (
        detect_skill_trigger(
            agent_id="a", run_id="r", audit_entries=entries, deployed_tool_sequence_hashes=set()
        )
        is None
    )


# --- C2-B extension: include_llm_stages ------------------------------------


def test_count_llm_stages_matches_suffix() -> None:
    entries = [_llm_entry(), _llm_entry(agent_id="synthesis"), _tool_entry("t")]
    assert count_llm_stages(entries) == 2


def test_extract_activity_sequence_interleaves_when_opted_in() -> None:
    entries = [_tool_entry("alpha"), _llm_entry(), _tool_entry("beta")]
    assert extract_activity_sequence(entries, include_llm_stages=False) == ("alpha", "beta")
    assert extract_activity_sequence(entries, include_llm_stages=True) == (
        "alpha",
        "llm:investigation.llm.call_completed",
        "beta",
    )


def test_pure_llm_run_triggers_when_opted_in() -> None:
    entries = [_llm_entry(entry_hash=f"l{i}") for i in range(MIN_TOOL_CALL_COUNT)]
    trigger = detect_skill_trigger(
        agent_id="synthesis",
        run_id="r2",
        audit_entries=entries,
        deployed_tool_sequence_hashes=set(),
        include_llm_stages=True,
    )
    assert isinstance(trigger, SkillTrigger)
    assert all(name.startswith("llm:") for name in trigger.tool_names)
    assert len(trigger.tool_names) == MIN_TOOL_CALL_COUNT


def test_llm_novelty_hash_distinguishes_run_length() -> None:
    short = [_llm_entry(entry_hash=f"l{i}") for i in range(MIN_TOOL_CALL_COUNT)]
    longer = [_llm_entry(entry_hash=f"m{i}") for i in range(MIN_TOOL_CALL_COUNT + 1)]
    t_short = detect_skill_trigger(
        agent_id="s",
        run_id="a",
        audit_entries=short,
        deployed_tool_sequence_hashes=set(),
        include_llm_stages=True,
    )
    t_long = detect_skill_trigger(
        agent_id="s",
        run_id="b",
        audit_entries=longer,
        deployed_tool_sequence_hashes=set(),
        include_llm_stages=True,
    )
    assert t_short is not None and t_long is not None
    assert t_short.tool_sequence_hash != t_long.tool_sequence_hash
