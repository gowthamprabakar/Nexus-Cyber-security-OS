"""Tests — `meta_harness.skill_triggers` (Task 6).

13 tests covering the 3-condition gate from Q3 of the v0.2 plan:

1.  ``compute_tool_sequence_hash`` on empty input returns the SHA-256
    of the empty byte string (stable sentinel).
2.  ``compute_tool_sequence_hash`` is deterministic — same input,
    same output across calls.
3.  ``compute_tool_sequence_hash`` is order-sensitive (different
    orderings produce different hashes).
4.  ``extract_tool_calls`` returns ``()`` for an empty audit chain.
5.  ``extract_tool_calls`` extracts tool names in audit-chain order.
6.  ``extract_tool_calls`` skips entries that lack
    ``payload["tool_name"]`` or whose payload is malformed.
7.  ``count_completion_failures`` returns 0 for a clean run.
8.  ``count_completion_failures`` counts ``.failure`` suffix actions.
9.  ``count_completion_failures`` counts ``.escalation.raised`` actions.
10. ``detect_skill_trigger`` returns ``None`` when tool-call count is
    below the Q3 threshold.
11. ``detect_skill_trigger`` returns ``None`` when failure entries
    are present in the audit chain.
12. ``detect_skill_trigger`` returns ``None`` when the computed hash
    is already in the deployed-hash set (novelty fail).
13. ``detect_skill_trigger`` returns a populated ``SkillTrigger``
    when all three conditions hold.
"""

from __future__ import annotations

import hashlib
from typing import Any

from meta_harness.skill_triggers import (
    MIN_TOOL_CALL_COUNT,
    SkillTrigger,
    compute_tool_sequence_hash,
    count_completion_failures,
    detect_skill_trigger,
    extract_tool_calls,
)


def _tool_entry(tool_name: str, *, entry_hash: str = "h") -> dict[str, Any]:
    return {
        "action": "investigation.tool_invoked",
        "payload": {"tool_name": tool_name},
        "entry_hash": entry_hash,
    }


def _five_clean_tool_entries() -> list[dict[str, Any]]:
    return [
        _tool_entry(name, entry_hash=f"h{i}")
        for i, name in enumerate(
            ("memory_neighbors_walk", "ocsf_lookup", "iam_query", "s3_get", "audit_query")
        )
    ]


# ---------------------------- compute_tool_sequence_hash ----------------------------


def test_compute_tool_sequence_hash_empty_input_is_empty_byte_string_sha256() -> None:
    assert compute_tool_sequence_hash([]) == hashlib.sha256(b"").hexdigest()


def test_compute_tool_sequence_hash_deterministic() -> None:
    h1 = compute_tool_sequence_hash(["a", "b", "c"])
    h2 = compute_tool_sequence_hash(["a", "b", "c"])
    assert h1 == h2
    assert h1 == hashlib.sha256(b"a:b:c").hexdigest()


def test_compute_tool_sequence_hash_order_sensitive() -> None:
    h_forward = compute_tool_sequence_hash(["a", "b", "c"])
    h_reverse = compute_tool_sequence_hash(["c", "b", "a"])
    assert h_forward != h_reverse


# ---------------------------- extract_tool_calls ----------------------------


def test_extract_tool_calls_empty_audit() -> None:
    assert extract_tool_calls([]) == ()


def test_extract_tool_calls_preserves_order() -> None:
    entries = [_tool_entry("alpha"), _tool_entry("beta"), _tool_entry("gamma")]
    assert extract_tool_calls(entries) == ("alpha", "beta", "gamma")


def test_extract_tool_calls_skips_non_tool_entries() -> None:
    entries: list[dict[str, Any]] = [
        {"action": "investigation.heartbeat", "payload": {}},
        _tool_entry("alpha"),
        {"action": "investigation.weird", "payload": "not-a-mapping"},
        _tool_entry("beta"),
        {"action": "investigation.tool_invoked", "payload": {"tool_name": 42}},  # non-str
        {"action": "investigation.tool_invoked", "payload": {"tool_name": ""}},  # empty str
        _tool_entry("gamma"),
    ]
    assert extract_tool_calls(entries) == ("alpha", "beta", "gamma")


# ---------------------------- count_completion_failures ----------------------------


def test_count_completion_failures_clean_run_returns_zero() -> None:
    entries = _five_clean_tool_entries()
    assert count_completion_failures(entries) == 0


def test_count_completion_failures_counts_failure_suffix() -> None:
    entries: list[dict[str, Any]] = [
        {"action": "investigation.tool_invoked.failure", "payload": {}},
        {"action": "investigation.heartbeat", "payload": {}},
        {"action": "investigation.tool_invoked.failure", "payload": {}},
    ]
    assert count_completion_failures(entries) == 2


def test_count_completion_failures_counts_escalation_raised_suffix() -> None:
    entries: list[dict[str, Any]] = [
        {"action": "supervisor.escalation.raised", "payload": {}},
        {"action": "supervisor.heartbeat", "payload": {}},
    ]
    assert count_completion_failures(entries) == 1


# ---------------------------- detect_skill_trigger ----------------------------


def test_detect_skill_trigger_too_few_tool_calls_returns_none() -> None:
    entries = [_tool_entry(f"t_{i}") for i in range(MIN_TOOL_CALL_COUNT - 1)]
    trigger = detect_skill_trigger(
        agent_id="investigation",
        run_id="r1",
        audit_entries=entries,
        deployed_tool_sequence_hashes=frozenset(),
    )
    assert trigger is None


def test_detect_skill_trigger_failure_present_returns_none() -> None:
    entries: list[dict[str, Any]] = [
        *_five_clean_tool_entries(),
        {"action": "investigation.tool_invoked.failure", "payload": {}},
    ]
    trigger = detect_skill_trigger(
        agent_id="investigation",
        run_id="r1",
        audit_entries=entries,
        deployed_tool_sequence_hashes=frozenset(),
    )
    assert trigger is None


def test_detect_skill_trigger_hash_already_deployed_returns_none() -> None:
    entries = _five_clean_tool_entries()
    expected_hash = compute_tool_sequence_hash([e["payload"]["tool_name"] for e in entries])
    trigger = detect_skill_trigger(
        agent_id="investigation",
        run_id="r1",
        audit_entries=entries,
        deployed_tool_sequence_hashes=frozenset({expected_hash}),
    )
    assert trigger is None


def test_detect_skill_trigger_all_three_conditions_pass_returns_trigger() -> None:
    entries = _five_clean_tool_entries()
    trigger = detect_skill_trigger(
        agent_id="investigation",
        run_id="r_42",
        audit_entries=entries,
        deployed_tool_sequence_hashes=frozenset({"unrelated-hash"}),
    )
    assert isinstance(trigger, SkillTrigger)
    assert trigger.agent_id == "investigation"
    assert trigger.run_id == "r_42"
    assert trigger.tool_names == tuple(e["payload"]["tool_name"] for e in entries)
    assert trigger.tool_sequence_hash == compute_tool_sequence_hash(trigger.tool_names)
    assert trigger.audit_entry_hashes == tuple(e["entry_hash"] for e in entries)
