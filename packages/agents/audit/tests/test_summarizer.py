"""Tests for `audit.summarizer.render_markdown` (F.6 Task 9).

Production contract — the report layout (top-down):

    # Audit summary — tenant <id>, <since> → <until>

    ## Chain integrity
    <broken_at if any, else "Chain valid (<N> entries checked).">

    ## Volume by action
    <sorted desc table>

    ## Volume by agent
    <sorted desc table>

    ## Tamper alerts pinned
    <chain-break event details if any>

    ## Per-action sections
    ### action: <name>
    <event list>

The tamper-alert pin mirrors D.3's "Critical runtime alerts" pinning —
the operator must not have to scroll past per-action sections to see
the chain break. Empty inputs degrade gracefully (no events → "No
audit events in this window.").
"""

from __future__ import annotations

from datetime import UTC, datetime

from audit.schemas import AuditEvent, AuditQueryResult, ChainIntegrityReport
from audit.summarizer import render_markdown

_TENANT_A = "01HV0T0000000000000000TENA"
_HEX_GENESIS = "0" * 64
_HEX_A = "a" * 64
_HEX_B = "b" * 64
_HEX_C = "c" * 64


def _event(
    *,
    action: str,
    agent_id: str = "cloud_posture",
    entry_hash: str = _HEX_A,
    previous_hash: str = _HEX_GENESIS,
    correlation_id: str = "01J7M3X9Z1K8RPVQNH2T8DBHFZ",
) -> AuditEvent:
    return AuditEvent(
        tenant_id=_TENANT_A,
        correlation_id=correlation_id,
        agent_id=agent_id,
        action=action,
        payload={"k": "v"},
        previous_hash=previous_hash,
        entry_hash=entry_hash,
        emitted_at=datetime(2026, 5, 1, 12, 0, 0, tzinfo=UTC),
        source="jsonl:/var/log/audit.jsonl",
    )


_SINCE = datetime(2026, 5, 1, tzinfo=UTC)
_UNTIL = datetime(2026, 5, 31, tzinfo=UTC)


# ---------------------------- header & framing -------------------------


def test_render_markdown_starts_with_h1_header() -> None:
    result = AuditQueryResult(total=0, events=())
    report = ChainIntegrityReport(valid=True, entries_checked=0)
    output = render_markdown(
        tenant_id=_TENANT_A, since=_SINCE, until=_UNTIL, result=result, chain=report
    )
    assert output.startswith("# Audit summary"), output[:200]


def test_render_markdown_includes_tenant_and_window_in_header() -> None:
    result = AuditQueryResult(total=0, events=())
    report = ChainIntegrityReport(valid=True, entries_checked=0)
    output = render_markdown(
        tenant_id=_TENANT_A, since=_SINCE, until=_UNTIL, result=result, chain=report
    )
    assert _TENANT_A in output
    assert "2026-05-01" in output
    assert "2026-05-31" in output


# ---------------------------- chain integrity section ------------------


def test_render_markdown_chain_valid_section_states_count() -> None:
    result = AuditQueryResult(total=0, events=())
    report = ChainIntegrityReport(valid=True, entries_checked=42)
    output = render_markdown(
        tenant_id=_TENANT_A, since=_SINCE, until=_UNTIL, result=result, chain=report
    )
    assert "## Chain integrity" in output
    assert "42" in output  # count surfaced
    assert "valid" in output.lower()


def test_render_markdown_chain_break_section_pins_breaking_event() -> None:
    """A broken chain must be visible without scrolling past per-action sections."""
    result = AuditQueryResult(
        total=2,
        events=(
            _event(action="episode_appended"),
            _event(action="entity_upserted", entry_hash=_HEX_B),
        ),
    )
    chain = ChainIntegrityReport(
        valid=False,
        entries_checked=1,
        broken_at_correlation_id="01J7N4Y0A2L9SQWRJK3U9ECIGA",
        broken_at_action="entity_upserted",
    )
    output = render_markdown(
        tenant_id=_TENANT_A, since=_SINCE, until=_UNTIL, result=result, chain=chain
    )
    # Tamper alerts section header appears BEFORE per-action sections.
    tamper_idx = output.index("## Tamper alerts pinned")
    per_action_idx = output.index("## Per-action sections")
    assert tamper_idx < per_action_idx

    # Pinned break details survive into the report.
    assert "01J7N4Y0A2L9SQWRJK3U9ECIGA" in output
    assert "entity_upserted" in output


# ---------------------------- volume-by-action ------------------------


def test_render_markdown_volume_by_action_lists_counts_descending() -> None:
    result = AuditQueryResult(
        total=4,
        events=(
            _event(action="episode_appended", entry_hash=_HEX_A),
            _event(action="episode_appended", entry_hash=_HEX_B),
            _event(action="entity_upserted", entry_hash=_HEX_C),
            _event(action="episode_appended", entry_hash="d" * 64),
        ),
    )
    chain = ChainIntegrityReport(valid=True, entries_checked=4)
    output = render_markdown(
        tenant_id=_TENANT_A, since=_SINCE, until=_UNTIL, result=result, chain=chain
    )
    # Episode-appended (count 3) lists before entity_upserted (count 1).
    section_start = output.index("## Volume by action")
    section_end = output.index("##", section_start + 1)
    section = output[section_start:section_end]
    assert section.index("episode_appended") < section.index("entity_upserted")


def test_render_markdown_volume_by_agent_lists_counts_descending() -> None:
    result = AuditQueryResult(
        total=3,
        events=(
            _event(action="x", agent_id="cloud_posture", entry_hash=_HEX_A),
            _event(action="x", agent_id="runtime_threat", entry_hash=_HEX_B),
            _event(action="x", agent_id="cloud_posture", entry_hash=_HEX_C),
        ),
    )
    chain = ChainIntegrityReport(valid=True, entries_checked=3)
    output = render_markdown(
        tenant_id=_TENANT_A, since=_SINCE, until=_UNTIL, result=result, chain=chain
    )
    section_start = output.index("## Volume by agent")
    section_end = output.index("##", section_start + 1)
    section = output[section_start:section_end]
    assert section.index("cloud_posture") < section.index("runtime_threat")


# ---------------------------- per-action sections ---------------------


def test_render_markdown_emits_per_action_section_per_distinct_action() -> None:
    result = AuditQueryResult(
        total=2,
        events=(
            _event(action="episode_appended", entry_hash=_HEX_A),
            _event(action="entity_upserted", entry_hash=_HEX_B),
        ),
    )
    chain = ChainIntegrityReport(valid=True, entries_checked=2)
    output = render_markdown(
        tenant_id=_TENANT_A, since=_SINCE, until=_UNTIL, result=result, chain=chain
    )
    assert "### action: episode_appended" in output
    assert "### action: entity_upserted" in output


def test_render_markdown_per_action_section_includes_correlation_id() -> None:
    result = AuditQueryResult(
        total=1,
        events=(
            _event(
                action="episode_appended",
                correlation_id="01J7N4Y0A2L9SQWRJK3U9ECIGA",
            ),
        ),
    )
    chain = ChainIntegrityReport(valid=True, entries_checked=1)
    output = render_markdown(
        tenant_id=_TENANT_A, since=_SINCE, until=_UNTIL, result=result, chain=chain
    )
    assert "01J7N4Y0A2L9SQWRJK3U9ECIGA" in output


# ---------------------------- empty inputs ----------------------------


def test_render_markdown_empty_result_states_no_events() -> None:
    """No events in the window should not produce a confusing 0/0 layout —
    it should say so plainly so operators don't think the tool broke.
    """
    result = AuditQueryResult(total=0, events=())
    chain = ChainIntegrityReport(valid=True, entries_checked=0)
    output = render_markdown(
        tenant_id=_TENANT_A, since=_SINCE, until=_UNTIL, result=result, chain=chain
    )
    assert "No audit events" in output


def test_render_markdown_clean_chain_omits_tamper_section() -> None:
    """The tamper-alerts section only renders when the chain is broken.
    A clean chain → no pinned section (would be noise).
    """
    result = AuditQueryResult(
        total=1,
        events=(_event(action="episode_appended"),),
    )
    chain = ChainIntegrityReport(valid=True, entries_checked=1)
    output = render_markdown(
        tenant_id=_TENANT_A, since=_SINCE, until=_UNTIL, result=result, chain=chain
    )
    assert "## Tamper alerts pinned" not in output
