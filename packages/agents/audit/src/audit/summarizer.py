"""Markdown summarizer for `AuditQueryResult` + `ChainIntegrityReport` (F.6 Task 9).

Renders a top-down operator report:

    # Audit summary — tenant <id>, <since> → <until>

    ## Chain integrity
    Chain valid (<N> entries checked).            ← or break details

    ## Volume by action
    | action               | count |
    |----------------------|------:|
    | episode_appended     |    42 |
    | entity_upserted      |     7 |

    ## Volume by agent
    | agent             | count |
    |-------------------|------:|
    | cloud_posture     |    33 |
    | runtime_threat    |    16 |

    ## Tamper alerts pinned                       ← rendered only on break
    > Chain break at correlation_id `…`, action `…`.
    >
    > Last verified entry index: <N>

    ## Per-action sections
    ### action: episode_appended
    - <ts> · cloud_posture · corr `…` · hash `a1b2…`
    - …

The tamper-alerts section is pinned **above** the per-action sections
so the operator never has to scroll past noise to see a chain break.
This mirrors D.3's "Critical runtime alerts" pinning pattern.

Empty input renders a "No audit events in this window." note so the
operator doesn't think the tool broke.
"""

from __future__ import annotations

from datetime import datetime
from io import StringIO

from audit.schemas import AuditEvent, AuditQueryResult, ChainIntegrityReport


def render_markdown(
    *,
    tenant_id: str,
    since: datetime,
    until: datetime,
    result: AuditQueryResult,
    chain: ChainIntegrityReport,
) -> str:
    """Render an audit summary as Markdown."""
    out = StringIO()
    _write_header(out, tenant_id=tenant_id, since=since, until=until)
    _write_chain_integrity(out, chain=chain)

    if result.total == 0:
        out.write("\nNo audit events in this window.\n")
        return out.getvalue()

    _write_volume_by_action(out, result=result)
    _write_volume_by_agent(out, result=result)

    if not chain.valid:
        _write_tamper_pin(out, chain=chain, result=result)

    _write_per_action_sections(out, result=result)
    return out.getvalue()


# ---------------------------- section writers ---------------------------


def _write_header(
    out: StringIO,
    *,
    tenant_id: str,
    since: datetime,
    until: datetime,
) -> None:
    out.write(
        f"# Audit summary — tenant `{tenant_id}`, "
        f"{since.date().isoformat()} → {until.date().isoformat()}\n"
    )


def _write_chain_integrity(out: StringIO, *, chain: ChainIntegrityReport) -> None:
    out.write("\n## Chain integrity\n\n")
    if chain.valid:
        out.write(f"Chain valid ({chain.entries_checked} entries checked).\n")
    else:
        out.write(
            "**Chain BROKEN.** Last verified entry index: "
            f"{chain.entries_checked}.\n\n"
            f"Break location: correlation_id `{chain.broken_at_correlation_id}`, "
            f"action `{chain.broken_at_action}`.\n"
        )


def _write_volume_by_action(out: StringIO, *, result: AuditQueryResult) -> None:
    out.write("\n## Volume by action\n\n")
    counts = sorted(result.count_by_action.items(), key=lambda kv: (-kv[1], kv[0]))
    out.write("| action | count |\n")
    out.write("|---|---:|\n")
    for action, count in counts:
        out.write(f"| {action} | {count} |\n")


def _write_volume_by_agent(out: StringIO, *, result: AuditQueryResult) -> None:
    out.write("\n## Volume by agent\n\n")
    counts = sorted(result.count_by_agent.items(), key=lambda kv: (-kv[1], kv[0]))
    out.write("| agent | count |\n")
    out.write("|---|---:|\n")
    for agent, count in counts:
        out.write(f"| {agent} | {count} |\n")


def _write_tamper_pin(
    out: StringIO,
    *,
    chain: ChainIntegrityReport,
    result: AuditQueryResult,
) -> None:
    out.write("\n## Tamper alerts pinned\n\n")
    out.write(
        f"> **Chain break detected.** Verified through entry index "
        f"{chain.entries_checked}; the next entry's hash does not match.\n>\n"
        f"> - correlation_id: `{chain.broken_at_correlation_id}`\n"
        f"> - action: `{chain.broken_at_action}`\n"
    )
    # If the broken event is in the result set, surface its raw row too.
    for event in result.events:
        if event.correlation_id == chain.broken_at_correlation_id:
            out.write(
                f">\n> Event details: agent `{event.agent_id}`, "
                f"emitted_at `{event.emitted_at.isoformat()}`, "
                f"source `{event.source}`.\n"
            )
            break


def _write_per_action_sections(out: StringIO, *, result: AuditQueryResult) -> None:
    out.write("\n## Per-action sections\n")
    # Group events by action (preserve order within a group).
    grouped: dict[str, list[AuditEvent]] = {}
    for event in result.events:
        grouped.setdefault(event.action, []).append(event)

    # Iterate actions in descending count order so the heaviest section
    # appears first; ties break alphabetically.
    action_order = sorted(
        grouped.keys(),
        key=lambda action: (-len(grouped[action]), action),
    )
    for action in action_order:
        out.write(f"\n### action: {action}\n\n")
        for event in grouped[action]:
            out.write(
                f"- `{event.emitted_at.isoformat()}` · agent `{event.agent_id}` · "
                f"corr `{event.correlation_id}` · hash `{event.entry_hash[:8]}…`\n"
            )


__all__ = ["render_markdown"]
