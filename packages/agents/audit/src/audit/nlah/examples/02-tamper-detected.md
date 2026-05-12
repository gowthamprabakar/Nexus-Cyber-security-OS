# Example: chain tamper detected during a routine export

A weekly cron pulls a Meta-Harness training corpus: _"Give me every action for tenant `01HV0T...042` for the last 7 days."_

The Audit Agent's response when a tamper is present:

1. Same ingest path as Example 01.
2. `verify_audit_chain(jsonl_events, sequential=True)` returns `ChainIntegrityReport(valid=False, entries_checked=47, broken_at_correlation_id="01J7N4Y0...", broken_at_action="episode_appended")`.
3. The store query still runs — the operator sees the full data set, just labelled. Hiding the data would let the tamperer also hide the surrounding context.
4. `render_markdown` pins the **`## Tamper alerts pinned`** section above the per-action sections. The break's correlation_id and action are surfaced verbatim. If the breaking event is in the result set, its raw agent + emitted_at + source are also pinned.
5. The CLI exits with status code 2 (distinct from 0=clean, 1=tooling failure) so the cron job's downstream pipeline halts the export and pages the on-call.

What the operator does next:

- Reads the pinned break details to identify the breaking event.
- Locates the underlying `audit.jsonl` source via the event's `source` field (e.g. `jsonl:/var/log/nexus/audit-2026-05-23.jsonl`).
- Compares against any backup of that file (chain integrity is the canary; restoring from backup is the response).
- Files an incident under the platform's compliance-incident playbook.

What the Audit Agent does **not** do:

- Auto-correct the chain. The chain is evidence; correcting it would destroy the very thing the chain is for.
- Page a person directly. v0.1 surfaces breaks via CLI exit code; Phase 1c adds PagerDuty / Slack routing.
- Skip the chain check on cron-style invocations. Always-on means always-on; there's no flag that turns chain verification off.
