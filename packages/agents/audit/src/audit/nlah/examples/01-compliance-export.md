# Example: compliance team exports a 30-day audit trail

A SOC 2 auditor asks: _"Show me every memory write for tenant `01HV0T...001` between May 1 and May 30, 2026."_

The Audit Agent's response:

1. Parses the NL question into typed parameters: `tenant_id="01HV0T...001"`, `since=2026-05-01T00:00:00Z`, `until=2026-05-30T23:59:59Z`, no action filter.
2. Ingests every `audit.jsonl` source listed in the contract via `audit_jsonl_read`.
3. Also reads F.5 `episodes` rows in the window via `episode_audit_read` (memory-rooted events surface alongside jsonl-chained events).
4. Ingests both into `audit_events` via `AuditStore.ingest` — idempotent, so re-running the export over the next 30 days doesn't duplicate.
5. `verify_audit_chain(jsonl_events, sequential=True)` + `verify_audit_chain(memory_events, sequential=False)`. Both reports must be valid before the export is signed.
6. `AuditStore.query(tenant_id=..., since=..., until=...)` returns the unified `AuditQueryResult`.
7. `render_markdown(result, chain)` produces the operator-facing report. The audit chain stays valid → no tamper-pin section. Volume tables surface the heaviest actions and agents. Per-action sections enumerate every event.

Output:

- `report.md` — Markdown summary handed to the auditor.
- `events.json` — Wire-shape `AuditQueryResult` for downstream tools.
- `audit.jsonl` — The Audit Agent's own chain entry for this query (the auditor can audit the auditor).
