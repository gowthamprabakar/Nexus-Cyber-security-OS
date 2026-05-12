# Tools reference

Every tool below is async (per [ADR-005](../../../../../docs/_meta/decisions/ADR-005-async-tool-wrapper-convention.md)). Permissions and budget impact go through the runtime charter — but per ADR-007 v1.3 the Audit Agent is **always-on**: only `wall_clock_sec` causes a stop. Every other budget axis logs a warning and proceeds.

## `audit_jsonl_read`

Read an `audit.jsonl` file emitted by `charter.audit.AuditLog`. Filesystem read happens under `asyncio.to_thread` so the agent driver can fan it out via `asyncio.TaskGroup`.

**Signature:** `await audit_jsonl_read(*, path, tenant_id)`

**Output:** `tuple[AuditEvent, ...]` — events with `source = "jsonl:<path>"`. Maps `AuditEntry.run_id` → `AuditEvent.correlation_id`.

**Forgiving:** malformed JSON / missing fields / hash that fails AuditEvent validation drops the line silently. Empty file → empty tuple. Missing file → `AuditJsonlError`.

## `episode_audit_read`

Read F.5 `episodes` rows for a tenant and surface them as `AuditEvent` shape.

**Signature:** `await episode_audit_read(*, session_factory, tenant_id, since=None, until=None)`

**Output:** `tuple[AuditEvent, ...]` — events with `source = "memory:<tenant_id>"`. The episodes table is **not** chain-structured (the chain lives in jsonl); F.6 roots each event at `charter.audit.GENESIS_HASH` and computes `entry_hash` deterministically via `_hash_entry`. The chain verifier handles these with `sequential=False`.

## `audit_store.ingest`

Append a batch of `AuditEvent`s to the `audit_events` table. Idempotent on `(tenant_id, entry_hash)` via dialect-specific `INSERT ... ON CONFLICT DO NOTHING`.

**Signature:** `await store.ingest(*, tenant_id, events)`

**Output:** `int` — count of newly inserted rows. Re-ingest of identical events returns 0.

## `audit_store.query`

Five-axis filter against the `audit_events` table.

**Signature:** `await store.query(*, tenant_id, since=None, until=None, action=None, agent_id=None, correlation_id=None, limit=1000)`

**Output:** `AuditQueryResult` (pydantic, JSON-round-tripping). Carries `total` for paging, `events: tuple[AuditEvent, ...]` ordered by `(emitted_at, audit_event_id)` ascending, plus derived `count_by_action` and `count_by_agent` dicts.

## `verify_audit_chain`

Validate the hash chain of an in-memory event sequence.

**Signature:** `verify_audit_chain(events, *, sequential)` (sync — no I/O)

**Output:** `ChainIntegrityReport` — `valid`, `entries_checked`, `broken_at_correlation_id`, `broken_at_action`. The model enforces `valid ↔ broken_at_correlation_id is None`. Stops at first break.

**Modes:**

- `sequential=True` — full chain validation. Use for `source = "jsonl:*"` events.
- `sequential=False` — per-entry hash recompute only. Use for `source = "memory:*"` events.

## `render_markdown`

Operator-grade summary renderer.

**Signature:** `render_markdown(*, tenant_id, since, until, result, chain)`

**Layout:** header → chain integrity → volume by action (desc) → volume by agent (desc) → tamper alerts pinned (only on break, **above** per-action sections) → per-action sections. Empty input degrades to "No audit events in this window." Clean chain omits the tamper section.
