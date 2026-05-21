# Tool surface — Supervisor Agent (#0 v0.1)

Supervisor v0.1 ships **no charter-registered tools.** The in-driver helpers below are pure-function or async-helper calls invoked directly from `supervisor.agent.run` and `supervisor.heartbeat.Heartbeat`, not through `ctx.call_tool`. They consume only the I/O budget of the underlying substrate calls (audit-chain writes + scheduled-queue file I/O + per-customer fcntl locks).

## In-driver helpers (NOT charter-registered)

### `supervisor.routing.parser.load_routing_rules`

Stage 0 startup — load + validate the routing table from `agents.md`.

- **Signature:** `load_routing_rules(path, *, known_agents=None) -> tuple[RoutingRule, ...]`
- **Behavior:** Markdown-with-YAML-frontmatter loader; rule entries validated through the `RoutingRule` pydantic model (at-least-one-match-predicate, non-empty permitted-tool names). Optional `known_agents: frozenset[str]` rejects unknown `target_agent` values.
- **Errors:** `RoutingRuleParseError` on missing file / malformed YAML / missing `rules:` key / duplicate rule_id / per-rule validation failure / unknown agent_id.

### `supervisor.routing.router.route`

Stage 2 ROUTE — pure-function rule engine.

- **Signature:** `route(task: IncomingTask, rules: Sequence[RoutingRule]) -> RoutingDecision`
- **Precedence:** explicit `target_agent_declared` > `task_type_pattern` > `delta_type_pattern`. Higher `priority` wins ties; same-priority ties → `Ambiguous`.
- **WI-4 sub-clause:** router only inspects four envelope keys on `IncomingTask` — never opens OCSF payload bodies.

### `supervisor.dispatch.dispatch_parallel`

Stage 3 DISPATCH — parallel delegation under `Semaphore(MAX_PARALLEL_DISPATCH=5)`.

- **Signature:** `async dispatch_parallel(contracts, *, invoker: DelegationInvoker, concurrency=5) -> list[DelegationOutcome]`
- **Failure model (Q4):** OK / TIMEOUT_PARTIAL (via `asyncio.wait_for`) / ERROR (any other exception). One attempt per delegation; no auto-retry.
- **DI:** `DelegationInvoker` Protocol — production wires it to the entry-point lookup; v0.1 default (`make_logging_invoker()`) logs the dispatch + no-ops since real fleet specialist invocation is deferred to v0.2.

### `supervisor.escalation.{build_routing_escalation, build_delegation_escalation, write_escalation_markdown}`

Stage 4 AUDIT + Stage 5 HANDOFF — convert non-OK outcomes into operator notifications.

- Returns `None` on the OK / Match paths.
- Each escalation gets a fresh ULID `escalation_id`.
- `write_escalation_markdown` writes to `<workspace_root>/escalation_<id>.md` with the "v0.1 does not auto-retry" reminder verbatim.

### `supervisor.scheduled_queue.{enqueue, drain, peek}`

Stage 1 INGEST trigger source #3 — file-backed JSON queue.

- **Storage:** `<workspace_root>/.supervisor/scheduled/<customer_id>.json` (JSON array).
- **Concurrency:** all I/O acquires `fcntl.LOCK_EX` on the queue file for the duration of the read-modify-write.
- **Drain:** atomic per-tick read-then-rewrite; missing file = empty queue (not an error).

### `supervisor.audit_emit.emit_*`

Stage 4 AUDIT — write entries to the per-tick `AuditLog`.

- 4 additive vocabulary entries (Q6 below).
- F.6 hash-chain semantics inherited unchanged from `charter.audit.AuditLog`.

## Audit-action vocabulary (per Q6)

The driver emits four additive `audit.>` entries per ADR-010 condition 4 (additive-only; no existing strings touched):

- `supervisor.heartbeat.started` — every tick start; carries `customer_id`, `tick_id`, `triggers_by_source` (counts per `events_bus` / `operator_cli` / `scheduled_queue`).
- `supervisor.delegation.dispatched` — one per delegation at dispatch time; carries `target_agent`, `delegation_id`, `task_id`, `rule_id`, `budget_wall_clock_sec`, `budget_max_tool_calls`.
- `supervisor.delegation.completed` — one per delegation at completion; carries `status` (ok / timeout_partial / error), `duration_sec`, `reason` (only when status != ok).
- `supervisor.escalation.raised` — one per escalation event; carries `escalation_id`, `reason`, `raised_at`, optional `escalation_markdown` path.

These land via F.6 hash-chain semantics unchanged. **No substrate writes to `packages/charter/`** beyond the SAFETY-CRITICAL Task 8 substrate touch (which extended `_FORBIDDEN_SUBSCRIPTIONS` in `packages/shared/src/shared/fabric/client.py`).
