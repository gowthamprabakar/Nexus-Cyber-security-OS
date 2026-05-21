# Example 2 — parallel dispatch of pre-declared independent tasks

Operator enqueues three independent tasks via the CLI, then triggers a heartbeat:

```sh
supervisor schedule --customer-id acme --task-id t1 --target-agent cloud_posture
supervisor schedule --customer-id acme --task-id t2 --target-agent vulnerability
supervisor schedule --customer-id acme --task-id t3 --target-agent identity
supervisor heartbeat-once --customer-id acme
```

What Supervisor does this tick:

1. **INGEST** — drains 3 tasks from the file-backed scheduled-task queue at `<workspace_root>/.supervisor/scheduled/acme.json`. Each materializes as `IncomingTask(trigger_source=SCHEDULED_QUEUE, ...)`.
2. **ROUTE** — `route(...)` per trigger. All three return `RoutingMatch` against the explicit rules in `agents.md`.
3. **DISPATCH** — builds three `DelegationContract` objects. `dispatch_parallel(contracts, invoker=..., concurrency=5)` runs all three under `Semaphore(5)` simultaneously. Wall-clock is the max of the three, not the sum (parallel-dispatch is the optimization v0.1's `MAX_PARALLEL_DISPATCH=5` enables).
4. **AUDIT** — 7 entries: `heartbeat.started` (1) + `delegation.dispatched` (3) + `delegation.completed` (3).
5. **HANDOFF** — `supervisor_report.md` shows three rows in the "Delegation outcomes" section.

## What this is NOT

**This is NOT multi-agent planning.** Supervisor did not decide "task t1 needs cloud_posture, task t2 needs vulnerability, task t3 needs identity" by analysing intent — the operator (or the upstream event source) pre-declared each `target_agent` explicitly. Supervisor v0.1's role is purely to **fan out pre-declared independent tasks in parallel**, not to decompose a single task into agent assignments.

Per Q-ARCH-2 / v0.3 deferral: actual multi-agent decomposition + LLM-driven planning lands in **Supervisor v0.3+**, after v0.2 introduces LLM-assisted routing.

## The Semaphore(5) cap

If the operator enqueues 6 tasks instead of 3, the first 5 dispatch concurrently while the 6th waits behind the semaphore. Once any of the first 5 finishes, the 6th proceeds. **Wall-clock is roughly 2 × max-per-task-latency**, not 6× — the cap protects against runaway concurrent dispatch while still parallelising what fits in the budget.

```markdown
## Delegation outcomes

- `<d1>` -> `cloud_posture`: ok (0.00s)
- `<d2>` -> `vulnerability`: ok (0.00s)
- `<d3>` -> `identity`: ok (0.00s)
```

Each delegation gets its own ULID `delegation_id`. The audit chain links them all to the same `tick_id` so the operator can reconstruct the full per-tick story.
