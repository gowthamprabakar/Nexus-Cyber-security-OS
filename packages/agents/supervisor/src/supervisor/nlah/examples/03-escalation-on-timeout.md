# Example 3 — escalation on delegation timeout

Operator triggers a task that overshoots the F.1 budget:

```sh
supervisor heartbeat-once \
  --customer-id acme \
  --task-id t_slow \
  --target-agent cloud_posture
```

Under the hood, the cloud_posture specialist (production v0.2+ wiring) takes longer than the `DelegationContract.budget_wall_clock_sec` allows. What Supervisor does this tick:

1. **INGEST** — single `IncomingTask`, target_agent=cloud_posture.
2. **ROUTE** — `RoutingMatch` against the explicit rule, as usual.
3. **DISPATCH** — `asyncio.wait_for` enforces the budget. The specialist's invoker runs past 30s; `wait_for` raises `TimeoutError`. The dispatch path catches it and produces `DelegationOutcome(status=TIMEOUT_PARTIAL, reason="timeout after 30s")`.
4. **AUDIT** — entries: `heartbeat.started` (1) + `delegation.dispatched` (1) + `delegation.completed` (1, status=timeout_partial) + `escalation.raised` (1).
5. **HANDOFF** — `supervisor_report.md` shows the timeout outcome in the "Delegation outcomes" table; `escalation_<id>.md` written to the workspace with the full escalation context.

## The escalation markdown

```markdown
# Supervisor escalation — `<escalation_id>`

- **Customer:** `acme`
- **Task:** `t_slow`
- **Raised at:** 2026-05-21T12:00:30+00:00

## Reason

cloud_posture: timeout after 30s

---

_This escalation is operator-facing only — Supervisor v0.1 does not auto-retry. Re-triggering the failed task is the operator's responsibility._
```

## What Supervisor does NOT do

- **No auto-retry.** Per Q4: one attempt per delegation. Re-triggering is the operator's job. Deferred to **Supervisor v0.2**.
- **No retry with extended budget.** The budget value comes from the routing rule + heartbeat config; Supervisor doesn't unilaterally extend it.
- **No silent failure.** Every non-OK outcome surfaces in three places: the audit chain entry, the `supervisor_report.md` delegation table, and a dedicated `escalation_<id>.md` markdown.

The operator now has a clear punch list: investigate why `cloud_posture` exceeded budget for `t_slow`, decide whether to re-trigger with a higher budget, or escalate further within the team. Supervisor stays out of that loop in v0.1.
