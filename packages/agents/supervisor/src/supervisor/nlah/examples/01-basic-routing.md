# Example 1 — basic single-task routing

Operator triggers a one-shot task via the CLI:

```sh
supervisor heartbeat-once \
  --customer-id acme \
  --task-id t1 \
  --target-agent cloud_posture \
  --task-description "Scan us-east-1 for posture issues"
```

What Supervisor does this tick:

1. **INGEST** — the CLI invocation creates a single `IncomingTask(task_id="t1", trigger_source=OPERATOR_CLI, target_agent="cloud_posture", ...)`. Scheduled queue is empty; events.> source is no-op.
2. **ROUTE** — `route(task, rules)` walks the rule list. Rule `cloud_posture_explicit` carries `target_agent_declared="cloud_posture"` → exact match. Returns `RoutingMatch(rule_id="cloud_posture_explicit", target_agent="cloud_posture", permitted_tools=("prowler_scan", "aws_s3_describe", ...))`.
3. **DISPATCH** — builds `DelegationContract(delegation_id=<ULID>, target_agent="cloud_posture", task_id="t1", permitted_tools=..., budget_wall_clock_sec=30.0, budget_max_tool_calls=50)`. Invokes the v0.1 logging-only invoker; returns immediately with `DelegationOutcome(status=OK, duration_sec=~0)`. (Real fleet specialist invocation lands in Supervisor v0.2.)
4. **AUDIT** — three entries written to the F.6 hash-chained audit log:
   - `supervisor.heartbeat.started` (1 trigger, source=operator_cli)
   - `supervisor.delegation.dispatched` (target_agent=cloud_posture, rule_id=cloud_posture_explicit)
   - `supervisor.delegation.completed` (status=ok)
5. **HANDOFF** — writes `supervisor_report.md` showing the trigger → routing → outcome chain.

Output fragment from `supervisor_report.md`:

```markdown
# Supervisor heartbeat report — `acme` / `01J7M3X9Z1K8RPVQNH2T8DBHFZ`

- **Tick window:** 2026-05-21T12:00:00+00:00 -> 2026-05-21T12:00:00+00:00
- **Triggers received:** 1
- **Delegations:** 1 (1 successful)
- **Escalations raised:** 0

## Triggers

- `t1` from `operator_cli` -> target_agent=`cloud_posture` task_type=`None` delta_type=`None`

## Routing decisions

- match: ...

## Delegation outcomes

- `<delegation_id>` -> `cloud_posture`: ok (0.00s)
```

This is the canonical happy-path: operator triggers → Supervisor routes → specialist would-be-invoked → audit chain records the decision → operator reads `supervisor_report.md`.
