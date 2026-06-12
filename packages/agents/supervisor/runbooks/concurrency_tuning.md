# Runbook — Per-Agent Concurrency Tuning (supervisor v0.2)

## Defaults

Per-agent cap defaults to **4** concurrent delegations (Q2). A slow agent can't starve the
others.

## Override per agent

Pass a config mapping (`concurrency/config.py::parse_concurrency_config`):

```json
{ "default_cap": 4, "overrides": { "audit": 2, "compliance": 8 } }
```

`build_semaphores(cfg)` yields the `PerAgentSemaphores`. Caps must be >= 1.

## Backpressure

`acquire_within(sems, agent_id, timeout_s=...)` raises `SemaphoreWaitTimeout` if a slot can't
be acquired in time — emit `supervisor.delegation.semaphore_wait` and let the operator decide.
Per-tenant concurrency is v0.3.
