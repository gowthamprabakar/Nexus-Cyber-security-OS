# Runbook — Continuous Monitoring (investigation v0.2)

D.7 v0.2 ships continuous-monitoring **infrastructure** (WI-I9). Two modes coexist (Q6); neither
preempts the other:

| Mode         | Trigger                                         | Default |
| ------------ | ----------------------------------------------- | ------- |
| `HEARTBEAT`  | On-demand Supervisor dispatch (the v0.1 path)   | ✅ yes  |
| `CONTINUOUS` | The `InvestigationScheduler` marks a tenant due | no      |

## Selecting a mode

The mode is a **charter config flag only** — it governs _when_ an investigation runs, never _how_
the report renders. `emit_for_mode()` is deliberately mode-independent, so both modes produce
**byte-identical** OCSF 2005 output on the same input (WI-I5):

```python
from investigation.continuous.mode import MODE_CONFIG_KEY, select_mode
mode = select_mode({MODE_CONFIG_KEY: "continuous"})  # unknown/missing -> HEARTBEAT
```

## The scheduler (infrastructure)

```python
from investigation.continuous.scheduler import InvestigationScheduler
s = InvestigationScheduler()
s.register(tenant_id, interval_seconds=300)   # per-tenant, independent intervals
due = s.due(now)                              # never-run tenants are always due
s.mark_ran(tenant_id, at=now)                 # records the last run
```

Every entry is tenant-scoped (WI-I16): an empty `tenant_id` is rejected at `register`.

## Path 1 boundary (important)

The scheduler decides _when_; it does **not** drive `agent.run()`. Wiring `CONTINUOUS` into the
production loop is the **Phase C consolidated retrofit** that lands after all 17 v0.2 cycles — it
is _not_ a v0.3 carry-forward. Until then, run investigations via the `HEARTBEAT` path.
