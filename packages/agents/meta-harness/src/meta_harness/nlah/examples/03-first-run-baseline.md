# Example 3 — first-run baseline (no prior `agent_scorecard` entities)

Operator command on a fresh A.4 install:

```sh
meta-harness run --customer-id acme --run-id baseline-2026-05-21
```

What A.4 does this run:

1. **INTROSPECT** runs as usual — every shipped agent's `nlah/` parses cleanly.
2. **BATCH_EVAL** produces 15 `Scorecard` rows (assume all clean for this example).
3. **DELTA**. The driver calls `SemanticStore.list_entities_by_type(tenant_id="acme", entity_type="agent_scorecard")` — and gets back **zero rows** because this is the operator's first A.4 run. `compute_batch_deltas(current, previous=[])` produces 15 `ScorecardDelta` entries, every one with `is_first_run=True`, `previous_pass_rate=None`, `delta_pct=0.0`.
4. **REPORT**. `flag_regressions(deltas)` returns an empty tuple — first-run rows are filtered out at the regression-flagger gate. Zero regressions, by design.
5. **HANDOFF** writes the report markdown + persists all 15 `agent_scorecard` entities. These become the **baseline** that the _next_ A.4 run will compare against.

Output fragment:

```markdown
# Meta-Harness Report — `acme` / `baseline-2026-05-21`

- **Scan window:** 2026-05-21T12:00:00+00:00 → 2026-05-21T12:08:42+00:00
- **Agents evaluated:** 15 (15 successful, 0 errored)
- **Regressions flagged:** 0

## Batch eval summary

... (15 agent rows) ...

## Regressions flagged

_No regressions detected._

## Watch-list

_No agents trending down across prior runs._
```

**Why this matters.** A first-run report contains zero regressions even when an agent's pass rate is theoretically bad — A.4 has nothing to compare against yet. The operator should treat first-run output as the **establishment of the baseline**, not as a green light. Subsequent runs (which now have these `agent_scorecard` entities to read) will surface real regressions.

This is also why **`semantic_store=None`** (the Q5 single-tenant default for v0.1) effectively makes every run a first-run for the lifetime of the process: without a persistent KG to read prior scorecards from, the delta computation always sees `previous=[]`. Production deployments that wire a real SemanticStore are the only ones that get true delta tracking — and multi-tenant production blocks on the future `SET LOCAL $1` tenant-RLS substrate-fix plan.
