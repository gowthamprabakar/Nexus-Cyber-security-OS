# Example 1 — batch eval across the 15 v0.1 fleet

Operator command:

```sh
meta-harness run --customer-id acme --run-id r-2026-05-21 --workspace-root .
```

What A.4 does this run:

1. **INTROSPECT** discovers 15 registered `nexus_eval_runners` entry points, parses each agent's `nlah/` directory, and builds 15 `AgentManifest` objects with persona + declared-tools + example_count + eval_case_count.
2. **BATCH_EVAL** runs each agent's bundled eval suite in lexicographic order. For this run, 14 of 15 agents return clean `Scorecard(pass_rate=...)`; one (`data_security`) raises an `ImportError` because a recent refactor left a stale dependency — it surfaces as `Scorecard(pass_rate=None, error="ImportError: ...")` and the batch continues.
3. **DELTA** loads previous `agent_scorecard` entities from `SemanticStore` (one per agent from the prior run, 36 hours ago). 13 of 15 produce a `ScorecardDelta` with `is_first_run=False`. 1 agent (`investigation`) is brand new since the last A.4 run — `is_first_run=True`, `delta_pct=0.0`. 1 agent (`data_security`) failed this run, so its delta has `is_comparable=False`.
4. **REPORT** runs `flag_regressions`. Two agents crossed the 5% threshold: `compliance` dropped from 92% to 85% (`delta_pct=-7.0`); `runtime_threat` dropped from 88% to 75% (`delta_pct=-13.0`). Both surface as `RegressionFlag` entries.
5. **HANDOFF** writes `meta_harness_report.md` to the workspace + persists the 15 `agent_scorecard` entities to `SemanticStore`.

Output fragment from the report's "Regressions flagged" section:

```markdown
## Regressions flagged

_2 agent(s) crossed the ≥5% pass-rate-drop threshold._

| Agent            | Previous | Current | Δ         |
| ---------------- | -------- | ------- | --------- |
| `compliance`     | 92.0%    | 85.0%   | -7.0 pct  |
| `runtime_threat` | 88.0%    | 75.0%   | -13.0 pct |
```

The operator now has a clear punch list: re-investigate `compliance` + `runtime_threat`, and separately repair the `ImportError` that took `data_security` offline this run.
