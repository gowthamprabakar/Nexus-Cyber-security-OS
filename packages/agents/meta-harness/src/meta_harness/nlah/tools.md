# Tool surface — Meta-Harness Agent (A.4 v0.1)

A.4 v0.1 ships **no charter-registered tools.** The four in-driver helpers below are pure-function or async-helper calls invoked directly from `meta_harness.agent.run`, not through `ctx.call_tool`. They consume only the I/O budget of the underlying substrate calls (SemanticStore reads + the per-agent eval-suite invocation).

## In-driver helpers (NOT charter-registered)

### `parse_nlah_dir`

Stage 1 INTROSPECT — read-only walker over one agent's `nlah/` directory.

- **Signature:** `parse_nlah_dir(nlah_dir, *, agent_id, eval_cases_dir=None) -> AgentManifest`
- **Behaviour:** Required `README.md` → persona extracted from first non-heading paragraph (collapsed whitespace, 1024-char bound). Optional `tools.md` → declared tools parsed from level-2 headers shaped like `## tool_name(...)` (deduplicated, first-occurrence order). Optional `examples/` → markdown file count. Optional `eval_cases_dir` cross-reference → YAML file count.
- **Errors:** `NlahParseError` on missing dir / missing README / empty README. Caught at the driver boundary (Stage 1 INTROSPECT skip-with-log) — does not kill the batch.
- **WI-4:** Every read goes through `Path.read_text(encoding="utf-8")`. The companion integration test patches `Path.open` + `builtins.open` and asserts every mode is read-only.

### `BatchEvalRunner.run_batch`

Stage 2 BATCH_EVAL — sequential cross-agent eval orchestrator.

- **Signature:** `async BatchEvalRunner(*, cases_root, config=None).run_batch(*, customer_id, run_id) -> list[Scorecard]`
- **Discovery:** `importlib.metadata.entry_points(group="nexus_eval_runners")`, sorted lexicographically by name for deterministic ordering.
- **Failure tolerance (Task 4 risk-mitigation row):** per-agent exceptions — `ep.load()`, `load_cases`, or mid-suite raises — surface as `Scorecard(pass_rate=None, error=<short message>)` and the loop continues. Empty cases dir → `Scorecard(total_cases=0, pass_rate=1.0)` (zero-cases doesn't drag the batch average).
- **DI:** the `cases_root: CasesRootResolver` Protocol lets tests inject synthetic case directories; the default resolver picks `<workspace_root>/packages/agents/<kebab-case>/eval/cases`.

### `ab_compare`

Stage 3 AB_COMPARE — single-agent A/B engine (optional; only when all three of `ab_variant_a`, `ab_variant_b`, `ab_target_agent` are set).

- **Signature:** `async ab_compare(request, *, cases_resolver) -> ABComparison`
- **Mechanism:** `nlah_override(target_dir)` context patches `charter.nlah_loader.default_nlah_dir` to redirect every per-agent call to the override path for the duration of one suite run, then restores the original (including under exception).
- **WI-3 acceptance:** the top-level `byte_equal` flag is True iff every per-case serialized `RunOutcome` is byte-equal across variants. `_canonical_bytes` strips `duration_sec` and trace timestamps before compare (those are legitimately variable); payload is sorted-key JSON.
- **Errors:** `ABCompareError` on identical variant paths, unknown agent_id, or missing override directory.

### `compute_batch_deltas` + `flag_regressions`

Stages 4 DELTA + 5 REPORT — pure-function consumers of `Scorecard` and `ScorecardDelta`.

- **`compute_batch_deltas(current_scorecards, previous_scorecards) -> tuple[ScorecardDelta, ...]`** matches by `agent_id`; orphan previous agents (not in current) are silently dropped; first-run rows flagged with `delta_pct=0.0`. Either side `pass_rate=None` → `delta_pct=0.0`, `is_comparable=False`.
- **`flag_regressions(deltas, *, threshold_pct=5.0) -> tuple[RegressionFlag, ...]`** filters to rows crossing `delta_pct <= -threshold_pct` (≤ is conservative; the boundary 5% drop IS flagged). First-run and non-comparable rows never flag. `threshold_pct <= 0` raises `ValueError`.

## Audit-action vocabulary (per Q6)

The driver emits four additive `audit.>` entries per ADR-010 condition 4 (additive-only; no existing strings touched):

- `meta_harness.batch_eval.started` — run start; carries `customer_id`, `run_id`, `evaluated_agent_count`.
- `meta_harness.batch_eval.completed` — run end; carries per-agent pass-rate summary.
- `meta_harness.regression_detected` — one per regression; carries `agent_id`, `delta_pct`, previous-run pointer.
- `meta_harness.ab_comparison.completed` — only when the A/B subcommand is invoked.

These land via F.6 hash-chain semantics unchanged. **No substrate writes to `packages/charter/`.**
