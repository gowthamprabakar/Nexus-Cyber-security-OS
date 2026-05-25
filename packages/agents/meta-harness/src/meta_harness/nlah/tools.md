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

## Audit-action vocabulary

### v0.1 actions (4)

The v0.1 driver emits four additive `audit.>` entries per ADR-010 condition 4 (additive-only; no existing strings touched):

- `meta_harness.batch_eval.started` — run start; carries `customer_id`, `run_id`, `evaluated_agent_count`.
- `meta_harness.batch_eval.completed` — run end; carries per-agent pass-rate summary.
- `meta_harness.regression_detected` — one per regression; carries `agent_id`, `delta_pct`, previous-run pointer.
- `meta_harness.ab_comparison.completed` — only when the A/B subcommand is invoked.

### v0.2 actions (+4, total 8)

Task 12 of v0.2 adds four skill-lifecycle entries — emit helpers in `meta_harness.audit_emit`:

- **`meta_harness.skill.candidate_emitted`** — emitted by `emit_skill_candidate_emitted(audit_log, *, candidate)` after Task 7's `skill_writer.write_skill_candidate` writes the shadow `SKILL.md`. Payload: `skill_id`, `target_agent`, `category`, `shadow_path`, `tool_sequence_hash`, `emitted_at`.
- **`meta_harness.skill.eval_gate_completed`** — emitted by `emit_skill_eval_gate_completed(audit_log, *, result)` after Task 8's `run_skill_eval_gate` produces an `EvalGateResult` — pass OR fail, the event fires on both verdicts so the audit chain is complete. Payload: `skill_id`, `target_agent`, `passed`, `baseline_pass_rate`, `candidate_pass_rate`, `per_case_regression_count` (count only — full per-case detail lives in the cached `eval_gate_result.json` beside the shadow), `evaluated_at`.
- **`meta_harness.skill.deployed`** — emitted by `emit_skill_deployed(audit_log, *, decision)` after Task 10 promotes shadow → canonical (auto-approved refinement OR operator-approved first-of-class). Payload: `skill_id`, `target_agent`, `category`, `approval_mode` (`auto_approved` or `operator_approved`), `deployed_path`, `decided_at`. **Raises `ValueError` if `decision.deployed=False`** (routing-bug guard).
- **`meta_harness.skill.rejected`** — emitted by `emit_skill_rejected(audit_log, *, decision)` after Task 10 removes the shadow (eval-gate failure or operator rejection). Payload: `skill_id`, `target_agent`, `category`, `rejection_reason`, `decided_at`. **Raises `ValueError` if `decision.deployed=True`** (routing-bug guard).

All eight entries land via F.6 hash-chain semantics unchanged — each entry's `previous_hash` is the prior entry's `entry_hash`. **Substrate writes to `packages/charter/` are limited to the additive ADR-007 v1.4 progressive-disclosure loader (Task 4) and the additive ADR-012 §v1.1 forbidden-subscriber entry (Task 11). Both are SAFETY-CRITICAL substrate touches.**

## Skill-lifecycle helpers (v0.2)

Five module surfaces that Tasks 13's driver wires through Stages 6 + 7:

- **`meta_harness.skill_discovery`** (Task 5) — `discover_all_agent_skills(workspace_root, ...)` walks every `nexus_eval_runners` entry point + per-agent `nlah/skills/` subtree, builds `AgentSkillRegistry` per agent merging bundled + overlay (shadow) entries.
- **`meta_harness.skill_triggers`** (Task 6) — `detect_skill_trigger(agent_id, run_id, audit_entries, deployed_tool_sequence_hashes)` applies the Q3 3-condition gate (≥5 tool calls + no failure/escalation + hash novelty). Returns `SkillTrigger | None`.
- **`meta_harness.skill_writer`** (Task 7) — `await write_skill_candidate(trigger, audit_log_path, workspace_root, llm_provider, ...)` composes `SKILL.md` via a single `charter.llm.LLMProvider.complete(...)` call, overrides trust-boundary fields (`target_agent`, `created_by`, `deployment_status`, `eval_gate_status`, `provenance`), writes to the Q1 shadow path.
- **`meta_harness.skill_eval_gate`** (Task 8) — `await run_skill_eval_gate(candidate, workspace_root, cases, runner, llm_provider)` runs Option-B mandatory eval-gate (two runs of the target agent's eval suite, no `--force`). `with_candidate_skill_overlay(overlay_dir)` is a `contextvars.ContextVar`-based wrapper agents migrating to v0.2-aware NLAH loading consult via `get_active_skill_overlay()`.
- **`meta_harness.skill_registry`** (Task 9) — persistent skill-class registry at `<workspace>/.nexus/skill-class-registry.json`. `register_class(...)` is idempotent — re-registering preserves the original `first_approved_at` (audit-trail integrity). `deployed_tool_sequence_hashes(agent_id)` is the Task 6 input shape.
- **`meta_harness.skill_approval`** (Task 10) — three routing paths: `approve_candidate` (operator-approved first-of-class), `auto_deploy_candidate` (refinement within registered class), `reject_candidate` (eval-gate failure OR operator rejection). Promotion flips `deployment_status` `CANDIDATE → DEPLOYED` and removes the shadow.

All six modules are stitched together by `meta_harness.skill_lifecycle.run_skill_lifecycle(...)` (Task 13) — the Stage 6 + 7 orchestrator. The driver invokes it between Stage 5 REPORT (data assembly) and Stage 8 HANDOFF (markdown + KG write). When any of `llm_provider`, `audit_chain_loader`, `eval_runner_loader` is `None`, the orchestrator returns an empty `SkillLifecycleSummary` — v0.1-equivalent backwards-compat.

## G1 effectiveness scoring (v0.2.5)

A.4 measures the real-world effectiveness of every deployed skill via G1 composite scoring ([ADR-011](../../../../../../docs/_meta/decisions/ADR-011-g1-effectiveness-scoring.md)). The scoring pipeline spans three axes — adoption, outcome correlation, operator feedback — and produces an `EffectivenessScore` consumed by GEPA v0.2.5 for prompt optimisation.

### CLI commands

#### `meta-harness score-effectiveness`

Compute and persist G1 effectiveness scores for deployed skills.

```
meta-harness score-effectiveness [--agent <id>] [--skill <id>] [--tenant <id>] [--workspace-root <path>]
```

- **No flags:** aggregates all deployed skills across all agents.
- **`--agent <id>`:** scope to a single agent.
- **`--skill <id>` + `--agent <id>`:** scope to a single skill (requires `--agent`).
- **`--tenant <id>`:** scope to a specific tenant (default `"default"`).
- **Output:** table with columns `AGENT`, `SKILL`, `SCORE`, `CONF`, `REASON`.
- **Side-effects:** writes `effectiveness.json` to each skill's workspace-scoped sidecar directory at `<workspace>/.nexus/deployed-skills/<agent_id>/<skill_id>/effectiveness.json`.

#### `meta-harness rate-skill`

Record an operator rating for a deployed skill.

```
meta-harness rate-skill <skill_id> --rating {useful|neutral|harmful} [--note <text>] [--note-file <path>] [--agent <id>] [--tenant <id>] [--workspace-root <path>]
```

- **`--rating`:** required; one of `useful`, `neutral`, `harmful`.
- **`--note`:** optional one-line note attached to the rating.
- **`--note-file`:** optional file containing a multi-line note (takes precedence over `--note`).
- **`--agent`:** agent that owns the skill (default `"default-agent"`).
- **Side-effects:** appends to audit chain (`agent.skill.operator_rated`) AND sidecar projection at `<workspace>/.nexus/deployed-skills/<agent_id>/<skill_id>/operator-ratings.jsonl`.

### G1 audit-action vocabulary (6 actions)

Per ADR-007 v1.5 and G1-Q8-C, six audit actions form the closed effectiveness-event vocabulary. Future agents that emit skill-lifecycle events MUST use these constants from `shared.skill_telemetry`:

| Action                                     | Emitter                                        | Destination                      | Purpose                               |
| ------------------------------------------ | ---------------------------------------------- | -------------------------------- | ------------------------------------- |
| `agent.skill.loaded`                       | Agent runtime (`meta_harness.audit_emit`)      | Sidecar `run-events.jsonl`       | Skill activated at run start          |
| `agent.skill.contributed`                  | Agent runtime (`meta_harness.audit_emit`)      | Sidecar `run-events.jsonl`       | Skill outcome recorded at run end     |
| `agent.skill.outcome_correlated`           | A.4 aggregator (`compute_outcome_correlation`) | Audit chain                      | Outcome-axis correlation computed     |
| `agent.skill.operator_rated`               | CLI `rate-skill` command                       | Audit chain + sidecar projection | Operator feedback recorded            |
| `meta_harness.skill.effectiveness_updated` | A.4 store (`write_effectiveness_score`)        | Audit chain                      | Composite score changed               |
| `meta_harness.skill.effectiveness_error`   | G1 error paths (CF #2)                         | Audit chain                      | Any effectiveness computation failure |

The split is load-bearing: raw telemetry (loaded, contributed) goes to sidecar JSONL to avoid unbounded audit-chain growth; decision-level events (outcome_correlated, operator_rated, effectiveness_updated, effectiveness_error) go to the audit chain with full hash-chain linkage.

### Python API surface

**Score computation:**

- **`meta_harness.skill_effectiveness.compute_effectiveness_score(skill_id, agent_id, *, audit_log, workspace_root, tenant_id="default") -> EffectivenessScore`** — composite score from adoption + outcome + feedback axes. Returns `global_score=None, confidence=0.0, reason="insufficient_data"` when no data exists.

**Persistence:**

- **`meta_harness.effectiveness_store.get_effectiveness_score(skill_id, agent_id, *, workspace_root, tenant_id="default") -> EffectivenessScore | None`** — read the last persisted score from the sidecar. Returns `None` when no score has been computed yet.
- **`meta_harness.effectiveness_store.write_effectiveness_score(score, *, audit_log, workspace_root) -> None`** — atomic write (temp-file + rename) to the sidecar. Emits `meta_harness.skill.effectiveness_updated` to the audit chain only on change (idempotent — same `global_score` + `confidence` → no duplicate event).
- **`meta_harness.effectiveness_store.list_deployed_skills_with_scores(workspace_root, tenant_id="default") -> list[tuple[str, str, EffectivenessScore | None]]`** — enumerate all deployed skills with their current scores.

**Backwards-compat:**

- **`meta_harness.effectiveness_compat.apply_backwards_compat_reason(score, agent_id, *, audit_log, workspace_root) -> EffectivenessScore`** — upgrades `reason` from `"insufficient_data"` to `"agent_not_emitting_events"` for agents that have never emitted lifecycle events. Zero-confidence scores pass through unchanged for emitting agents.

**Agent-side emission helpers:**

- **`meta_harness.audit_emit.emit_skill_loaded(audit_log, skill_id, agent_id, tenant_id, *, run_id=None) -> Path`** — append `agent.skill.loaded` to the sidecar at run start.
- **`meta_harness.audit_emit.emit_skill_contributed(audit_log, skill_id, agent_id, tenant_id, *, outcome="success", run_id=None) -> Path`** — append `agent.skill.contributed` to the sidecar at run end. `outcome` must be `"success"`, `"failure"`, or `"partial"`.
- **`meta_harness.audit_emit.emit_skill_context(skill_id, agent_id, tenant_id, *, run_id=None)`** — context manager that emits `loaded` on enter and `contributed` on exit (outcome defaults to `"success"`; `"failure"` on exception).
