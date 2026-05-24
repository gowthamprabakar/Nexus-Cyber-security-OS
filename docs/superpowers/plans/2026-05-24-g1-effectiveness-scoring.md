# G1 Effectiveness Scoring — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Pause for review after each numbered task.

**Goal:** Ship **G1 Effectiveness Scoring** — the post-deployment telemetry layer that assigns a confidence-weighted composite effectiveness score (0-1) to every deployed skill. G1 answers: "Did this skill actually make the agent better?"

Without G1, v0.2.5's DSPy+GEPA compilation has no metric to optimize against. The [DSPy+GEPA strategic doc](../../_meta/dspy-gepa-prompt-optimization-2026-05-22.md) §2.2 shows `metric=skill_quality_metric` — G1 defines that metric mechanically. G1 is the first brick in the G1→G2→v0.2.5→Wave 1 dependency chain per [Hermes adoption doc](../../_meta/hermes-self-evolution-adoption-2026-05-23.md) §5.1.

**Scope (G1 v0.1):**

1. **Skill-lifecycle event vocabulary.** Six new audit actions: `agent.skill.loaded`, `agent.skill.contributed` (agent-emitted, to sidecar JSONL), `agent.skill.outcome_correlated`, `agent.skill.operator_rated`, `meta_harness.skill.effectiveness_updated`, `meta_harness.skill.effectiveness_error` (A.4-emitted, to audit chain). Per G1-Q8-C: raw telemetry in sidecar JSONL; state transitions in audit chain — following A.4 v0.2 verification record CF #6 ("decision in chain, detail in cached JSON").
2. **Effectiveness score computation.** Confidence-weighted composite formula: `w_adoption=0.25`, `w_outcome=0.35`, `w_feedback=0.40`. Per-agent weight refinement deferred to v0.3 when real data justifies tuning. New skills start at confidence=0; scores converge as data accumulates. GEPA naturally ignores zero-confidence signals.
3. **Effectiveness storage.** Workspace-scoped sidecar at `<workspace>/.nexus/deployed-skills/<agent_id>/<skill_id>/effectiveness.json`. Mirrors Task 15's candidate-sidecar pattern. Python API (`effectiveness_store.get_effectiveness_score(skill_id, agent_id) -> EffectivenessScore`) with **leaf-module discipline**: `effectiveness_store.py` must NOT import from `skill_lifecycle.py`, `skill_writer.py`, `skill_eval_gate.py`, or `skill_approval.py` (resolves CR-3 circular-import risk). Score payload: global score + per-agent + per-tenant breakdowns.
4. **Tenant-keyed schema from day one.** Uses `tenant_id="default"` until SET LOCAL `$1` fix lands. No schema migration needed when multi-tenancy opens.
5. **Operator feedback mechanism.** CLI: `meta-harness rate-skill <skill_id> --useful|--neutral|--harmful [--note "..."]`. Programmatically callable (subprocess-friendly exit codes + structured stdout).
6. **Aggregator CLI.** `meta-harness score-effectiveness [--agent <id>] [--skill <id>]` — manual trigger for v0.2.5; scheduled/automated aggregation deferred to A.4 v0.3 Curator. CLI is programmatically callable by v0.2.5 GEPA compilation (call before reading scores).
7. **Backwards-compat.** Agents not emitting skill-lifecycle events yield `{global_score: null, confidence: 0.0, reason: "agent_not_emitting_events"}`. Schema `reason` field supports: `agent_not_emitting_events`, `insufficient_data`, `operator_marked_archived`, `effectiveness_error_during_aggregation`.
8. **Eval suite.** 5 new scenario-based cases (total 20). Scenario-based naming makes the eval suite self-documenting.
9. **Per-agent migration runbook.** Shipped in A.4's NLAH bundle — tells future Wave 1+ agent migrations exactly how to opt in (2-line addition: `emit_agent_skill_loaded` at run start, `emit_agent_skill_contributed` at run end).

---

## Architecture overview

```
┌────────────────────────────────────────────────────────────────────┐
│ G1 Effectiveness Scoring                                           │
│                                                                    │
│  Per-run (agent-local, opt-in):                                    │
│    Agent run start → emit agent.skill.loaded    → sidecar JSONL    │
│    Agent run end   → emit agent.skill.contributed → sidecar JSONL  │
│                                                                    │
│  Per-aggregation (A.4 Meta-Harness, manual CLI):                   │
│    meta-harness score-effectiveness                                │
│      → Read sidecar JSONL (load/contribute events)                 │
│      → Read audit chain (run success/failure events)               │
│      → Read operator ratings (rate-skill CLI output)               │
│      → Compute confidence-weighted composite score (0-1)           │
│      → Write effectiveness.json (workspace-scoped sidecar)         │
│      → Emit meta_harness.skill.effectiveness_updated (audit chain) │
│      → On error: emit meta_harness.skill.effectiveness_error       │
│                                                                    │
│  Consumption (v0.2.5 GEPA):                                        │
│    from meta_harness.effectiveness_store import get_effectiveness_score │
│    metric = get_effectiveness_score(skill_id, agent_id).global_score│
│    → Used as DSPy teleprompter optimization target                 │
│                                                                    │
│  Consumption (G2 skill selection):                                 │
│    Same Python API → rank skills by per-agent effectiveness        │
│    → Select top-N most effective skills within context budget      │
└────────────────────────────────────────────────────────────────────┘
```

**Key architectural decisions (resolved):**

- Effectiveness events are agent-emitted (loaded, contributed → sidecar JSONL). A.4 is the aggregator + audit-chain emitter.
- Aggregator runs via manual CLI (`meta-harness score-effectiveness`), programmatically callable.
- Tenant-keyed schema: `tenant_id="default"` in v0.1; field exists from day one.
- Storage granularity: global score + per-agent + per-tenant breakdowns in single payload.
- **Leaf-module discipline:** `effectiveness_store.py` imports only from `charter.audit`, `meta_harness.schemas`, stdlib, and pydantic. No imports from lifecycle modules.

**Relationship to existing A.4 v0.2 pipeline:**

G1 adds no new stages to the 8-stage Meta-Harness driver. It adds:

- New modules (`skill_effectiveness.py`, `skill_adoption.py`, `skill_outcome.py`, `skill_feedback.py`, `effectiveness_store.py`, `effectiveness_compat.py`) called by the aggregator CLI.
- New audit-action constants (SAFETY-CRITICAL substrate touch — same discipline as A.4 v0.2 Tasks 4 + 11).
- New eval cases (5 scenario-based, additive to existing 15).

---

## Tech stack

- **Language:** Python 3.12+ (same as A.4 v0.2)
- **New module paths (A.4-local):**
  - `packages/agents/meta-harness/src/meta_harness/skill_effectiveness.py` — confidence-weighted score computation
  - `packages/agents/meta-harness/src/meta_harness/skill_adoption.py` — adoption tracker (reads sidecar JSONL)
  - `packages/agents/meta-harness/src/meta_harness/skill_outcome.py` — run-outcome correlator (reads sidecar JSONL + audit chain)
  - `packages/agents/meta-harness/src/meta_harness/skill_feedback.py` — CLI feedback parsing (`rate-skill` input)
  - `packages/agents/meta-harness/src/meta_harness/effectiveness_store.py` — Python API + sidecar read/write (LEAF MODULE)
  - `packages/agents/meta-harness/src/meta_harness/effectiveness_compat.py` — backwards-compat handler (graceful degradation)
- **Substrate touches (SAFETY-CRITICAL):**
  - **Task 3:** 6 new audit-action constants in `packages/shared/` or `packages/charter/` (same discipline as A.4 v0.2 Tasks 4 + 11). Action constants: `agent.skill.loaded`, `agent.skill.contributed`, `agent.skill.outcome_correlated`, `agent.skill.operator_rated`, `meta_harness.skill.effectiveness_updated`, `meta_harness.skill.effectiveness_error`.
  - **Task 13:** ADR-007 v1.5 amendment — effectiveness scoring as canonical pattern (if operator determines pattern is heritable by future agents).
  - No `charter.nlah_loader` changes (G2 handles loader extension).
- **Existing dependencies reused:**
  - `charter.llm_adapter` — no LLM consumption in G1 v0.1 (pure computation on audit-chain + sidecar data).
  - `eval-framework` — new eval cases follow existing `MetaHarnessEvalRunner` pattern.
  - F.6 audit chain — read path for outcome events; write path for effectiveness-updated + effectiveness-error events.
- **New storage:**
  - `<workspace>/.nexus/deployed-skills/<agent_id>/<skill_id>/effectiveness.json` — composite score payload.
  - `<workspace>/.nexus/deployed-skills/<agent_id>/<skill_id>/run-events.jsonl` — per-run sidecar telemetry (loaded + contributed events).
- **No new Python dependencies** (G1 is arithmetic + file I/O + audit-chain reads).

---

## Depends on (prior PRs/plans)

- **A.4 v0.2 closure (PR #194).** G1 builds on the skill-lifecycle pipeline (Stages 6-7), audit-action vocabulary (Task 12), sidecar pattern (Task 15), and progressive-disclosure NLAH loader (Task 4).
- **A.4 v0.2 verification record carry-forwards:**
  - CF #2 (silent-swallow): G1 PROVES the fix-pattern with `meta_harness.skill.effectiveness_error` — every error path emits to audit chain, not just `_LOG.warning`. v0.2.5 retrofits this pattern to existing `_safely` helpers.
  - CF #6 (audit-payload compactness): G1 follows the same "decision in chain, detail in sidecar" pattern — `effectiveness_updated` carries score + confidence + axes summary in audit chain; full per-run telemetry lives in `run-events.jsonl`.
  - CF #9 (sidecar store): G1 extends the sidecar pattern to effectiveness telemetry — same idempotent cleanup, same loud-failure-on-absence pattern.
- **Hermes adoption doc (PR #195).** §4.1 defines G1 scope; §5.1 defines dependency chain.
- **DSPy+GEPA strategic doc (PR #181).** §2.2 defines the GEPA `metric=` interface G1 feeds.

---

## Defers (out-of-scope items)

1. **NO per-customer effectiveness isolation.** Uses `tenant_id="default"` until SET LOCAL `$1` tenant-RLS fix lands. Schema is tenant-ready; migration is zero-code (just field value changes).
2. **NO scheduled/automated aggregation.** Manual CLI only in G1 v0.1. Scheduled aggregation deferred to A.4 v0.3 Curator.
3. **NO UI dashboard for effectiveness scores.** Deferred to Phase 2 Surface track. CLI + file-based only in G1.
4. **NO effectiveness-based skill pruning.** That's A.4 v0.3 N3 Curator territory (G4). G1 only produces scores; Curator consumes them.
5. **NO cross-agent effectiveness comparison.** Per-skill scores with per-agent breakdowns; cross-agent ranking is G2's concern (skill selection).
6. **NO GEPA integration in G1.** G1 ships the metric + Python API; v0.2.5 wires it into GEPA. The API interface (`get_effectiveness_score`) is the contract.
7. **NO per-agent weight refinement.** Weights (`0.25/0.35/0.40`) are fixed in G1 v0.1. Per-agent weight tuning deferred to v0.3 when real data justifies it.

---

## Resolved questions

| #      | Question                     | Resolution                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Task       |
| ------ | ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----- |
| G1-Q11 | Storage granularity?         | **D — Global score + per-agent + per-tenant breakdowns in payload.** Single `effectiveness.json` per skill carries `{global_score, by_agent: {agent_id: score}, by_tenant: {tenant_id: score}}`. G2 and v0.2.5 query the same API.                                                                                                                                                                                                                             | 2, 9       |
| G1-Q4  | Tenant scoping?              | **B — Single-tenant storage; tenant-keyed schema from day one.** Uses `tenant_id="default"` until SET LOCAL `$1` fix lands. No migration needed when multi-tenancy opens.                                                                                                                                                                                                                                                                                      | 2, 9       |
| G1-Q3  | Contribution measurement?    | **D — Composite (adoption rate + run-outcome correlation + operator feedback).** Three-axis metric resists single-dimension gaming. Operator feedback is the hardest-to-game axis.                                                                                                                                                                                                                                                                             | 5, 6, 7, 8 |
| G1-Q9  | Composite formula?           | **B — Confidence-weighted.** Starting weights: `w_adoption=0.25`, `w_outcome=0.35`, `w_feedback=0.40`. Per-agent weight refinement deferred to v0.3 when real data justifies. New skills start at confidence=0 and converge as data accumulates.                                                                                                                                                                                                               | 8          |
| G1-Q6  | GEPA integration interface?  | **A — Python API.** `effectiveness_store.get_effectiveness_score(skill_id, agent_id) -> EffectivenessScore`. Leaf-module discipline: `effectiveness_store.py` must NOT import from `skill_lifecycle.py`, `skill_writer.py`, `skill_eval_gate.py`, or `skill_approval.py` (resolves CR-3 circular-import risk).                                                                                                                                                 | 9          |
| G1-Q1  | Storage location?            | **B — Workspace-scoped sidecar.** `<workspace>/.nexus/deployed-skills/<agent_id>/<skill_id>/effectiveness.json`. Mirrors Task 15 candidate-sidecar pattern. Keeps agent repos clean of git-noise from per-run telemetry writes.                                                                                                                                                                                                                                | 9          |
| G1-Q2  | Audit-action namespace?      | **B — Moderate granularity: 6 new actions.** `agent.skill.loaded` + `agent.skill.contributed` (agent-emitted → sidecar JSONL), `agent.skill.outcome_correlated` + `agent.skill.operator_rated` (A.4-emitted → audit chain), `meta_harness.skill.effectiveness_updated` (A.4-emitted → audit chain), `meta_harness.skill.effectiveness_error` (A.4-emitted → audit chain; CF #2 fix-pattern proof). SAFETY-CRITICAL substrate task for shared action constants. | 3          |
| G1-Q8  | Hash-chain granularity?      | **C — State transitions in audit chain; raw telemetry in sidecar JSONL.** `loaded`/`contributed` → `run-events.jsonl`. `outcome_correlated`/`operator_rated`/`effectiveness_updated`/`effectiveness_error` → audit chain with full hash-chain linkage. Aligns with v0.2 verification record CF #6 pattern.                                                                                                                                                     | 3, 4, 12   |
| G1-Q5  | Aggregator trigger?          | **D — Manual CLI for v0.2.5; scheduled deferred to v0.3.** `meta-harness score-effectiveness [--agent <id>] [--skill <id>]`. Programmatically callable (subprocess-friendly exit codes + structured stdout). v0.2.5 GEPA compilation calls it before reading scores. Hermes adoption doc §5.2 recommended exactly this phasing.                                                                                                                                | 11         |
| G1-Q7  | Backwards-compat?            | **A — Degrade gracefully.** Agents not emitting events yield `{global_score: null, confidence: 0.0, reason: "agent_not_emitting_events"}`. Schema `reason` field supports explicit zero-confidence states. Per-agent opt-in is 2-line addition: `emit_agent_skill_loaded` at run start + `emit_agent_skill_contributed` at run end.                                                                                                                            | 10         |
| G1-Q10 | Operator feedback mechanism? | **B — CLI.** `meta-harness rate-skill <skill_id> --useful                                                                                                                                                                                                                                                                                                                                                                                                      | --neutral  | --harmful [--note "..."]`. Programmatically callable. Operator burden minimized by making feedback optional (score works without it; feedback axis contribution drops to zero with `confidence_feedback=0`). | 7, 11 |
| G1-Q12 | G1 eval suite?               | **A — 5 new scenario-based cases (total 20).** Cases: `16_skill_loaded_increments_adoption_axis`, `17_operator_marks_skill_harmful_drops_composite`, `18_non_emitting_agent_yields_zero_confidence`, `19_aggregator_idempotent_under_repeated_invocation`, `20_gepa_api_returns_correct_shape_for_compiled_metric`. Scenario-based names make eval suite self-documenting.                                                                                     | 15         |

---

## Risks

| Risk                                                                                              | Mitigation                                                                                                                                                                                                                                                                                                                                     |
| ------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| G1 effectiveness metric is novel — no prior art for "how effective is a deployed security skill?" | Start simple with fixed weights (`0.25/0.35/0.40`). Composite metric with operator feedback as the hardest-to-game axis. Weights tunable in v0.3 when real data justifies.                                                                                                                                                                     |
| Cold-start: new skills have no effectiveness data                                                 | Confidence-weighted scoring: new skills start at confidence=0; scores converge as data accumulates. GEPA naturally ignores zero-confidence signals during compilation. `reason` field in schema makes zero-confidence reasons explicit and queryable.                                                                                          |
| Operator feedback collection requires UX that doesn't exist                                       | CLI-based (`rate-skill`) — same pattern as Task 15's `approve-skill` / `reject-skill`. Operator burden minimized by making feedback optional — score works without it (feedback axis drops to zero weight when `confidence_feedback=0`). UI deferred to Phase 2 Surface track.                                                                 |
| Agent-emitted events require per-agent code changes (17 agents)                                   | Opt-in design: 2-line addition per agent (`emit_agent_skill_loaded` at start, `emit_agent_skill_contributed` at end). Backwards-compat: non-emitting agents degrade gracefully with `reason="agent_not_emitting_events"`. Migration runbook shipped in NLAH bundle. Agent migration happens during each agent's v0.2+ cycle — not all at once. |
| Audit-chain volume from per-skill per-run events                                                  | G1-Q8-C: raw telemetry (loaded/contributed) → sidecar JSONL, NOT audit chain. Only state transitions (outcome_correlated, operator_rated, effectiveness_updated, effectiveness_error) → audit chain. Per-run events are append-only JSONL; bounded volume per run.                                                                             |
| Effectiveness scores may be gameable (agents load skills unnecessarily to inflate adoption)       | Composite metric resists single-dimension gaming. Adoption is only 25% weight. Operator feedback (40% weight) is hardest to game. Run-outcome correlation (35% weight) requires actual run success — loading a skill doesn't improve outcome if the skill is useless.                                                                          |
| G1 must not regress A.4 v0.2 eval suite                                                           | New eval cases are additive; existing 15 cases run unchanged. WI-1 (substrate sealed) enforced — `git diff --stat packages/charter/ packages/shared/` empty except for Task 3 audit-vocab additions and Task 13 ADR amendment (doc-only).                                                                                                      |
| Circular import: `effectiveness_store.py` ↔ `skill_lifecycle.py`                                  | Leaf-module discipline: `effectiveness_store.py` imports from `charter.audit`, `meta_harness.schemas`, stdlib, and pydantic ONLY. CI enforces via import-linter rule.                                                                                                                                                                          |
| Audit-action namespace collision with existing `meta_harness.skill.*` actions                     | New actions use `agent.skill.*` prefix for agent-emitted events; `meta_harness.skill.*` prefix for A.4-emitted events. Clear naming convention. Existing 8 `meta_harness.*` actions unchanged.                                                                                                                                                 |
| CF #2 silent-swallow gap persists in G1                                                           | G1 PROVES the fix-pattern: `meta_harness.skill.effectiveness_error` emitted on every error path. No `_LOG.warning`-only exceptions. v0.2.5 retrofits this pattern to existing `_safely` helpers.                                                                                                                                               |

---

## Tasks 1-16

| Task | Risk Level                             | Title                                                               | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| ---- | -------------------------------------- | ------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Plan | —                                      | G1 plan doc                                                         | This document. Merged as LOW-RISK doc-only PR.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| 1    | LOW-RISK                               | Bootstrap G1 — version bump + smoke tests                           | Bump A.4 version (`0.2.0` → `0.3.0` per new capability). Smoke tests asserting G1 imports, no regression in existing 15 eval cases, backwards-compat probe for agents without effectiveness events, import-linter rule for leaf-module discipline. ~12 smoke tests.                                                                                                                                                                                                                                                                                                                                                   |
| 2    | LOW-RISK                               | `schemas.py` extension — effectiveness types                        | Add `EffectivenessScore` (global_score, by_agent, by_tenant, confidence, axes_breakdown, reason), `SkillTelemetry` (loaded_at, contributed_at, run_id), `OperatorRating` (rating, note, rated_at, rated_by), `RunOutcomeCorrelation` (run_id, skill_loaded, skill_contributed, run_success) pydantic types. Schema validation for 0-1 score range, confidence interval, reason enum, timestamped ratings. ~12 schema tests.                                                                                                                                                                                           |
| 3    | **SAFETY-CRITICAL**                    | Audit-action vocabulary — 6 new effectiveness actions               | Add shared action constants for `agent.skill.loaded`, `agent.skill.contributed`, `agent.skill.outcome_correlated`, `agent.skill.operator_rated`, `meta_harness.skill.effectiveness_updated`, `meta_harness.skill.effectiveness_error`. Substrate touch — same discipline as A.4 v0.2 Tasks 4 + 11. Includes: action constant definitions, payload pydantic schemas, hash-chain linkage for audit-chain actions (outcome_correlated, operator_rated, effectiveness_updated, effectiveness_error). Sidecar-only actions (loaded, contributed) are defined but NOT hash-chain-linked. ~14 tests. NO auto-merge.          |
| 4    | LOW-RISK                               | Per-agent event emission helpers + sidecar JSONL writer             | Shared utility functions: `emit_agent_skill_loaded(skill_ids: list[str])` and `emit_agent_skill_contributed(skill_ids: list[str])`. Writes to `<workspace>/.nexus/deployed-skills/<agent_id>/<skill_id>/run-events.jsonl` (append-only JSONL). Designed as opt-in — agents call these at run start/end. Migration runbook drafted in this task. ~12 tests.                                                                                                                                                                                                                                                            |
| 5    | LOW-RISK                               | Skill adoption tracker                                              | Reads sidecar `run-events.jsonl` for `loaded` events. Computes per-skill adoption metrics: load count, unique runs, agents loading this skill, time series of adoption. Pure read path; no writes. ~10 tests.                                                                                                                                                                                                                                                                                                                                                                                                         |
| 6    | LOW-RISK                               | Run outcome correlator                                              | Reads sidecar `run-events.jsonl` for `contributed` events + audit chain for run success/failure events. Correlates: "runs where this skill contributed → pass rate." Computes outcome-correlation axis of composite score. ~12 tests.                                                                                                                                                                                                                                                                                                                                                                                 |
| 7    | LOW-RISK                               | Operator feedback parser                                            | Parses `meta-harness rate-skill <skill_id> --useful                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | --neutral | --harmful [--note "..."]`CLI input. Validates rating values. Writes`<workspace>/.nexus/deployed-skills/<agent_id>/<skill_id>/feedback.jsonl`(append-only JSONL, one entry per rating). Emits`agent.skill.operator_rated` to audit chain on each rating. ~10 tests. |
| 8    | LOW-RISK                               | Effectiveness score computer                                        | Confidence-weighted composite formula: `score = (0.25 * adoption * conf_a + 0.35 * outcome * conf_o + 0.40 * feedback * conf_f) / (0.25 * conf_a + 0.35 * conf_o + 0.40 * conf_f)`. Axes with zero confidence drop out of numerator and denominator. Pure computation; no I/O. ~12 tests.                                                                                                                                                                                                                                                                                                                             |
| 9    | LOW-RISK                               | Effectiveness store — Python API + sidecar read/write               | **Leaf module.** Write path: persist `EffectivenessScore` to `<workspace>/.nexus/deployed-skills/<agent_id>/<skill_id>/effectiveness.json`. Read path: `get_effectiveness_score(skill_id, agent_id, tenant_id="default") -> EffectivenessScore`. Imports ONLY from `charter.audit`, `meta_harness.schemas`, stdlib, and pydantic. CI-enforced import-linter rule. ~12 tests.                                                                                                                                                                                                                                          |
| 10   | LOW-RISK                               | Backwards-compat handler                                            | Graceful degradation for non-emitting agents: `{global_score: null, confidence: 0.0, reason: "agent_not_emitting_events"}`. Reason enum: `agent_not_emitting_events`, `insufficient_data`, `operator_marked_archived`, `effectiveness_error_during_aggregation`. Zero-confidence skills are queryable — G2 and v0.2.5 can filter or deprioritize them. ~10 tests.                                                                                                                                                                                                                                                     |
| 11   | LOW-RISK                               | CLI extension — `score-effectiveness` + `rate-skill`                | `meta-harness score-effectiveness [--agent <id>] [--skill <id>]` triggers aggregation. `meta-harness rate-skill <skill_id> --useful                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | --neutral | --harmful [--note "..."]` collects operator feedback. Both commands are programmatically callable (structured stdout, meaningful exit codes). Follows Task 15 CLI pattern. ~15 CLI tests via CliRunner.                                                            |
| 12   | LOW-RISK                               | Audit-chain integration — state-transition events                   | Emits `meta_harness.skill.effectiveness_updated` when composite score changes (carries: skill_id, new_score, previous_score, confidence, axes_breakdown, tenant_id). Emits `meta_harness.skill.effectiveness_error` on aggregation failures (carries: skill_id, error_type, error_detail, stack_trace). Hash-chain linkage for both. Sidecar JSONL events (loaded, contributed) do NOT go to audit chain per G1-Q8-C. ~12 tests.                                                                                                                                                                                      |
| 13   | **SAFETY-CRITICAL** (if ADR amendment) | ADR-007 v1.5 amendment — effectiveness scoring as canonical pattern | If effectiveness scoring becomes a canonical pattern that future agents inherit (Python API contract, sidecar storage pattern, audit-action vocabulary), amend ADR-007 to document the pattern. Doc + code in same PR. SAFETY-CRITICAL per ADR amendment discipline. LOW-RISK if operator determines no amendment needed.                                                                                                                                                                                                                                                                                             |
| 14   | LOW-RISK                               | NLAH bundle update + per-agent migration runbook                    | Update A.4's NLAH persona to reflect effectiveness scoring capability. New example: `05-effectiveness-scoring.md`. `tools.md` updated with new audit-action vocabulary and CLI commands. **Ships per-agent migration runbook:** tells future Wave 1+ agent migrations exactly how to opt in (2-line addition at run start + run end). ~12 tests.                                                                                                                                                                                                                                                                      |
| 15   | LOW-RISK                               | Eval suite extension — 5 new effectiveness cases                    | New scenario-based cases (total 20): `16_skill_loaded_increments_adoption_axis` (loaded event → adoption axis updates), `17_operator_marks_skill_harmful_drops_composite` (harmful rating → score drops), `18_non_emitting_agent_yields_zero_confidence` (no events → null score, reason set), `19_aggregator_idempotent_under_repeated_invocation` (same inputs → same scores), `20_gepa_api_returns_correct_shape_for_compiled_metric` (Python API returns `EffectivenessScore` with `.global_score: float`). Stub harness: no LLM consumption → no stub-LLM responses needed. ~15 eval tests + harness extensions. |
| 16   | LOW-RISK                               | Verification record — G1 closure                                    | Execution-status table, eval acceptance (20/20), watch-items WI-1..WI-5, carry-forwards to G2/v0.2.5. Documents: "G1 closes; effectiveness scoring is real. G2 brainstorm opens next."                                                                                                                                                                                                                                                                                                                                                                                                                                |

---

## File map (target)

```
packages/agents/meta-harness/
├── pyproject.toml                                  # Task 1 (version bump: 0.2.0 → 0.3.0)
├── src/meta_harness/
│   ├── schemas.py                                  # Task 2 (extended — 4 new types)
│   ├── skill_effectiveness.py                      # Task 8 (NEW — score computer)
│   ├── skill_adoption.py                           # Task 5 (NEW — adoption tracker)
│   ├── skill_outcome.py                            # Task 6 (NEW — outcome correlator)
│   ├── skill_feedback.py                           # Task 7 (NEW — feedback parser)
│   ├── effectiveness_store.py                      # Task 9 (NEW — LEAF MODULE; Python API)
│   ├── effectiveness_compat.py                     # Task 10 (NEW — backwards-compat)
│   ├── event_emitters.py                           # Task 4 (NEW — per-agent emit helpers)
│   ├── audit_emit.py                               # Task 3 (extended — 6 new action constants)
│   ├── cli.py                                      # Task 11 (extended — score-effectiveness + rate-skill)
│   ├── agent.py                                    # (unchanged — G1 adds no driver stages)
│   └── nlah/                                       # Task 14 (persona + migration runbook)
│       ├── README.md
│       ├── tools.md
│       └── examples/
│           ├── 04-skill-curation.md
│           └── 05-effectiveness-scoring.md         # NEW
├── eval/
│   ├── cases/                                      # Task 15 (5 new cases; total 20)
│   └── stub_responses/                             # Task 15 (no LLM; no new stubs needed)
└── tests/                                          # Tasks 1-12, 14-15 (per-task test modules)

{packages/shared/src/shared/}                       # Task 3 (SAFETY-CRITICAL — audit-action constants)
{packages/charter/src/charter/}                     # Task 3 (if audit vocab in charter)
docs/_meta/decisions/ADR-007-...md                  # Task 13 (SAFETY-CRITICAL if ADR amendment)
docs/_meta/g1-verification-{date}.md                # Task 16
```

**New workspace paths:**

```
<workspace>/.nexus/deployed-skills/
└── <agent_id>/
    └── <skill_id>/
        ├── effectiveness.json      # Composite score (Task 9 writes)
        ├── run-events.jsonl        # Per-run telemetry (Task 4 appends)
        └── feedback.jsonl          # Operator ratings (Task 7 appends)
```

---

## Watch-items (carry-forward to verification record)

- **WI-1: Substrate sealed except Task 3 + Task 13.** `git diff --stat packages/charter/ packages/shared/` empty across non-substrate tasks. Task 3 bounded to 6 audit-action constant additions. Task 13 bounded to ADR-007 doc amendment (if applicable).
- **WI-2: No regression in A.4 v0.2 eval suite.** Existing 15 cases pass unchanged. 5 new effectiveness cases are additive.
- **WI-3: Deterministic-by-construction effectiveness computation.** No LLM consumption in G1 v0.1. Scores are pure arithmetic on sidecar JSONL + audit-chain data. Stub-LLM not needed for G1 eval cases. Byte-equal probe adapted: same sidecar inputs → same effectiveness.json output.
- **WI-4: Backwards-compat for v0.1 agents.** Agents that don't emit skill-lifecycle events yield `{global_score: null, confidence: 0.0, reason: "agent_not_emitting_events"}`. Not errors. GEPA ignores zero-confidence scores.
- **WI-5: G1→v0.2.5 interface contract.** `effectiveness_store.get_effectiveness_score(skill_id, agent_id) -> EffectivenessScore` is the Python API contract. Leaf-module discipline verified by import-linter CI rule. v0.2.5 plan doc can reference this contract.
- **WI-6: CF #2 fix-pattern proven.** `meta_harness.skill.effectiveness_error` emitted on every error path. v0.2.5 retrofits this pattern to existing `_safely` helpers in `skill_lifecycle.py`.

---

## Done definition

G1 Effectiveness Scoring is **done** when:

- 16/16 tasks closed; every commit pinned in the execution-status table.
- `ruff check` + `ruff format --check` + `mypy --strict` clean.
- Import-linter CI rule passes: `effectiveness_store.py` imports only from allowed modules.
- `meta-harness eval` returns 20/20 (15 original + 5 new effectiveness cases).
- `meta-harness score-effectiveness` runs against the live fleet and produces a valid `EffectivenessScore` per deployed skill.
- `meta-harness rate-skill <id> --useful` updates the composite score on next aggregation.
- `meta-harness rate-skill <id> --harmful` drops the composite score on next aggregation.
- Backwards-compat probe: running `score-effectiveness` against agents without skill-lifecycle events produces `{global_score: null, confidence: 0.0, reason: "agent_not_emitting_events"}`.
- Audit chain carries `effectiveness_updated` and `effectiveness_error` events with valid hash-chain linkage.
- Sidecar JSONL (`run-events.jsonl`, `feedback.jsonl`) is valid append-only JSONL with correct schema.
- Per-agent migration runbook is clear and ship in NLAH bundle.
- Verification record committed; watch-items WI-1 through WI-6 verified.
- **G2 brainstorm is unblocked** — G1 delivers the effectiveness metric; G2 can reference `get_effectiveness_score` for "select top-N most effective skills."

---

## ADR-011 cadence (per-task discipline)

Every numbered task lands as its **own PR** off branches like `feat/g1-task-N-<scope>`. Per ADR-011:

- **LOW-RISK on Tasks 1-2, 4-12, 14-16** (14 tasks) — agent-local changes.
- **SAFETY-CRITICAL on Tasks 3 + 13 only** (at most 2 tasks):
  - Task 3: `packages/shared/` or `packages/charter/` substrate touch — 6 audit-action constants.
  - Task 13: ADR-007 v1.5 amendment — doc + code in same PR (if operator determines amendment needed).
- **NO auto-merge on SAFETY-CRITICAL PRs.** Verified-against-HEAD; manual review.
- **Report → review → merge → next task.** After each task PR opens, pause for review.
- **Execution-status table is single source of truth** for task-commit pinning per ADR-010.

---

## Reference template

Follows [A.4 v0.2 plan doc](2026-05-22-a-4-meta-harness-v0-2.md) (PR #176) for section structure, task granularity, watch-item shape, and done-definition pattern. [A.4 v0.2 verification record](../../_meta/a-4-meta-harness-v0-2-verification-2026-05-23.md) (PR #194) for carry-forward awareness — G1 addresses CF #2 (silent-swallow fix-pattern), CF #6 (audit-payload compactness), CF #9 (sidecar store extension). [Hermes adoption doc](../../_meta/hermes-self-evolution-adoption-2026-05-23.md) §4.1 for G1 fix shape, §5.1 for dependency chain. [DSPy+GEPA strategic doc](../../_meta/dspy-gepa-prompt-optimization-2026-05-22.md) §2.2 for the `metric=` interface G1 feeds. [G1 brainstorm question candidates](../../_meta/g1-brainstorm-questions-draft-2026-05-23.md) for the 12 resolved questions (all resolved in this plan). [G1-G2 dependency map](../../_meta/g1-g2-dependency-map-2026-05-23.md) for cross-cycle constraint awareness (G1-Q4 + G1-Q11 → G2 critical path).
