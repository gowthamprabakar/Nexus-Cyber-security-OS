# G2 Skill Selection — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Pause for review after each numbered task.

**Goal:** Ship **G2 Skill Selection** — the runtime layer that selects which deployed skills an agent loads per run, using G1 effectiveness data as the selection signal. G2 answers: "which skills should this agent load for THIS run?"

G1 answers "how effective is each skill?" G2 answers "which effective skills fit this context?" G2 is the second prerequisite gap per the [Hermes adoption doc](../../_meta/hermes-self-evolution-adoption-2026-05-23.md) §4.1. Without skill selection, Wave 1 agents accumulate skills and context windows overflow. G2 prevents context-window exhaustion by selecting top-N most effective + relevant skills per run.

**Scope (G2 v0.1):**

1. **Dual-mode dispatch.** Autonomous runs (EVENTS_BUS, SCHEDULED_QUEUE) select skills once at run start. Interactive runs (OPERATOR_CLI) re-select per user turn. Requires propagating `trigger_source` from Supervisor's `IncomingTask` → `ExecutionContract` → downstream agents.
2. **Hermes-pattern selection — LLM-driven, no embeddings.** Extend Level 0 NLAH metadata index with G1 effectiveness data per skill (`effectiveness_score`, `confidence`, `last_updated`). The LLM reads enriched metadata and selects skills naturally based on task + effectiveness signal. No embeddings infrastructure. No RAG. No vector store. No separate ranking algorithm. The LLM is the selection layer.
3. **Effectiveness signal wiring.** Wire `get_effectiveness_score()` from G1 into Level 0 metadata generation. Skills with zero-confidence scores (new, unproven, or non-emitting agents) are included with `confidence=0` — the LLM decides whether to load them (safe default: include all unproven skills; excludes nothing that might be useful).
4. **Per-agent NLAH persona update.** All 17 agents get a "skill selection guidance" section in their NLAH persona template, telling the LLM how to use the enriched metadata to select skills.
5. **Eval suite.** Verify LLM selects high-effectiveness skills more often than baseline. No G1-style arithmetic cases — G2 selection is LLM-dependent.

---

## Architecture overview

```
┌────────────────────────────────────────────────────────────────────┐
│ G2 Skill Selection                                                 │
│                                                                    │
│  Supervisor (#0) — trigger_source propagation:                     │
│    IncomingTask.trigger_source                                     │
│      → DelegationContract                                          │
│        → ExecutionContract.trigger_source                          │
│          → Charter (runtime context)                               │
│                                                                    │
│  Agent runtime — per-run selection:                                │
│    Autonomous (EVENTS_BUS / SCHEDULED_QUEUE):                      │
│      Run start → load_skill_metadata_index()                       │
│        → enriched Level 0 with G1 scores                           │
│        → LLM selects top-N skills for entire run                   │
│                                                                    │
│    Interactive (OPERATOR_CLI):                                     │
│      Per user turn → load_skill_metadata_index()                   │
│        → LLM re-selects based on turn context                      │
│                                                                    │
│  charter.nlah_loader v1.5 — Level 0 enrichment:                    │
│    SkillMetadataEntry extended:                                    │
│      effectiveness_score: float | None                             │
│      confidence: float                                             │
│      last_updated: str | None                                      │
│    Read path:                                                      │
│      G1's get_effectiveness_score(skill_id, agent_id)              │
│      → injected into metadata for each skill entry                 │
│                                                                    │
│  Agent NLAH persona — skill selection guidance:                    │
│    "You have N skills available. Each has an effectiveness         │
│     score (0-1) with confidence. Higher scores = more proven.      │
│     Select skills relevant to the current task, prioritizing       │
│     high-effectiveness skills. Include unproven skills if          │
│     they're relevant."                                             │
└────────────────────────────────────────────────────────────────────┘
```

**Key architectural decisions (resolved):**

- **Hermes-pattern, not RAG.** The LLM reads enriched metadata and selects skills — same progressive-disclosure pattern as `load_skill_metadata_index` (Level 0 → Level 1). No ChromaDB, no pgvector similarity, no embeddings. The LLM is the selection layer per the Hermes adoption doc §3 (`skill_curator` row: "adopt that semantic model; rebuild on Nexus substrate").
- **Dual-mode dispatch.** Autonomous runs select once (stable context). Interactive runs re-select per turn (context shifts with each user message). The `trigger_source` field on `ExecutionContract` enables this distinction.
- **Zero-confidence = include, don't exclude.** Unproven skills get `effectiveness_score=None, confidence=0.0`. The LLM sees this and can still load them — conservative default prevents accidentally dropping valuable new skills.
- **No scheduled aggregation.** G2 reads G1's `get_effectiveness_score()` as-is. If scores are stale (G1-Q5: manual CLI only), G2 reads what's available. Staleness handling is a G2 v0.2 concern.
- **Per-agent granularity inherited from G1.** G2 queries `by_agent[agent_id]` from the `EffectivenessScore` payload. Per-agent selection is the primary axis.

**Relationship to existing pipeline:**

G2 adds no new agent driver stages. It extends:

- `charter.contract.ExecutionContract` — new `trigger_source` field (SAFETY-CRITICAL substrate touch).
- `charter.nlah_loader` — Level 0 `SkillMetadataEntry` extended with effectiveness fields; `load_skill_metadata_index` gains an optional `effectiveness_provider` callable.
- Supervisor's `_build_contract()` — propagates `task.trigger_source` into the contract.
- 17 agent NLAH README files — new "skill selection guidance" section.

---

## Tech stack

- **Language:** Python 3.12+ (same as G1)
- **Substrate touches (SAFETY-CRITICAL):**
  - **Task 2:** `packages/charter/src/charter/contract.py` — add `trigger_source: str | None = None` to `ExecutionContract`. Backwards-compat: optional field; defaults to `None` for legacy paths.
- **Existing modules extended:**
  - `packages/charter/src/charter/nlah_loader.py` — `SkillMetadataEntry` extended with 3 effectiveness fields; `load_skill_metadata_index` gains optional `effectiveness_provider` parameter.
  - `packages/agents/supervisor/src/supervisor/agent.py` — `_build_contract()` propagates `task.trigger_source.value`.
- **Existing dependencies consumed:**
  - `meta_harness.effectiveness_store.get_effectiveness_score()` — G1's Python API is the effectiveness data source.
  - `charter.llm_adapter` — LLM-driven selection (same adapter all agents use).
  - F.6 audit chain — G2 emits `agent.skill.selected` / `agent.skill.skipped` per G1-Q2 namespace precedent.
- **No new Python dependencies.**
- **No embeddings infrastructure.** No ChromaDB. No pgvector similarity. No RAG.
- **No new workspace paths.** G2 reads from existing `.nexus/deployed-skills/` (G1) and `<agent>/nlah/skills/` (A.4 v0.2).

---

## Resolved questions

| #     | Question                 | Resolution                                                                                                                                                                                                                                                                                                        | Task    |
| ----- | ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| G2-Q1 | Selection trigger point? | **E — Dual-mode dispatch.** Autonomous runs (EVENTS_BUS, SCHEDULED_QUEUE) → one selection at run start. Interactive runs (OPERATOR_CLI) → re-selection per user turn. Requires propagating `trigger_source` from Supervisor → `ExecutionContract` → downstream agents.                                            | 2, 3    |
| G2-Q2 | Selection mechanism?     | **Hermes-pattern — LLM-driven via enriched Level 0 metadata.** Extend `SkillMetadataEntry` with G1 effectiveness fields. LLM reads enriched metadata; selects skills based on task + effectiveness signal. No embeddings, no RAG, no vector store, no separate ranking algorithm. The LLM is the selection layer. | 4, 5, 6 |

---

## Depends on (prior PRs/plans)

- **G1 effectiveness scoring (PRs #196-#213).** G2 consumes `get_effectiveness_score()`. The Python API contract defined by G1-Q6 is the seam.
- **A.4 v0.2 (PR #194).** `charter.nlah_loader` v1.4 provides the progressive-disclosure pattern G2 extends. Skill registry + sidecar pattern are the storage foundation.
- **Supervisor v0.1 (PR #166).** `IncomingTask.trigger_source` + `TriggerSource` enum are the field + type G2 propagates.
- **ADR-007 v1.5 (PR #210).** Canonical effectiveness-scoring patterns — G2 inherits the Python API contract, sidecar storage pattern, and audit-action vocabulary namespace.
- **Hermes adoption doc (PR #195).** §4.1 defines G2 scope; §5.1 defines dependency chain.
- **G1 verification record (PR #213).** Carry-forwards G1-CF1 through G1-CF8 constrain G2 design (leaf-module discipline, CF #2 fix-pattern, tenant-keyed schema).

---

## Defers (out-of-scope items)

1. **NO embeddings infrastructure.** Hermes-pattern doesn't need it. LLM-driven selection uses metadata enrichment, not vector similarity.
2. **NO RAG / vector store.** Same rationale — the LLM is the selection layer.
3. **NO separate ranking algorithm.** The LLM selects skills; there's no pre-ranking step.
4. **NO per-tool-call selection granularity.** Selection is per-run (autonomous) or per-turn (interactive). Per-tool-call selection deferred to v0.3+ if needed.
5. **NO cross-agent selection coordination.** Each agent selects its own skills independently. Cross-agent coordination deferred to v0.3+.
6. **NO scheduled aggregation of effectiveness scores.** Locked as G1-Q5 → v0.3 Curator. G2 reads whatever G1 provides.
7. **NO per-agent weight tuning.** Locked as G1-CF1 → v0.3. G2 uses G1's fixed weights (0.25/0.35/0.40).
8. **NO skill pruning based on effectiveness.** That's G4 (A.4 v0.3 Curator). G2 only SELECTS; doesn't prune.

---

## Cross-cycle design rules

Inherited from G1 verification record carry-forwards and G2 brainstorm:

- **Leaf-module discipline.** Any new G2 modules must not import from `skill_lifecycle.py`, `skill_writer.py`, `skill_eval_gate.py`, or `skill_approval.py`. Inherits G1's import-linter rule.
- **CF #2 fix-pattern.** Any new G2 code paths emit `effectiveness_error` audit action on failure, not bare `_LOG.warning`. Same pattern as G1.
- **No embeddings / no RAG / no vector store.** Explicitly out-of-scope per operator directive. Hermes-pattern is the chosen architecture; over-engineering is forbidden.
- **Tenant-keyed schema from day one.** Any new fields default to `tenant_id="default"` until SET LOCAL `$1` fix lands. Same as G1.
- **`trigger_source` is OPTIONAL on `ExecutionContract`.** Backwards-compat with existing contracts that don't have it. Defaults to `None` for legacy paths (non-Supervisor invocations, eval harness, CLI direct).
- **Zero-confidence = include, don't exclude.** Unproven skills are not filtered out. The LLM sees them with `confidence=0.0` and decides. Conservative default prevents dropping valuable new skills.

---

## Risks

| Risk                                                   | Mitigation                                                                                                                                                                                                                                   |
| ------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| LLM-driven selection is non-deterministic              | Dual-mode dispatch bounds variance: autonomous runs select once (stable); interactive runs re-select naturally (context shifts). G2 eval cases use `MetaHarnessEvalRunner` with stub LLM responses — same WI-3 pattern as A.4 v0.2.          |
| `trigger_source` propagation touches substrate         | Bounded to ONE field addition on `ExecutionContract` — `trigger_source: str \| None = None`. Backwards-compat by default (optional, defaults to `None`). SAFETY-CRITICAL review per ADR-011; no auto-merge.                                  |
| Zero-confidence skills overwhelm LLM context           | LLM sees effectiveness scores and can deprioritize zero-confidence skills. But unproven skills are not excluded — the LLM may still load them if relevant. Context budget is the LLM's responsibility, not a hard filter.                    |
| G2 selection depends on G1 scores being populated      | Cold-start: new deployments have no effectiveness data. G1 handles this gracefully (`confidence=0.0, reason="insufficient_data"`). G2's "include zero-confidence" policy means selection still works — just without effectiveness signal.    |
| 17 agents need NLAH persona updates                    | Task 6 updates all 17 agent README files consistently. Template-driven — one canonical section replicated with per-agent customization. ~17 files touched but all are doc-only changes.                                                      |
| G2 must not regress G1 eval suite                      | G2 eval cases are additive. Existing 20 cases pass unchanged. G1 cases 16-20 (pure arithmetic) are unaffected — G2 doesn't touch the scoring pipeline.                                                                                       |
| `charter.nlah_loader` extension risks circular imports | `effectiveness_provider` is an optional callable injected at call site — `load_skill_metadata_index` never imports from `meta_harness`. The provider is constructed by the agent's driver, not the loader. Leaf-module discipline preserved. |

---

## Tasks 1-8

| Task | Risk Level          | Title                                                                       | Description                                                                                                                                                                                                                                                                                                                                            |
| ---- | ------------------- | --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Plan | —                   | G2 plan doc                                                                 | This document. Merged as LOW-RISK doc-only PR.                                                                                                                                                                                                                                                                                                         |
| 1    | LOW-RISK            | Bootstrap G2 — version bump + smoke tests                                   | Bump A.4 version (`0.3.0` → `0.4.0` per new capability). Smoke tests asserting G2 imports, no regression in existing 20 eval cases, backwards-compat probe for `ExecutionContract` without `trigger_source`, import-linter rule for leaf-module discipline. ~12 smoke tests.                                                                           |
| 2    | **SAFETY-CRITICAL** | Extend `ExecutionContract` with `trigger_source` field                      | Add `trigger_source: str \| None = None` to `charter.contract.ExecutionContract`. Backwards-compat: optional field; `None` for legacy paths (non-Supervisor invocations, eval harness, CLI direct). Substrate touch — same discipline as G1 Task 3. ~10 tests. NO auto-merge.                                                                          |
| 3    | LOW-RISK            | Propagate `trigger_source` in Supervisor `_build_contract()`                | Copy `task.trigger_source.value` into the `ExecutionContract` when Supervisor builds delegation contracts at `packages/agents/supervisor/src/supervisor/agent.py:264-275`. Agent-local change. ~8 tests.                                                                                                                                               |
| 4    | LOW-RISK            | Extend `charter.nlah_loader` Level 0 metadata with effectiveness fields     | Add `effectiveness_score: float \| None`, `confidence: float`, `last_updated: str \| None` to `SkillMetadataEntry`. Add optional `effectiveness_provider: Callable[[str, str], EffectivenessScore \| None] \| None` parameter to `load_skill_metadata_index`. Provider is injected at call site — loader never imports from `meta_harness`. ~12 tests. |
| 5    | LOW-RISK            | Wire G1 `get_effectiveness_score()` into Level 0 metadata generation        | Agent drivers construct the `effectiveness_provider` by importing `meta_harness.effectiveness_store.get_effectiveness_score` and partially applying `workspace_root`. Single call site per agent. ~10 tests.                                                                                                                                           |
| 6    | LOW-RISK            | Update agent NLAH persona template — add "skill selection guidance" section | Add a standardized "Skill Selection" section to all 17 agent NLAH README files. Template-driven: one canonical section replicated with per-agent customization (relevant skill categories, context-budget hints). Tells the LLM how to read enriched metadata and select skills. ~17 doc updates + validation tests.                                   |
| 7    | LOW-RISK            | Add eval cases verifying LLM selects high-effectiveness skills more often   | New scenario-based cases (total 22+): `21_high_effectiveness_skills_selected_more_often`, `22_zero_confidence_skills_not_excluded`. Stub-LLM harness: canned responses simulate "selects high-effectiveness" and "includes unproven" paths. ~10 eval tests + harness extensions.                                                                       |
| 8    | LOW-RISK            | G2 verification record + closure                                            | Execution-status table, eval acceptance (22/22), watch-items verification, carry-forwards to v0.3/G3. Documents: "G2 closes; skill selection is real. v0.2.5 DSPy+GEPA is unblocked."                                                                                                                                                                  |

---

## File map (target)

```
packages/charter/src/charter/
├── contract.py                              # Task 2 (extended — trigger_source field)
├── nlah_loader.py                           # Task 4 (extended — SkillMetadataEntry + effectiveness_provider)

packages/agents/supervisor/src/supervisor/
├── agent.py                                 # Task 3 (extended — _build_contract propagates trigger_source)

packages/agents/meta-harness/src/meta_harness/
├── skill_selection.py                       # Task 5 (NEW — effectiveness_provider factory)
├── __init__.py                              # Task 1 (version bump: 0.3.0 → 0.4.0)
├── nlah/                                    # Task 6 (persona template update)
│   └── README.md

packages/agents/{all 17 agents}/
└── src/{agent}/nlah/README.md               # Task 6 (per-agent skill selection guidance)

packages/agents/meta-harness/tests/          # Tasks 1-8 (per-task test modules)
packages/agents/meta-harness/eval/cases/     # Task 7 (2 new cases; total 22)
```

**No new workspace paths.** G2 reads from existing G1 paths:

```
<workspace>/.nexus/deployed-skills/
└── <agent_id>/
    └── <skill_id>/
        ├── effectiveness.json      # G2 reads (G1 writes)
        ├── run-events.jsonl        # (unchanged)
        └── feedback.jsonl          # (unchanged)
```

---

## Watch-items (carry-forward to verification record)

- **WI-1: Substrate sealed except Task 2.** `git diff --stat packages/charter/ packages/shared/` empty across Tasks 1, 3-8. Task 2 bounded to ONE optional field addition on `ExecutionContract` (`trigger_source: str | None = None`).
- **WI-2: No regression in G1 eval suite.** Existing 20 cases pass unchanged. 2 new G2 cases are additive.
- **WI-3: Deterministic under stub-LLM.** G2 selection is LLM-driven but eval cases use stub-LLM canned responses — same WI-3 pattern as A.4 v0.2. Byte-equal probe: same stub responses → same selection outcomes.
- **WI-4: Backwards-compat for legacy ExecutionContracts.** `trigger_source` is optional (`None` default). Contracts without the field parse and execute unchanged. Non-Supervisor invocations (eval harness, CLI direct) are unaffected.
- **WI-5: Leaf-module discipline preserved.** `nlah_loader.py` never imports from `meta_harness`. The `effectiveness_provider` is injected at call site. Import-linter CI rule verifies.
- **WI-6: Hermes-pattern fidelity.** No embeddings, no RAG, no vector store, no separate ranking algorithm. The LLM is the selection layer. CI grep asserts zero imports of `chromadb`, `pgvector`, `numpy.linalg`, `sklearn`.

---

## Done definition

G2 Skill Selection is **done** when:

- 8/8 tasks closed; every commit pinned in the execution-status table.
- `ruff check` + `ruff format --check` + `mypy --strict` clean.
- Import-linter CI rule passes: `nlah_loader.py` imports only from allowed modules (no `meta_harness`).
- WI-6 grep: zero imports of `chromadb`, `pgvector`, `numpy.linalg`, `sklearn` in G2 code paths.
- `meta-harness eval` returns 22/22 (20 original + 2 new G2 selection cases).
- `ExecutionContract` parses cleanly with AND without `trigger_source` field (backwards-compat).
- Supervisor `_build_contract()` copies `trigger_source` into the contract.
- `load_skill_metadata_index` with `effectiveness_provider` returns enriched `SkillMetadataEntry` tuples.
- All 17 agent NLAH README files carry the "Skill Selection" guidance section.
- Stub-LLM eval cases verify: high-effectiveness skills selected more often; zero-confidence skills not excluded.
- Verification record committed; watch-items WI-1 through WI-6 verified.
- **v0.2.5 DSPy+GEPA is unblocked** — G2 delivers skill selection; v0.2.5 can assume context budget is managed.

---

## ADR-011 cadence (per-task discipline)

Every numbered task lands as its **own PR** off branches like `feat/g2-task-N-<scope>`. Per ADR-011:

- **LOW-RISK on Tasks 1, 3-8** (7 tasks) — agent-local or doc-only changes.
- **SAFETY-CRITICAL on Task 2 only** (1 task):
  - Task 2: `packages/charter/src/charter/contract.py` substrate touch — one optional field addition (`trigger_source: str | None = None`).
- **NO auto-merge on SAFETY-CRITICAL PR.** Verified-against-HEAD; manual review.
- **Report → review → merge → next task.** After each task PR opens, pause for review.
- **Execution-status table is single source of truth** for task-commit pinning per ADR-010.

---

## Reference template

Follows [G1 plan doc](2026-05-24-g1-effectiveness-scoring.md) for section structure, task granularity, watch-item shape, and done-definition pattern. [G1-G2 dependency map](../../_meta/g1-g2-dependency-map-2026-05-23.md) for cross-cycle constraint awareness (all G1 resolutions that constrain G2 design space are resolved favorably — G1-Q11 Option D enables per-agent ranking; G1-Q6 Python API is the natural seam; G1-Q8 hash-chain pattern extends cleanly to G2 selection events). [G1 verification record](../../_meta/g1-effectiveness-scoring-verification-2026-05-25.md) for carry-forwards inherited by G2. [Hermes adoption doc](../../_meta/hermes-self-evolution-adoption-2026-05-23.md) §4.1 for G2 prerequisite identification, §3 `skill_curator` row for Hermes-pattern adoption rationale.
