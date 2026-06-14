# v0.3 / Phase D — Track C Cycle C-2 recon (Hermes Phase 1 across the LLM trio) — 2026-06-14

> **Status:** Recon findings (doc-only, NO code). Per the directive, C-2 findings are surfaced
> for operator decision BEFORE coding (mirror the A-1/A-2 fork pattern). Three forks below.

## 1. Decisive finding — the pipeline already exists; do NOT rebuild

Hermes Phase 1 skill-creation was **already rebuilt** as A.4 meta-harness (adoption-doc §3
"REBUILD (already done)"). The full **trace → skill candidate → storage** pipeline exists,
production-grade:

- `skill_triggers.detect_skill_trigger()` (the trace→trigger half; pure stdlib; already
  decoupled from the registry — caller passes the deployed-hash set).
- `skill_writer.write_skill_candidate()` (trigger→candidate; only needs `charter.llm` +
  `skill_format`; trust-boundary overrides force CANDIDATE/NOT_RUN/provenance).
- `skill_eval_gate` + `skill_registry` (quality gate + deployment authority + first-of-class gate).
- `dspy_skill_creator` (C-1's parallel DSPy composer, adjudicated against the legacy writer).

A new `packages/runtime/hermes/` that re-implements composition would **duplicate** this and
drift. So C-2's real, net-new contribution is narrower:

1. **A SemanticStore-backed candidate store.** meta-harness stores candidates on the
   **filesystem** (`skill_candidate_store.py`, `.nexus/`), NOT in SemanticStore. The directive's
   "candidate → SemanticStore + cross-session retrieval" is a store backend meta-harness lacks.
2. **Wiring the trio's existing audit-chain traces into candidate emission.** All three trio
   agents (synthesis/investigation/curiosity) already run under `Charter` (→ an audit chain in
   the exact `Mapping[str,Any]` shape `detect_skill_trigger` consumes) and already
   `upsert_entity` to SemanticStore via their `kg_writer.py` — but none does skill-creation today.

**Precedent:** `nexus_runtime.llm_invariants` (the P3-2 hoist) is the exact pattern — generalizable
trio code lives in `packages/runtime/` (non-substrate), imported by all three. A `hermes/` module
beside it fits.

## 2. The LLM-trio template (confirmed near-identical)

`Charter` ctx → INGEST → LLM-narrate (`charter.llm` via per-agent narrator/synthesizer/hypothesizer

- `providers/` fallback) → assert `nexus_runtime.llm_invariants` → write OCSF/markdown → `upsert_entity`
  to SemanticStore → `assert_complete()`. None of the three does skill-creation today.

## 3. Three forks for operator decision (BEFORE coding)

### Fork C2-A — architecture (hoist vs copy vs reuse)

- **(A1) Hoist (RECOMMENDED):** move the generalizable primitives (`detect_skill_trigger`,
  `write_skill_candidate`) into `nexus_runtime/hermes/`; meta-harness re-imports them (byte-identical,
  additive — the `llm_invariants` move exactly). Add the net-new SemanticStore candidate store there.
  Single composition source of truth; no agent→agent dep. _Cost:_ a cross-package refactor of
  meta-harness import paths (per-PR-reviewed).
- **(A2) Copy:** put a thin generalized variant in `hermes/` without touching meta-harness. Avoids
  the refactor but risks two composition implementations drifting (the exact thing the REBUILD
  verdict warned against).
- **(A3) Reuse meta-harness directly:** the trio imports `meta_harness.skill_writer`. Zero
  duplication but creates an **agent→agent dependency** (the fleet hoists shared code to
  charter/shared/runtime, never agent-to-agent) + pulls eval_framework/GEPA weight into the trio.
  Not recommended.

### Fork C2-B — trigger tuning for narration agents

`detect_skill_trigger`'s `MIN_TOOL_CALL_COUNT=5` was tuned for tool-heavy agents. The trio's work
flows through `narrator`/`synthesizer`/`hypothesizer` (mostly NOT `ctx.call_tool`), so their audit
chains may carry few `tool_name` entries → the trigger may rarely fire. Options: (B1) lower the
threshold for the trio; (B2) count LLM-stage entries, not just tool calls; (B3) keep as-is and
accept that triggers fire only on tool-heavy runs.

### Fork C2-C — deployment authority (recommended default; confirm)

**Recommended:** trio candidates are **proposals** stored in SemanticStore; meta-harness's eval-gate

- C-1 DSPy adjudication remains the **sole deployment authority** (the trio gets NO deploy path).
  This preserves the A.4 first-of-class operator gate and avoids a second, ungated deployment surface.
  Confirm, or specify a different integration with meta-harness's legacy-vs-DSPy adjudication.

## 4. Substrate + review scope

- **Substrate (#19/#29) CLEAR for all options:** `nexus_runtime/hermes/` is non-substrate; a new
  `"skill_candidate"` SemanticStore `entity_type` needs no charter/shared edit (free-string type,
  like the trio's existing entity types). The one watch-item: (A1) hoist moves code within
  meta-harness + runtime (both non-substrate) — still no charter/shared edit, but it's a
  cross-package refactor → its own per-PR-reviewed PR.
- **Per-PR review:** the `hermes/` module + any hoist + the SemanticStore candidate-store design.
  **Cascade (agent-local):** each trio agent's thin end-of-run `detect→write→upsert` wiring + its
  `"skill_candidate"` entity type + tests.

## 5. References

- Hermes adoption doc — `hermes-self-evolution-adoption-2026-05-23.md` §3 (REBUILD-already-done) + §10 re-check.
- `nexus_runtime/llm_invariants/__init__.py` — the P3-2 hoist precedent.
- meta-harness `skill_triggers.py` / `skill_writer.py` / `skill_candidate_store.py` / `dspy_skill_creator.py`.
- `charter/memory/semantic.py` (`upsert_entity` / `list_entities_by_type`).
- v0.3 / Phase D directive — Track C C-2.
