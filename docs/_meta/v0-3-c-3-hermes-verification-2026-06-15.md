# Track C · C-3 PR1 — Hermes Phase 1 end-to-end verification (2026-06-15)

## Purpose

C-2 (PRs #680/#682/#683/#684) adopted Hermes Phase 1 across the LLM-narration trio
(D.13 synthesis / D.7 investigation / D.12 curiosity): each agent's `run()` ends
with `_propose_skill_candidate`, which reads the run's audit chain, runs the hoisted
`detect_skill_trigger(include_llm_stages=True)`, and on a novel LLM-stage workflow
upserts a `skill_candidate` entity into the cross-session `SemanticStore`
(proposer-only — C2-C; the meta-harness eval-gate + C-1 adjudication remain the
sole deploy authority).

The C-2 cycle shipped two layers of tests:

- `nexus_runtime/tests/test_hermes_candidate_store.py` — the `upsert_skill_candidate`
  helper against an **in-memory fake** store (canary-clean: no `charter` import in
  `nexus_runtime`).
- `packages/agents/{synthesis,investigation,curiosity}/tests/test_skill_proposal.py`
  — each agent's `_propose_skill_candidate` against an **`AsyncMock`** store
  (asserts the call shape: entity_type, tenant, external_id, properties).

Neither layer proved the **full loop against a real `SemanticStore`** — that a
proposed candidate actually persists and is retrievable by the cross-session query
path the meta-harness consumes.

## What C-3 PR1 adds

`packages/agents/{synthesis,investigation,curiosity}/tests/test_skill_proposal_e2e.py`
— one verification suite per trio agent, each driving `_propose_skill_candidate`
against a **real `SemanticStore`** (in-memory aiosqlite, `Base.metadata.create_all`),
asserting:

1. **Persistence + retrievability** — after a ≥5-LLM-stage run, exactly one
   `skill_candidate` row is returned by
   `store.list_entities_by_type(entity_type="skill_candidate")` (the query path the
   meta-harness uses), with `external_id` `=<agent>:<tool_sequence_hash>` and the
   categorical/hash properties (`agent_id`, `run_id`, `tool_sequence_hash`).
2. **Idempotency / cross-session reuse** — proposing the same workflow twice merges
   on `(tenant_id, "skill_candidate", external_id)` → still one row (no duplication
   across runs/sessions).
3. **Threshold floor** — a sub-threshold run (4 LLM stages) persists nothing.

## Result

`9 passed` (3 per agent). The C-2 Hermes Phase 1 loop is verified end-to-end against
the production `SemanticStore`, not just mocks: audit → `detect_skill_trigger` →
`upsert_skill_candidate` → queryable KG row, idempotent across runs.

## Scope / honesty

- **Additive tests + doc only.** No `src` change; substrate seal EMPTY; no behaviour
  change. The trio remains proposer-only (empty `deployed_tool_sequence_hashes`).
- **What this does NOT prove:** that proposed candidates are _consumed_ by the
  meta-harness eval-gate into deployments. That is the C-1 factory path
  (`make_default_dspy_factory`), which is gated default-OFF and remains blocked from
  a real production flip by the recorded v0.2.5 flag-flip gates (T2 trace
  persistence + Task-14 Anthropic switch-validation). C-3 PR2 records the activation
  surface and those gates explicitly; this PR1 only proves the _proposal_ half is
  live and durable.
