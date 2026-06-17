# ADR-021 — Skill-trace persistence (T2) for the Hermes DSPy loop

**Status:** Accepted (2026-06-18) · **Cycle:** v0.4 Stage 2 (Hermes Phase 4a) · **Decides:** operator Q3 (Hermes brainstorm #749). **Substrate change** — trigger #19 (substrate) + #48 (graph/memory substrate) pattern, same as ADR-018/019/020; per-PR review.

## Context

The DSPy/GEPA skill-improvement machinery (charter `dspy_compiler` + meta-harness
`gepa_adapter` / `dspy_skill_creator` / `compilation_cadence`) is built and live but
**default-OFF** (`NEXUS_DSPY_PRODUCTION`). The load-bearing reason it stays off: GEPA needs a
**multi-example** trainset to produce any optimization signal, but deployed skills persist only
a provenance _hash_, not their **originating trace**. Every compilation therefore assembles a
1-example trainset → no signal (measured ~0 delta in the A.4 v0.2.5 quality-delta report).
"T2 trace persistence" is the unblock: persist each deployed skill's originating trace so
trainset assembly can pull N scored `(skill_id, trace)` examples.

## Decision

Persist skill originating-traces as a **typed store over the existing `SemanticStore`
`entities` table** — `entity_type="skill_trace"`, keyed `(agent_id, skill_id)`:

- New module **`charter/memory/skill_trace.py`** — `SkillTraceStore` (`record_trace` /
  `list_traces`) + `SkillTraceExample`. Tenant-scoped (every op pins `customer_id`, ADR-007);
  opt-in/inert when no store (mirrors the kg-writer-base contract).
- **No new table, no alembic migration.** The substrate touch is this additive charter module
  - the `skill_trace` entity-type convention. (Option A in the T2 recon — chosen over a
    dedicated `skill_traces` table to keep the change lightweight + avoid a charter↔meta-harness
    schema coupling; a native table + index is a v0.5 option if scale demands it.)

Trace properties stored: `agent_id`, `skill_id`, `category`, `trace` (the text), `audit_hashes`
(the existing provenance), `effectiveness_score` (for the Q5-a trainset pre-filter).

## Consequences

- **Un-starves GEPA**: `list_traces(agent_id, category)` is the N-example source the
  meta-harness trainset assembly consumes (the immediate self-merge follow-up PR, sequenced
  via main — substrate-first per the standing rule).
- **No production-by-faith**: this ships the _capability_ only. `NEXUS_DSPY_PRODUCTION` stays
  default-OFF; the flip remains a separate operator go after a measured GEPA delta + Task-14
  Anthropic validation (Q2). Gate 3 (quality cadence) is a separate formal flip-criterion (Q5).
- **Backfill caveat**: existing deployed skills have no persisted trace; the benefit accrues as
  new skills deploy (the deploy path records going forward).
- Substrate seal: this is the **one** authorized substrate touch of the Hermes work (per-PR
  review); Phases 4b/2/5 are seal-empty.
