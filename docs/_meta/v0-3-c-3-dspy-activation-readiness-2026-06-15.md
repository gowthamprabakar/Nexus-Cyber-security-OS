# Track C · C-3 — DSPy self-improvement activation readiness + cycle close (2026-06-15)

This record closes cycle **C-3**. It documents the production-activation surface for
the DSPy compilation loop (the volume cadence + flag), the gates that keep it
default-OFF in v0.3, and **why C-3 collapsed from 4 PRs to 1 code PR + this record.**

## C-3 as planned vs. as verified against `main`

The close-stretch directive pre-authorized C-3 as a 4-PR self-merge cascade:
PR1 Hermes verification · PR2 DSPy flag activation · PR3 volume cadence · PR4 close.

Recon against actual `main` (not memory) found that **PR2 and PR3 are already shipped**
by C-1 (#662) + the v0.2.5 cycle. Manufacturing duplicate code PRs would be ceremony,
which the close-stretch discipline forbids ("verify against actual main; no heroics").
So C-3 is delivered as:

- **PR1 (#703)** — genuine net-new: end-to-end verification of the Hermes Phase 1
  proposal loop against a real `SemanticStore` (the C-2 gap; the proposal was only
  tested vs. fakes/mocks).
- **This record** — the activation runbook + gate ledger + cycle close (collapses the
  literal PR2/PR3/PR4, which had no honest net-new code).

## What is already wired on `main` (PR2 + PR3, verified)

The DSPy compilation loop is fully wired, default-OFF, behind the standard
`NEXUS_*`-gate idiom the rest of the fleet uses.

| Concern (directive label)                                              | Where it lives                                                                                                                   | Tests proving it                                                                                                                             |
| ---------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| **Gate 1 — flag activation** (`NEXUS_DSPY_PRODUCTION`)                 | `compilation_factory.make_default_dspy_factory` → returns `None` unless `=1`; wired into `agent.run()` (lines ~197-217)          | `test_default_factory_disabled_when_flag_unset`, `test_default_factory_enabled_when_flag_set`, `test_default_factory_accepts_semantic_store` |
| **Gate 2 — volume cadence** (`SKILL_THRESHOLD`, default 10 new skills) | `compilation_cadence.CompilationCadenceController` priority ladder (MANUAL → EFFECTIVENESS_DROP → SKILL_THRESHOLD → WEEKLY_CRON) | `test_skill_threshold_fires`, `test_below_skill_threshold_no_compile`, full ladder suite                                                     |
| **Cross-session reuse** (Q-C1-2)                                       | factory upserts `dspy_compilation` entity to `SemanticStore`                                                                     | `test_success_records_compilation_to_semantic_store`                                                                                         |
| **Proposal loop** (C-2 trio → candidate)                               | `_propose_skill_candidate` → `upsert_skill_candidate`                                                                            | `test_skill_proposal.py` (mock) + **`test_skill_proposal_e2e.py` (real store, C-3 PR1)**                                                     |

## Production activation runbook

To turn the loop on in a production tenant (operator action — costs live LLM spend):

1. Set `NEXUS_DSPY_PRODUCTION=1` for the meta-harness process (Gate 1).
2. Configure the LLM provider (`NEXUS_LLM_PROVIDER` + model pin + provider API key,
   e.g. `DEEPSEEK_API_KEY` / `ANTHROPIC_API_KEY`). The factory pins the model per run.
3. The `CompilationCadenceController` then fires a compile when **≥10 new deployed
   skills** have accumulated for an agent since its last compile (Gate 2 volume), or
   on effectiveness-drop / weekly-cron / operator `request_manual`.
4. Compiled candidates are materialised at the legacy candidate's canonical shadow
   path and adjudicated by the **eval-gate (sole deploy authority)** — DSPy never
   self-deploys; a losing DSPy candidate is restored to the legacy `SKILL.md`.

## Why the flag stays default-OFF in v0.3 (gate ledger)

The wiring is production-ready; the **flip** is gated on three recorded conditions, none
of which v0.3 closes:

1. **T2 — trace persistence (blocking, no-op without it).** Deployed `Skill`s carry
   provenance hashes, not raw originating traces, so the factory's trainset assembles
   from the _current trigger's_ unscored skill only — the Q5-a pre-filter drops it →
   empty trainset → CF #2 no-op (factory returns `None`, legacy proceeds). Flipping the
   flag today is therefore inert until traces are persisted with deployed skills. This
   is a substantial feature, out of v0.3 close-stretch scope.
2. **Task-14 — Anthropic switch-validation.** The production rollout is gated behind
   validating the live provider switch (recorded v0.2.5 follow-up).
3. **Gate 3 — quality-based cadence.** Deferred to v0.4 (audit Q5); v0.3 ships volume
   cadence only.

Until T2 + Task-14 clear, the honest posture is: **proposal half live and verified
(C-2 + C-3 PR1); compilation half wired but default-OFF; production flip = operator
decision once the gates clear.** This mirrors the A-1 live-loop posture (lanes wired +
gated; value realized when the operator runs them).

## C-3 cycle close

- **PR1 #703** — Hermes Phase 1 real-`SemanticStore` verification (9 new tests).
- **This record** — activation runbook + gate ledger; documents PR2/PR3 as
  already-shipped (C-1 #662 + v0.2.5) and PR4 close.
- Substrate seal EMPTY throughout. No flag flipped. No live LLM call in CI.

**C-3 CLOSED.** Track C status: C-1 (DSPy cadence wiring) + C-2 (Hermes Phase 1 trio
adoption) + C-3 (verification + activation readiness) all complete.
