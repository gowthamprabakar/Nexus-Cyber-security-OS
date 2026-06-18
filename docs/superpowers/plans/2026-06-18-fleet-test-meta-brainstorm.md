# Fleet Test Harness — meta-brainstorm (v0.4 T1–T5)

_2026-06-18 · distills `docs/_meta/v0-4-fleet-test-directive-2026-06-18.md` (#762) + records the Q-set answers · v0.2-style template_

## 1. What the directive commits us to (recon)

The fleet ships 6,916 isolated tests but **zero fleet-level tests**. The directive sets a
five-phase harness that produces **instrumented** evidence for the hard 85% PRD claim (§R1),
replacing the per-agent-maturity `[estimate]`:

| Phase  | Proves                                              | Deliverable                 | Backend                |
| ------ | --------------------------------------------------- | --------------------------- | ---------------------- |
| **T1** | each agent works alone, E2E, against real backends  | one E2E test per agent      | in-memory (Q1)         |
| **T2** | the ADR-018 spine correlates (toxic combos surface) | 10–15 `kg_query` scenarios  | in-memory (Q1)         |
| **T3** | Hermes closes the loop on _every_ detection agent   | per-agent closure scenarios | in-memory (Q1)         |
| **T4** | the substrate survives concurrency + scale          | gated pressure tests        | **real Postgres** (Q1) |
| **T5** | the whole platform does what it exists to do        | one pure-breed scenario     | **real Postgres** (Q1) |

T1 is the foundation — every later phase reuses its per-agent harnesses; T5 _is_ the 18 harnesses
run concurrently against shared state.

## 2. Recon discrepancies → reconciliation items (resolve in per-phase brainstorms)

Honest grounding against the actual repo (not the directive's round numbers):

- **R-1 — agent count.** Directive says **18 agents**; `packages/agents/` has **20 packages**:
  supervisor (#0), audit (F.6), meta-harness (A.4), remediation (A.1), investigation (D.7),
  synthesis (D.13), curiosity (D.12), vulnerability (D.1), identity (D.2), cloud-posture (F.3),
  multi-cloud-posture (D.15), k8s-posture, runtime-threat (D.3), network-threat (D.4),
  data-security, threat-intel (D.8), compliance (D.9), appsec (D.14), sspm (D.10), aispm (D.11).
  **T1 brainstorm must enumerate the canonical in-scope set** (likely all 20 get a T1 harness; the
  "18" probably predates D.10/D.11 or folds a pair). Recommend: **T1 = one harness per package =
  20**, not 18 — broader is correct for a fleet test.
- **R-2 — kg_writer count.** Directive says **15 kg_writers** + T5 asserts "all 15 wrote ≥1
  entity." Recon: 14 packages carry a top-level `kg_writer.py`; cloud-posture carries
  `tools/kg_writer.py` (= 15). **`multi-cloud-posture` (D.15) has no graph-writer code at all** —
  yet T2 scenario 9 + T5 route D.5/Azure findings through the graph. Either D.15 needs a kg_writer
  (a real gap) or those scenarios route through cloud-posture. **T1/T2 brainstorm must resolve the
  D.15 graph-writer gap** (flag, don't paper over).
- **R-3 — detection-agent set for T3.** Directive says "12+ detection agents." The Hermes loop
  (SkillTraceStore record-at-deploy) only fires for agents that run the skill lifecycle. **T3
  brainstorm must list exactly which agents close the loop** (detection agents that emit skills),
  vs. those that don't (supervisor/audit/remediation are not skill-emitting detectors).
- **R-4 — bridge-edge inventory.** T5 asserts HOSTS_AI, IRSA_MAPPING, AUTHORIZED, DEFINED_IN,
  **STORES_DATA**. The catalogue (ADR-018 `EdgeType`) has `EXPOSES_DATA` / `CLASSIFIED_AS`, not
  `STORES_DATA`. **T2/T5 brainstorm must map directive bridge names → real `EdgeType` members**
  (no inventing edges; reconcile naming).

These are the v0.4-catalogue `R-1/R-2/R-3` pattern — named now, resolved at the phase that owns them.

## 3. Q-set answers

**Operator-locked (calendar-shaping):**

- **Q1 — Postgres per phase: T1 in-memory · T2 in-memory · T3 in-memory · T4 REAL · T5 REAL.**
  In-memory at T1–T3 is the substrate's _documented_ test backend (ADR-009/ADR-019, the same
  aiosqlite path every unit test uses) — not mock theater. Real Postgres at T4–T5 is where
  Postgres-specific behavior matters: ON CONFLICT contention, RLS under load, recursive-CTE
  traversal cost, production-substrate verification.
- **Q8 — calendar: option (a), full T1–T5 in v0.4.** +6–8 weeks. v0.4 OPERATING declared with
  **INSTRUMENTED** 85% evidence, not `[estimate]`. Reasoning (operator): 50+ v0.4 PRs held the
  bar; declaring OPERATING on `[estimate]` at the finish breaks the discipline exactly where
  external credibility matters most.

**Carried forward with team recs (operator reviews at this brainstorm):**

- **Q2 — fakes vs sandboxed cloud.** _Rec: (a) live-lane fakes only for v0.4_ — cheap, fast,
  deterministic; the fakes already mirror real provider response shapes (swiss-bar #3). Sandboxed
  real accounts (AWS Goat / BadZure) → v0.5 design-partner pitches (cost + ongoing infra burden).
- **Q3 — T5 gated default-off.** _Rec: yes._ `NEXUS_PURE_BREED=1` gates the heavy test; default CI
  runs T1–T4; T5 runs nightly + on release branches. (Mirrors the existing `NEXUS_LIVE_*` /
  `NEXUS_PRESSURE_TEST` gating discipline.)
- **Q4 — false-positive acceptance.** _Rec: per-domain target, default 5% FP per detection class_
  until production data tunes. T1 asserts **zero false negatives** on the seeded violation
  (hard); FP budget is the softer, per-domain dial.
- **Q5 — T4 concurrency targets.** _Rec: 18 (→20, R-1) parallel agents · 100 parallel tenants ·
  10K entities × 100K edges per tenant._ Revisable per design-partner scale; these are the T4
  brainstorm's starting numbers, not a contract.
- **Q6 — Wiz/Orca/Lacework benchmark.** _Rec: defer to v0.5._ T5 proves _platform correctness_;
  competitive benchmarking is design-partner work.
- **Q7 — review mode.** _Rec: per-PR review on test **infrastructure** PRs_ (T1 foundation
  harness, substrate-adjacent T4 pressure infra, the Gate-3 evidence-rubric ADR); **self-merge**
  on per-scenario + per-agent tests once the T1 pattern is locked. (Same split that ran Stages 1–3.)
- **Q9 — brainstorm cadence.** _Rec: this meta-brainstorm first; then per-phase brainstorms as we
  hit each_ (T1 → then T2/T3/T4 parallel → T5), same v0.2-style template.

## 4. Sequencing (per directive §4, adjusted for R-1)

```
T1 (foundation, sequential)         per-agent E2E harness — pattern locked, ~20 harnesses
   ↓  (T1 pattern is the reusable base for everything after)
T2 + T3 + T4 (parallel)             correlation · Hermes-per-agent · substrate pressure
   ↓
T5 (finale, after T1+T2+T3)         pure-breed seeded scenario; tenant isolation; instrumented 85%
   ↓
Stage 4 (Wazuh 12-item) → Stage 5 (v0.4 close + v0.5 readiness audit)   [shifted AFTER T5 per §7]
```

No stacking — each phase brainstorm lands on main before its cascade; T1 must land before T2/T3/T4
start (they reuse T1 harnesses).

## 5. Swiss bar

The directive's §3 ten rules are binding verbatim — real code paths, no mock theater, real
Postgres in T4/T5, live-lane fakes mirror real shapes exactly, no "TODO fix later", no scaffolding
disguised as a test, **tenant isolation tested in every phase**, each phase's infra is its final
form (becomes the next phase's base + a CI regression gate), coverage stays `[estimate]` until T5,
no behavior PR ships without test-infra updates. Plus the standing project bars: no torch in core,
opt-in/default-off live lanes byte-identical offline, sequence via main.

## 6. Non-goals (v0.4, per directive §6)

Red-team/pentest, analyst-UX measurement, sandboxed cloud accounts, Wiz/Orca benchmark,
production-load stress (1M+ entities / 10K tenants), the DSPy production-flag flip (Gate-3 gated,
separate operator go), and the v0.5 readiness audit — all v0.5+.

## 7. Open for operator at review

1. Confirm Q2–Q7 + Q9 recs above (or amend).
2. **R-1**: T1 covers all 20 packages (rec) or a specific 18?
3. **R-2**: is the D.15 multi-cloud-posture graph-writer gap in-scope for this harness work
   (add the writer) or routed around (scenarios go through cloud-posture)?
4. **R-4**: confirm the directive's bridge names map to real `EdgeType` members (esp.
   `STORES_DATA` → `EXPOSES_DATA`/`CLASSIFIED_AS`).

On approval: T1 brainstorm next, then the cascade.
