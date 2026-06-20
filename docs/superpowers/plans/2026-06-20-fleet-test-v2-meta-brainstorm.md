# Fleet Test v2 — meta-brainstorm (six-level capability plan)

_2026-06-20 · distills `docs/_meta/v0-4-fleet-test-directive-v2-2026-06-18.md` (#766) + records the Q-set answers · supersedes the v1 meta-brainstorm (#763) · v0.2-style template_

## 1. What v2 commits us to (distill)

v1 (#762/#763) tested **integration** (wiring completes, kg_writer writes, OCSF validates) and
mislabeled it capability. v2 separates the two: integration is L1 (smoke); **capability is
measured** — precision/recall/FP against ground truth the agent doesn't know. Six levels (the
directive title says "five-level" but the body defines **L1–L6** = six; using six):

| Level              | Proves                       | Deliverable                                           | Backend           |
| ------------------ | ---------------------------- | ----------------------------------------------------- | ----------------- |
| **L1 integration** | wiring works                 | 20× `tests/integration/test_wiring.py`                | in-memory         |
| **L2 capability**  | the agent _detects_ (P/R/FP) | per-agent `tests/capability/` YAML banks (~146 cases) | in-memory         |
| **L3 correlation** | the spine bridges traverse   | `kg_query` scenarios (≥15)                            | in-memory         |
| **L4 Hermes loop** | feedback _improves_ quality  | GEPA-delta + loop-stage cases (≥10)                   | in-memory         |
| **L5 pressure**    | substrate survives load      | gated pressure tests (≥7)                             | **real Postgres** |
| **L6 pure-breed**  | platform competence          | one fleet scenario → instrumented 85%                 | **real Postgres** |

The load-bearing shift: **the directive is the FRAMEWORK; the team writes the CONTENT** (the actual
YAML test cases, fixtures, scenarios) in per-level brainstorms (Q10).

## 2. Q-set answers

**Operator-locked:**

- **Q5 — Hermes consumer scope: (a) narrow, 4 agents** (curiosity, investigation, synthesis,
  meta-harness). This is the honest resolution of **R-3′** (only 4 agents run the skill lifecycle
  today; the deterministic detection agents do not). No retcon (swiss-bar #14).
- **Q8 — calendar: (a) full L1–L6 in v0.4** (~14–15w). v0.4 OPERATING declared on INSTRUMENTED
  capability, not `[estimate]`. (+5–6w vs v1; ~Week 33–37.)
- **Q10 — framework/content split locked.** Meta-brainstorm first (this); then per-level
  brainstorms; team writes the test cases in them.

**Carried with team recs (operator reviews at this brainstorm):**

- **Q1 — bank ownership: per-agent package** (`packages/agents/<agent>/tests/capability/`). _Rec:
  yes_ — banks live with the code they measure; the agent team owns its own ground truth. Shared
  mechanics (loader, P/R compute, evaluator) centralize in `packages/integration/fleet_testkit/`.
- **Q2 — thresholds: §3.6 defaults, operator-amends-per-agent.** _Rec: yes_ — start from the
  per-class defaults; tune per agent as real data arrives. Thresholds are documented per case
  (swiss-bar #13), never implied.
- **Q3 — fixture realism: (a) synthetic for v0.4** (cheap, deterministic, fast); (b) recorded
  real-provider responses selectively where it pays off; (c) sandboxed accounts → v0.5. _Rec: (a)_,
  with the swiss-bar #3 constraint that synthetic fixtures **mirror real provider response shapes
  exactly** (the existing live-lane fakes already do this — reuse them).
- **Q4 — bank size: (a) honor §3.5 minimums (~146)**, expand per agent as gaps surface; never
  reduce below minimum without operator sign-off. _Rec: (a)_ — minimum is a floor, not a target.
- **Q6 — L5 pressure gated default-off** (`NEXUS_PRESSURE=1`). _Rec: yes_ (mirrors the existing
  `NEXUS_LIVE_*` gating discipline; default CI runs L1–L4).
- **Q7 — L6 pure-breed gated default-off** (`NEXUS_PURE_BREED=1`, nightly + release branches).
  _Rec: yes._
- **Q9 — review mode per level:** L1 infra per-PR / cascade self-merge; **L2 banks per-PR**
  (test-case _quality_ is the whole point) self-merge after the first 2 agents lock the pattern;
  L3 scenarios per-PR / self-merge; L4 Gate-3-evidence test per-PR; L5 substrate-adjacent per-PR;
  L6 per-PR (it's THE test). _Rec: as tabled_ — note L2 keeps per-PR longer than L1 because a
  weak test case is worse than no test case.

## 3. Carry-forward from v1 (no institutional capital lost)

The closed v1 T1 brainstorm (#765) did real recon that maps directly onto **v2 Level 1**:

- the **20-agent matrix** (verified `run()`/kg_writer/OCSF/Hermes/input per agent),
- the **`packages/integration` + `fleet_testkit`** design,
- the **tier classifications** (A full / B no-graph / B action / B special),
- **R-3′** (only 4 agents run the skill lifecycle).

These are carried into the **Level 1 brainstorm** verbatim rather than re-derived. R-3′ specifically
feeds **Level 4** (Q5(a) already resolves it to the 4-agent scope). The v1 "18 vs 20 agents"
discrepancy is moot — v2 §2.2 says **20** explicitly.

Also carried: **edge-name verification (swiss-bar #15 / old R-4)** — `STORES_DATA` is not an
ADR-018 member; v2 §4.1 already uses the correct `EXPOSES_DATA` / `CLASSIFIED_AS`. Every L3/L6
assertion verifies edge names against the catalogue before it's written.

## 4. Sequencing (per directive §9)

```
L1 (foundation, sequential) → L2 (per-agent banks, parallel within)
   → L3 + L4 (parallel) → L5 (parallel w/ L4 tail) → L6 (finale)
   → Stage 4 Wazuh → Stage 5 close
```

No stacking — each level's brainstorm lands on main before its cascade; L1 lands before L2
(L2 reuses the L1 harness + testkit); L6 consumes all prior levels' artifacts.

## 5. Swiss bar

Directive §8 (15 rules) binding verbatim. The four that change how we _write tests_ vs v1:
**#5** no fake-greens via assertion absence · **#6** every test = documented INPUT + GROUND TRUTH

- PASS CRITERIA (fixtures alone aren't a test) · **#12** every omitted assertion documented
  in-test with reason · **#13** precision/recall/FP measured explicitly, never implied. Plus #14
  (Hermes scope honest) and #15 (edge names verified). Standing bars also hold (no torch in core,
  default-off live lanes byte-identical, sequence via main).

## 6. Non-goals (v0.4, per directive §11)

Sandboxed cloud accounts, Wiz/Orca benchmark, 1M+ entity stress, Task-14 Anthropic validation,
analyst-UX, red-team, D.15 live-connector activation, Hermes-scope expansion to deterministic
agents — all v0.5+.

## 7. Open for operator

Confirm Q1–Q4, Q6, Q7, Q9 recs (Q5/Q8/Q10 already locked). On approval: the **Level 1 brainstorm**
(carrying the #765 recon) is next, then the L1 cascade.
