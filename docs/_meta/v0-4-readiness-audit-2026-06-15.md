# v0.4 Readiness Audit (E-2) — 2026-06-15

**Subject:** main HEAD `0a2f3a0` (post-v0.3 close). **Type:** readiness audit + v0.4 scope
kickoff, NOT a cycle. **Method:** ground-truth against main + the v0.3 completion record
(E-1, `v0-3-completion-2026-06-15.md`). Mirrors the Phase D readiness audit (#647).

This audit anchors the v0.4 baseline to the E-1 close, analyzes the residual gap to the PRD
85% target, ranks the scope candidates, and surfaces the operator Q-set for v0.4 scope
decisions. It proposes nothing as decided — the Q-set is the gate.

---

## §0 — Premise corrections (read first)

1. **v0.3 close is liveness + depth + the AppSec pilot, not instrumented coverage.** The
   realized lift from A-1 live lanes + B-1 AppSec is **operator-run-realized**, not produced
   by wiring alone (E-1 §Coverage; A-1 record #661). No instrumented number is claimed.
2. **The tenant-RLS blocker that historically gated the v2.0 graph is RESOLVED**
   (F.5 `SET LOCAL $1` → `set_config`, commit `5b8cefc`). Phase 0 is no longer
   substrate-blocked — its cost is greenfield build, not unblocking.
3. **DSPy production flag stays default-OFF** behind T2 trace-persistence + Anthropic
   switch-validation (#704). "Activate DSPy" in v0.4 means _build T2 + validate_, not flip a
   switch.
4. **The 85% PRD target needs Phase 0.** Detector depth caps **~75–80%** (#647 Dimension-2);
   the final push is structurally a graph problem, not a per-agent-depth problem.

---

## §1 — Audit framework + scope boundaries

Same 5-dimension frame as #647: (1) net-new agent readiness, (2) depth-track baseline +
weighted coverage, (3) Hermes self-evolution, (4) continuous-loop autonomy, (5) Phase 0
inventory seam. Scope boundary: this audit ranks candidates + frames the Q-set; the v0.4
directive (post-Q-set) commits scope. No code in E-2.

---

## §2 — Executive summary

v0.3 delivered the levers #647 named: live-loop wiring (A-1), the highest-leverage depth
(A-2 reachability, A-4 effective-perms, A-3 CSPM/CIS), the net-new AppSec agent (B-1), the
Hermes Phase 1 proposal loop (C-2/C-3), and the continuous-loop foundation (D-1/D-2). What
remains for the 85% target splits cleanly into **(a) activation** (turn the wired lanes /
continuous loop / DSPy flag ON — operator-run + T2), and **(b) the greenfield foundation +
deferred surface** (Phase 0 v2.0 graph, A-5/A-6 depth, D.10/D.11 + AI-SPM/SSPM net-new).
The single highest-leverage v0.4 investment is **Phase 0** — it is the only path past the
~75–80% detector-depth ceiling.

---

## Dimension 1 — Net-new agent readiness

- **D.14 AppSec — DONE** (v0.3 B-1). The net-new-agent pattern is proven end-to-end
  (scaffold → scanners → cross-agent OCSF → eval parity), a reusable template for D.10/D.11.
- **Candidates not yet built:** D.10, D.11 (roadmap net-new), **AI-SPM / SSPM** (the AI/SaaS
  Posture 0% row in #647). Each is a fresh agent (~1 cycle of per-PR or self-merge work,
  using the B-1 template). Combined weighted contribution is modest (#647 had AppSec+AI/SaaS
  at 0.04+0.02) — breadth, not the 85% lever.

## Dimension 2 — Depth-track baseline + residual gap

Baseline: **~56.7% `[estimate]`** (#647). v0.3 depth + breadth move the realized-on-live-run
number toward the **~74–76%** Track A close target. Residual to the **85% PRD target ≈
13–14pp** (operator-stated), structurally composed of:

| Residual lever                     | Nature                       | In v0.3?         |
| ---------------------------------- | ---------------------------- | ---------------- |
| Live-lane + continuous activation  | operator-run (wired in v0.3) | wired, not run   |
| A-5 (D.3 CWPP depth)               | deferred depth               | deferred         |
| A-6 (DSPM depth)                   | deferred depth               | deferred         |
| A-3 Item 2b (k8s CIS v2.0)         | needs authoritative data     | deferred         |
| **Phase 0 — v2.0 inventory graph** | **greenfield; past-ceiling** | **out of scope** |
| D.10 / D.11 / AI-SPM / SSPM        | net-new breadth              | not built        |

**Honest:** detector depth alone caps ~75–80%; **only Phase 0 crosses to 85%.** A-5/A-6 +
net-new agents narrow the gap but do not, by themselves, reach the target.

## Dimension 3 — Hermes self-evolution

Phase 1 (proposal) is live + verified (C-2/C-3). The full loop (propose → eval-gate →
deploy → measure → recompile) is gated on: **DSPy production flag** (needs T2 trace
persistence + Anthropic switch-validation), **Gate 3 quality cadence** (v0.4), and **Hermes
Phases 2-5**. v0.4 decision: build T2 (unblock the flag) and/or advance Hermes phases, or
hold the proposal-only posture.

## Dimension 4 — Continuous-loop autonomy

D-1/D-2 shipped the foundation (continuous-mode CLI + cadence/freshness/metrics/audit/status),
**wired-but-inert** (v0.3 builds, v0.4 activates). v0.4 decision: turn the continuous driver
ON (autonomous run loop) + the per-tenant cadence in production, or keep manual-dispatch.

## Dimension 5 — Phase 0 inventory seam

The v2.0 inventory graph is the greenfield foundation for the 85% push. **No longer
substrate-blocked** (tenant-RLS resolved, §0.2). Cost is a greenfield build (entity/edge
model at fleet scale, cross-agent inventory ingestion, query surface). This is the single
biggest v0.4 lever and a prerequisite for the PRD target — but also the largest effort.

---

## §8 — Scope candidates, ranked

1. **Phase 0 — v2.0 inventory graph** (foundational; only path to 85%; largest effort;
   now unblocked). _Highest leverage, highest cost._
2. **Activation sprint** — turn live lanes + continuous loop ON (operator-run) + build **T2
   trace persistence** to unblock the DSPy flag. _Realizes v0.3's already-wired lift; medium
   effort; high realized-coverage payoff._
3. **A-5 (D.3 CWPP depth) + A-6 (DSPM depth)** — deferred depth; per-agent cycles. _Medium
   leverage, medium effort._
4. **Net-new agents** — D.10 / D.11 / AI-SPM / SSPM (B-1 template). _Breadth; modest weight._
5. **A-3 Item 2b + Hermes Phases 2-5 + DSPy Gate 3** — finishing touches; data-/validation-gated.

## §9 — Operator Q-set (gates the v0.4 directive)

- **Q-v0.4-1 — Primary thrust.** (a) Phase 0 foundation-first (commit to 85% path), (b)
  Activation-first (realize v0.3's wired lift + T2), (c) Depth-first (A-5/A-6), or (d) a
  blended arc? _Recommendation: (b) then (a) — realize the wired lift cheaply, then take on
  the greenfield foundation._
- **Q-v0.4-2 — Coverage commitment.** Commit v0.4 to the **85% PRD target** (requires Phase
  0 in-cycle) or to a realistic interim (**~78–80%**, activation + A-5/A-6, Phase 0 staged)?
- **Q-v0.4-3 — DSPy production.** Build **T2 trace persistence** + run Anthropic
  switch-validation to unblock the flag this cycle, or hold proposal-only?
- **Q-v0.4-4 — Continuous autonomy.** Turn the continuous driver ON (autonomous loop) in
  v0.4, or keep manual-dispatch + grow the foundation?
- **Q-v0.4-5 — Net-new agents.** Which of D.10 / D.11 / AI-SPM / SSPM (if any) are in v0.4
  scope?

## §10 — Calendar projection (rough, per candidate — `[estimate]`)

| Candidate                          | Rough effort                |
| ---------------------------------- | --------------------------- |
| Activation sprint (lanes + T2)     | ~1–2 weeks                  |
| A-5 (D.3 depth)                    | ~1–1.5 weeks                |
| A-6 (DSPM depth)                   | ~1–1.5 weeks                |
| Net-new agent (each, B-1 template) | ~1 week                     |
| **Phase 0 — v2.0 graph**           | **~4–6 weeks** (greenfield) |

A focused v0.4 (activation + A-5/A-6 + 1 net-new) ≈ **~4–5 weeks**; including Phase 0 in-cycle
pushes to **~8–10 weeks**. The Q-set (esp. Q-v0.4-2) sets which.

## §11 — Risk register

- **R1 — coverage claims stay `[estimate]`.** v0.4 should add instrumentation if it commits
  to a hard 85% number, else the target remains a bounded judgement.
- **R2 — Phase 0 scope creep.** Greenfield graph is the largest single effort; staging it
  (model → ingestion → query) avoids a multi-cycle stall.
- **R3 — activation cost.** Turning live lanes / DSPy ON spends real cloud/LLM budget; gate
  - monitor per the existing `NEXUS_LIVE_*` / flag discipline.
- **R4 — net-new breadth vs depth.** Net-new agents add surface but modest weight; don't let
  them displace the Phase 0 lever if 85% is committed.

---

## Status

**v0.4 readiness audit complete.** v0.3 close is the baseline; the residual ~13–14pp to 85%
is structurally Phase 0 + deferred depth + activation. The **Q-set (§9) is the gate** — once
the operator answers, the v0.4 directive commits scope, target, and calendar. No v0.4 work
starts before that decision.
