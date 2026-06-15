# v0.3 / Phase D — Completion Record (E-1) — 2026-06-15

**Subject:** main HEAD `0a2f3a0`. **Type:** completion record (close-stretch finale), NOT a
new cycle and NOT a new audit. **Method:** ground-truth verification against main.
Mirrors the Phase C completion record (#646).

v0.3 took the v0.2 fleet — which Phase C had turned from INFRASTRUCTURE into OPERATING
(invariants load-bearing on every `run()`) — and added **live-loop wiring, depth on the
highest-leverage agents, a net-new build-time agent, the Hermes self-evolution proposal
loop, and the continuous-loop CLI foundation.** It was scoped against the Phase D
readiness audit (#647, `phase-d-readiness-audit-2026-06-14.md`).

---

## Executive summary

- **Track A — live-loop + depth.** A-1 wired 5 agents' live readers behind `NEXUS_LIVE_*`
  gates (threat-intel, vulnerability, identity-federation, network-threat, runtime-threat)
  on the shared `bounded_drain` infra. A-2 deepened D.1 (filesystem + host SCA, the
  reachability correlator — the biggest single depth lever — and secrets-in-runtime → DSPM
  per ADR-015). A-3 unlocked real Prowler json-ocsf parsing + native CIS extraction +
  k8s manifest rules. A-4 drove the D.2 effective-perms simulator that was _built but
  undriven_. **A-5 / A-6 / A-3 Item 2b deferred to v0.4.**
- **Track B — net-new agent.** D.14 AppSec shipped end-to-end (B-1, 10 PRs): build-time
  IaC (Checkov) + SAST (Semgrep) + secrets-in-code (gitleaks → DSPM), three SCM connectors,
  clone-for-scan, multi-tenant + full-pipeline integration, fleet eval parity. **ADR-014**
  (SBOM boundary) + **ADR-015** (secrets scan/emit split) authored.
- **Track C — self-evolution.** C-1 wired the DSPy compilation cadence into the
  meta-harness `run()` (default-OFF). C-2 adopted Hermes Phase 1 across the LLM trio
  (D.13/D.7/D.12) — each proposes skill candidates into the SemanticStore. C-3 verified
  the proposal loop end-to-end against a real store + recorded the activation runbook +
  gate ledger.
- **Track D — continuous loop.** D-1 added `supervisor run --continuous-mode` +
  kill-switch (wired-but-inert). D-2 added per-tenant cadence config, freshness API,
  continuous metrics, state-transition audit, and a status-page stub.
- **Honest deferrals recorded** (below) — explicit v0.4 boundary, nothing silently skipped.

---

## Track → PR map

| Track / workstream              | What landed                                                                                                                             | PRs                                                                               |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| Pre-flight                      | #647 readiness audit; P3-2 `llm_invariants` hoist; P3-4 curiosity fence + ADR-012; dspy/gepa pins; Hermes §10 addendum                  | #647, #648, #649, #650, #651                                                      |
| A-1 live-loop wiring            | launch + 5 agents (threat-intel/vuln/identity-fed/network/runtime) on `bounded_drain`; A-1 record                                       | #652–#657, #659, #660, #661                                                       |
| A-2 D.1 vulnerability depth     | fs-SCA, host-scan, reachability correlator (#676/#677/#678), secrets-in-runtime→DSPM; verification                                      | #669–#672, #674–#679, #685, #686, #687                                            |
| A-3 CSPM + k8s breadth          | Prowler dual-shape + native CIS extraction; cis_coverage; k8s manifest rules; compliance native-CIS                                     | #689, #693, #696, #698, #700                                                      |
| A-4 D.2 effective-perms         | drive the built-but-undriven simulator; OVERPRIVILEGE evidence enrich + verification                                                    | #688, #692                                                                        |
| B-1 D.14 AppSec (net-new agent) | scaffold+ADR-014, Checkov, gitleaks→DSPM (ADR-015 #681), GitHub/GitLab/Bitbucket, clone, Semgrep, integration, eval_runner, cycle close | #690, #691, #694, #695, #697, #699, #701, #702, #705, #706, #707 (+ ADR-015 #681) |
| C-1 DSPy cadence wiring         | `make_default_dspy_factory` into meta-harness `run()` (default-OFF) + SemanticStore reuse                                               | #662                                                                              |
| C-2 Hermes Phase 1 (LLM trio)   | hoist `detect_skill_trigger` + candidate-store; trio proposes skill candidates                                                          | #680, #682, #683, #684                                                            |
| C-3 verification + activation   | real-SemanticStore proposal-loop verification; DSPy activation runbook + gate ledger                                                    | #703, #704                                                                        |
| D-1 continuous-mode CLI         | `supervisor run --continuous-mode` + kill-switch (wired-but-inert)                                                                      | #658                                                                              |
| D-2 continuous infra            | cadence config, freshness API, metrics, state-transition audit, status-page stub                                                        | #663, #664, #665, #666, #667                                                      |
| E-1 completion record           | this                                                                                                                                    | (this PR)                                                                         |

~60 PRs, #647–#707.

---

## Verification (ground-truthed against main `0a2f3a0`)

- **Track B cycle CLOSED** — B-1 verification record on main
  (`v0-3-b-1-cycle-verification-2026-06-15.md`, #707); D.14 AppSec live + fleet-eval-registered;
  secrets-in-code loop closed into DSPM; appsec 67 pass.
- **Track C CLOSED** — C-1 + C-2 + C-3 all on main; Hermes proposal loop verified against a
  real SemanticStore (#703); DSPy compilation stays default-OFF behind the recorded gates
  (`v0-3-c-3-dspy-activation-readiness-2026-06-15.md`, #704).
- **Track A** — A-1 wiring + A-2/A-3/A-4 depth on main; A-2 cycle closed (#687); A-4 closed
  (#692); A-3 PR1-3 + Item 1 on main (Item 2b deferred).
- **Track D** — D-1 + D-2 on main; continuous infra wired-but-inert (audit §11: v0.3 builds,
  v0.4 activates).
- **Full repo:** **7339 passed, 73 skipped, 0 failed** (completion sweep on main `0a2f3a0`,
  all extras installed); ruff + mypy clean. Every v0.3 PR also merged green on all 5 CI
  checks (`go, python, python-tests, typescript, typescript-tests`).
- **Substrate seal** (`packages/shared` + `packages/charter`) preserved across every v0.3
  self-merge cascade; the only authorized substrate touches were the operator-reviewed
  pre-flight P3-2 hoist (#648) and P3-4 fence (#649). No agent cycle edited the seal.

---

## Coverage position (honest)

Baseline anchored at **~56.7% `[estimate]`** (#647 Dimension-2; range 55.4–58.1%). v0.3's
depth + the net-new agent move the realized number toward the **~74–76% Track A close
target**, but with the standing caveats that travel with every coverage claim
(`v0-3-track-a-baseline-reconciliation-2026-06-14.md`):

1. All values are `[estimate]` ranges, never instrumented.
2. **Live-loop lift (~+5–8pp) is realized when the gated live lanes RUN** (operator-run),
   not by the wiring alone (A-1 record #661).
3. **D.14 AppSec** was a **0% row** in #647 (no agent existed); B-1 adds a new build-time
   surface, realized on operator-run of the live SCM connectors. Secrets-in-code attributes
   to **DSPM** (ADR-015), not double-counted.
4. **Honest ceiling ~75–80%** for detector depth; the final push to the 85% PRD target needs
   the v2.0 inventory graph (Phase 0, greenfield) — out of v0.3 scope.

The instrumented number is not claimed; v0.3 closes the depth + breadth levers that #647
identified, and the realized lift lands when an operator runs the live lanes.

---

## Honest deferrals → v0.4 (explicit, not silently skipped)

- **A-5 (D.3 runtime/CWPP depth)** + **A-6 (data-security/DSPM depth)** — pre-authorized
  DEFER in the close-stretch directive.
- **A-3 Item 2b (k8s CIS v1.8 → v2.0)** — needs authoritative CIS-K8s-v2.0 data; deferred to
  avoid transcription/fabrication (#696/#700 recon).
- **D.10 / D.11** — net-new agents, not in v0.3 scope.
- **Phase 0 — v2.0 inventory graph** — the greenfield foundation for the 85% push; the
  single biggest v0.4 lever.
- **DSPy Gate 3 (quality-based cadence)** — v0.3 ships volume cadence only; the production
  flag-flip stays gated on T2 trace-persistence + Anthropic switch-validation (#704).
- **Hermes Phases 2-5** — v0.3 adopted Phase 1 (proposal) only.
- **AI-SPM / SSPM (AI/SaaS Posture)** — the other 0% row in #647; net-new, v0.4+.

---

## v0.3 → v0.4 boundary

v0.3 = **liveness + depth + the AppSec pilot + the self-evolution proposal loop + the
continuous-loop foundation.** v0.4 = **activation + the greenfield foundation**: turn the
live lanes / continuous loop / DSPy flag ON (operator-run), build Phase 0's v2.0 inventory
graph (the path past the ~75–80% ceiling), and add the deferred depth (A-5/A-6) + net-new
agents (D.10/D.11, AI-SPM/SSPM). The v0.4 readiness audit (E-2,
`v0-4-readiness-audit-2026-06-15.md`) ranks these and surfaces the operator Q-set.

---

## Status

**v0.3 is complete.** With E-1 (this record) + E-2 (the v0.4 readiness audit) landed, **v0.3
is declared OPERATING**: live-loop wiring + depth on the high-leverage agents, the D.14
AppSec agent, the Hermes Phase 1 proposal loop, and the continuous-loop foundation are all
on main, substrate-sealed, with the activation steps explicitly handed to v0.4. Next: the
v0.4 readiness Q-set (E-2) → operator scope decisions → v0.4 directive.
