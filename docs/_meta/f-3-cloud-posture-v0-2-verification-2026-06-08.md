# F.3 Cloud Posture v0.2 — verification record + cycle closure (2026-06-08)

> **F.3 v0.2 Milestone 4, Task 13 — the final task. This CLOSES the F.3 v0.2 cycle.** The [plan doc](../superpowers/plans/2026-06-07-f-3-cloud-posture-v0-2.md) was the pre-cycle plan; **this is the post-cycle source of truth.** Anyone reading this in 12 months should be able to reconstruct what shipped, what deferred, what broke, what was learned, and how D.5 v0.2 benefits. Docs-only; no code/test/charter touched.

---

## §1. Cycle summary

|                          |                                                                                                                      |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------- |
| **Cycle**                | F.3 Cloud Posture v0.2 (Level 1 → Level 2: offline → live AWS)                                                       |
| **Dates**                | kickoff 2026-06-08 03:58 UTC (#250) → closure 2026-06-09 (this PR). All 12 prior tasks merged 2026-06-08.            |
| **Architectural scope**  | **AWS CSPM only** (per [ADR-007](decisions/ADR-007-cloud-posture-as-reference-agent.md); F.3 is architecturally AWS) |
| **Maturity transition**  | Level 1 (offline / LocalStack) → **Level 2 (live AWS, single-tenant)**                                               |
| **Tasks completed**      | **13 of 13**                                                                                                         |
| **PRs merged**           | 13 task PRs (+ 5 related housekeeping PRs; 1 still parked)                                                           |
| **Tests added**          | **65 new test functions** across Tasks 1–8 (6 gated live, skip when env unset); Tasks 9–13 docs-only                 |
| **Closure suite state**  | `cloud-posture` **148 passed / 9 skipped**; **eval 10/10**                                                           |
| **Substrate seal**       | **empty throughout** — no `packages/charter/**` touched in any of the 13 tasks                                       |
| **OCSF 2003 invariance** | **maintained** — the 10 offline eval cases stayed byte-identical from Task 1 through Task 13                         |

## §2. Execution table (13 tasks)

All branches are `feat/f-3-cloud-posture-v0-2-<task>`; all merged to `main`; all **LOW-RISK**; all 5 CI checks green.

| Task | Title                                              | PR          | Merge (UTC) | Tests      | Notable                                                               |
| ---- | -------------------------------------------------- | ----------- | ----------- | ---------- | --------------------------------------------------------------------- |
| 1    | Bootstrap (version + ADR-010 pin + smoke)          | #250        | 06-08 03:58 | +8         | v0.2.0 pin; opens Milestone 1                                         |
| 2    | CredentialResolver seam                            | #254        | 06-08 05:44 | +12        | `--aws-profile`; seam in-package (Q1-A/Q7)                            |
| 3    | `aws_account_discovery` (STS + region enum)        | #255        | 06-08 06:08 | +9         | current-account only (Q4)                                             |
| 4    | Region scoping (`--regions`, default all)          | #256        | 06-08 06:31 | +9         | IAM global called once (Q3)                                           |
| 5    | Live-AWS error handling + partial-scan degradation | #257        | 06-08 13:44 | +9         | degraded markers; `BudgetExhausted` hard-stop; **closes Milestone 2** |
| 6    | `NEXUS_LIVE_AWS=1` gated live-eval lane            | #259        | 06-08 13:58 | +7         | `live_lane.py`; **opens Milestone 3** (Q5)                            |
| 7    | Live-AWS integration tests (read-only)             | #260        | 06-08 14:18 | +6 (gated) | real-account, read-only (Q4)                                          |
| 8    | LocalStack lane coexistence                        | #261        | 06-08 14:52 | +5         | lane-independence contract; **closes Milestone 3**                    |
| 9    | Cross-agent OCSF 2003 sweep                        | #262        | 06-08 15:05 | +0 (guard) | **opens Milestone 4**; 1,188 consumer tests green                     |
| 10   | Operator runbook + README v0.2                     | #263        | 06-08 15:52 | +0 (docs)  | live-AWS usage + degraded markers                                     |
| 11   | AWS CSPM coverage `[estimate]` note                | #265        | 06-08 16:31 | +0 (docs)  | honest **no-movement** (~84%)                                         |
| 12   | Hoist-candidate documentation (Q7)                 | #266        | 06-08 19:03 | +0 (docs)  | 5 patterns; closes Q7                                                 |
| 13   | Verification record + cycle closure                | **this PR** | 2026-06-09  | +0 (docs)  | **CLOSES F.3 v0.2**                                                   |

**Related housekeeping PRs** (not F.3-task PRs):

| PR   | What                                                   | Status                                                                    |
| ---- | ------------------------------------------------------ | ------------------------------------------------------------------------- |
| #251 | `SET LOCAL` → `set_config` tenant-RLS fix              | merged 06-08 04:41 (SAFETY-CRITICAL; parallel substrate per γ sequencing) |
| #252 | charter real-Postgres CI lane + setup script           | merged 06-08 05:45                                                        |
| #253 | multi-bug tenant-RLS substrate brainstorm              | **OPEN — DRAFT, parked** (awaits operator Q-locks)                        |
| #258 | parking discipline (macro plan §1.5 + 4 backlog files) | merged 06-08 13:41                                                        |
| #264 | backlog: flaky audit caplog test                       | merged 06-08 15:53                                                        |

## §3. Q-lock mapping (all 7 honored)

From the [v0.2 brainstorm](../superpowers/brainstorms/2026-06-07-f-3-cloud-posture-v0-2-brainstorm.md):

| Q   | Lock                                                 | Where honored | Evidence                                                                |
| --- | ---------------------------------------------------- | ------------- | ----------------------------------------------------------------------- |
| Q1  | (A) credential-resolution seam only, single-tenant   | Task 2 (#254) | `CredentialResolver` in `cloud_posture/credentials.py`, **not** charter |
| Q2  | Minimal live boto3 + `--aws-profile`                 | Task 2 (#254) | `--aws-profile` flag; boto3 default chain preserved                     |
| Q3  | `--regions` list, default = all available            | Task 4 (#256) | `--regions` option; default consumes `discover_regions()`               |
| Q4  | Current-account autodiscovery only                   | Task 3 (#255) | STS `get_caller_identity` only; no cross-account paths                  |
| Q5  | `NEXUS_LIVE_AWS=1` new gated live-eval lane          | Task 6 (#259) | new env-gated lane; offline 10 cases untouched                          |
| Q6  | Live KG persist on real Postgres OUT OF SCOPE        | all tasks     | no new RLS-dependent paths; `SemanticStore` offline only                |
| Q7  | Establish + document patterns; hoist at 3rd consumer | Tasks 2–12    | patterns in-package; #266 documents as hoist candidates                 |

**All 7 Q-locks honored. Zero scope deviations.**

## §4. Gates passed

- ✅ **All 13 task PRs:** 5/5 CI checks green (`go`, `python`, `python-tests`, `typescript`, `typescript-tests`).
- ✅ **Substrate seal empty:** no `packages/charter/**` touched in any task (the WI-1 guard never tripped on an F.3 task).
- ✅ **OCSF 2003 wire shape invariant:** confirmed by the Task 9 cross-agent sweep (#262) — `schemas.py` untouched since the pre-v0.2 ADR-004 refactor.
- ✅ **10 offline eval cases byte-identical:** Task 1 → Task 13 (re-verified at closure: **eval 10/10**).
- ✅ **`NEXUS_LIVE_AWS=1` lane:** green (operator-run; Task 7 #260).
- ✅ **`NEXUS_LIVE_LOCALSTACK` lane:** still green alongside the new AWS lane (Task 8 #261).
- ✅ **Cross-agent regression sweep (#262):** all 5 OCSF-2003 consumers green —

  | Consumer             | Result                                        |
  | -------------------- | --------------------------------------------- |
  | cloud-posture        | 148 passed / 9 skipped                        |
  | multi-cloud-posture  | 214 passed                                    |
  | k8s-posture          | 309 passed                                    |
  | data-security (DSPM) | 292 passed                                    |
  | compliance           | 225 passed                                    |
  | **Total**            | **1,188 tests across 5 consumers, all green** |

- ✅ **KG write paths:** green (Postgres-backed `SemanticStore`, offline-verified).
- ✅ **Audit chain integrity:** verified end-to-end (`charter.verify_audit_log`).
- ✅ **ruff + ruff format + mypy (strict):** clean across all task PRs.

## §5. Honest findings (what didn't go as planned)

**Finding 1 — AWS CSPM coverage didn't move (#265).** Macro-plan target was 84% → ~90%; **actual measured: ~84% → ~84% `[estimate]`.** Why: F.3 v0.2 added **zero AWS detection rules** — every task was credentials / discovery / region scoping / error-handling / lanes / docs. The macro-plan premise was the error: **live mode matures the liveness axis, not the rule-breadth axis.** Rule expansion (~700 → 1,200+) is v0.3 work. No fabrication, no round-up — reported as measured.

**Finding 2 — Live-Postgres RLS verification blocked.** The `SET LOCAL` fix (#251) is **necessary but not sufficient**: three pre-existing substrate bugs (`LTREE` missing, pgvector `cosine_distance` unexposed, RLS not `FORCE`d + tests run as superuser) block live verification. Captured in the parked #253 substrate brainstorm (4 bugs incl. SET LOCAL). F.3 v0.2 RLS verification was **offline only — acceptable under Q6** (live KG persist out of scope).

**Finding 3 — Flaky audit caplog test surfaced.** `test_run_logs_warning_when_non_wall_clock_budget_overrun` flakes only in cross-package runs; **pre-existing, not caused by F.3 v0.2**, CI-green. Captured as backlog #264 (opportunistic fix; trigger: convenient time / before F.6 Audit v0.2).

**Finding 4 — WI-1 substrate-seal guard is broadly scoped (carry-forward).** `meta-harness/test_g2_bootstrap.py`'s WI-1 check diffs the **whole repo** against `main`, not just meta-harness's own diff — so it reds `python-tests` on **any** legitimate charter-touching PR. This surfaced (correctly, as designed) on the SET LOCAL fix (#251). A re-scope is itself a meta-harness change and deserves its own PR — **opportunistic, post-F.3**; noted here so it is not lost.

## §6. Carry-forward to D.5 v0.2

**Inherits from F.3 v0.2:**

- **5 hoist-candidate patterns** (#266) — ready to lift when the third-consumer rule triggers.
- **Ascending-effort hoist sequencing:** D → E → C → A → B.
- **Per-cloud live-lane naming proposals** (forward triggers only): `NEXUS_LIVE_AZURE`, `NEXUS_LIVE_GCP`.
- **ADR-007 trigger:** D.5 likely triggers the hoist for Patterns C/D/E (the small-effort ones).

**Watch-items D.5 should inherit:**

- **WI-A** — flaky audit caplog test (#264): D.5's cross-agent sweep should not add new caplog cross-test interactions.
- **WI-B** — live-Postgres RLS unverifiable (blocked by #253): D.5 should **not** add new RLS-dependent code paths until that substrate cycle closes.
- **WI-C** — macro-plan-target premise correction: expect **liveness-axis** maturity from a v0.2 cycle, **not** rule-coverage-axis growth.

_(Carry-forward reminders only — not D.5 directives. D.5 v0.2 scope is set by its own brainstorm.)_

## §7. v0.3 deferred handoff (Level 2 → Level 3)

Deferred from F.3 v0.2 to **F.3 v0.3**, all already named on the README "Deferred to v0.3" line:

- **Cross-account scanning** — STS `AssumeRole` + Organizations account enumeration (Q4 deferral).
- **AWS Organizations integration** — management → member account discovery.
- **Control Tower integration** — landing-zone awareness.
- **Pattern-library expansion** — ~700 → ~1,200+ CIS-AWS rules (**this is the actual AWS CSPM coverage lift**).
- **Per-tenant credential store (option B)** — F.4 control-plane; SAFETY-CRITICAL; blocked by the #253 substrate cycle (Q1's deferred half).
- **Charter hoist execution** — patterns documented (#266); the actual hoist fires when D.5 v0.2 / D.2 v0.2 trips the third-consumer rule.

**Not immediate work.** F.3 v0.3 opens only after the detection arc progresses — per [macro plan §1.5](../strategy/nexus-agent-maturity-roadmap-2026-06-07.md), detection-first discipline (all 17 agents to Level 3 in series); parked work stays parked.

## §8. Cross-references

- [F.3 v0.2 brainstorm](../superpowers/brainstorms/2026-06-07-f-3-cloud-posture-v0-2-brainstorm.md) · [F.3 v0.2 plan](../superpowers/plans/2026-06-07-f-3-cloud-posture-v0-2.md)
- [Cross-agent OCSF 2003 sweep](f-3-cloud-posture-v0-2-cross-agent-sweep-2026-06-08.md) (#262) · [AWS CSPM coverage note](f-3-cloud-posture-v0-2-coverage-2026-06-08.md) (#265) · [Hoist-candidate documentation](f-3-cloud-posture-v0-2-hoist-candidates-2026-06-08.md) (#266)
- [ADR-007](decisions/ADR-007-cloud-posture-as-reference-agent.md) · [ADR-010](decisions/ADR-010-version-extension-template.md) · [ADR-011](decisions/ADR-011-pr-flow-and-branch-protection-discipline.md)
- [Macro plan](../strategy/nexus-agent-maturity-roadmap-2026-06-07.md) (§1.5 sequencing discipline) · [Competitive benchmark](../strategy/competitive-benchmark-2026-06-08.md) (§3 CSPM weighting) · [Parked work](backlog/2026-06-08-parked-architectural-work.md)
- **Task PRs:** #250 · #254 · #255 · #256 · #257 · #259 · #260 · #261 · #262 · #263 · #265 · #266 · (this PR)
- **Housekeeping PRs:** #251 · #252 · #253 (parked) · #258 · #264

---

## 🎯 F.3 v0.2 CYCLE COMPLETE

13 of 13 tasks. Level 1 → Level 2 (offline → live AWS, single-tenant). All 7 Q-locks honored, zero scope deviations, substrate seal empty throughout, OCSF 2003 invariant. Honest findings recorded (incl. the ~84% AWS CSPM no-movement). Next on the strict-serial detection track: **D.5 Multi-Cloud Posture v0.2** (brainstorm, after operator confirmation).

— recorded 2026-06-08 (F.3 v0.2 Task 13; verification record + cycle closure; docs-only, no code touched).
