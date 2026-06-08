# Nexus Platform Readiness Report — 2026-06-07

> **Purpose.** Accurate, empirically-grounded current-state inventory of the entire Nexus platform, so strategy decisions (agent-maturity progression, v2.0 attack-path layer, v3.0 Cure track) rest on facts, not a stale mental model. Commissioned after the v0.2.5 close + the "D.4 already shipped" finding revealed the roadmap had drifted from main.

- **Date:** 2026-06-07
- **Method:** parallel read-only investigation across 10 axes; subagent findings spot-checked against `origin/main` (`4b17250`). Test counts run; SHAs/PRs cited; estimates flagged as estimates.
- **Scope rule:** read-only; no code changed.

---

## 0. Executive summary

The breadth-first build phase is **complete**: **all 17 Wave-1 agents are shipped at v0.1** on `origin/main`, every one with a registered eval-runner and 10+ eval cases, suites green. The platform has roughly **doubled** its Wiz-equivalent coverage since 2026-05-13 — from a _corrected_ ~27% to an estimated **~56–60%** — driven by the CSPM/CDR/network pillars.

Three strategic headlines:

1. **v3.0 (Cure track) is the _most_ ready layer** — already shipped at v0.1. The A.1 Remediation agent collapses Tier-3/2/1 into one agent with operator approval gates, a dry-run framework, detector-re-run rollback, and an earned-autonomy promotion pipeline. v3.0 is **breadth-expansion, not foundational construction**.
2. **v2.0 (attack-path layer) is ~one substrate decision away from "ready to start," but the modeling is greenfield** — graph storage + generic BFS + real cross-agent correlation exist, but attack-path semantics, a graph-wide exposure model, and a dual-substrate reconciliation (Neo4j vs Postgres SemanticStore) are unbuilt and partly blocked.
3. **The maturity arc is unblocked** for most agents — the v0.2 theme is **offline → live cloud feeds**, gated mainly on a live-cloud credential/sandbox substrate (not yet established) and the tracked **SET LOCAL tenant-RLS bug** (multi-tenant only).

**Top risk:** the `SET LOCAL $1` tenant-RLS bug is **still present at HEAD** (`charter/memory/service.py:96`) — multi-tenant isolation is effectively broken on real Postgres. Consciously deferred; single-tenant dev unaffected; will surprise a multi-tenant launch.

**Recommended first maturity-arc agent: F.3 Cloud Posture** (reference agent + heaviest Wiz weight + maximal pattern reuse) — see §10; D.1 Vulnerability and D.4 Network Threat are the alternates.

---

## 1. Agent inventory (Axis 1)

All 17 at **v0.1.0** except A.4 (v0.2.5). 17/17 register `nexus_eval_runners`. Suites green on main.

| Code | Agent                | Ver       | First merge | src | tests | Runbook | Verif record        | OCSF class_uid  | Eval cases |
| ---- | -------------------- | --------- | ----------- | --: | ----: | ------- | ------------------- | --------------- | ---------: |
| F.3  | Cloud Posture        | 0.1.0     | 05-08       |  11 |    87 | ✅      | ✅                  | 2003            |         10 |
| F.6  | Audit                | 0.1.0     | 05-12       |  11 |   125 | ✅      | ✅                  | 6003            |         10 |
| D.1  | Vulnerability        | 0.1.0     | 05-10       |  11 |   103 | ✅      | ✅                  | 2002, 2003      |         10 |
| D.2  | Identity             | 0.1.0     | 05-11       |  10 |   125 | ✅      | ✅                  | 2004            |         10 |
| D.3  | Runtime Threat       | 0.1.0     | 05-11       |  11 |   135 | ✅      | ✅                  | 2004            |         10 |
| D.4  | Network Threat       | 0.1.0     | 05-13       |  13 |   207 | ✅      | ✅                  | 2004            |         10 |
| D.5  | Multi-Cloud Posture  | 0.1.0     | 05-13       |  12 |   170 | ✅      | ✅                  | 2003            |         10 |
| D.6  | K8s Posture          | 0.1.0     | 05-13       |  14 |   257 | ✅      | ✅ (v0.1/0.2/0.3)   | 2003            |         10 |
| D.7  | Investigation        | 0.1.0     | 05-12       |  14 |   203 | ✅      | ✅                  | 2005            |         10 |
| D.8  | Threat Intel         | 0.1.0     | 05-20       |  16 |   231 | ❌      | ✅                  | 2002, 2004      |         10 |
| D.12 | Curiosity            | 0.1.0     | 05-21       |  12 |   200 | ❌      | ✅                  | none (deferred) |         10 |
| D.13 | Synthesis            | 0.1.0     | 05-21       |  11 |   188 | ❌      | ✅                  | 2003            |         10 |
| —    | Data Security (DSPM) | 0.1.0     | 05-20       |  15 |   262 | ✅      | ✅                  | 2003            |         10 |
| —    | Compliance           | 0.1.0     | 05-21       |  14 |   207 | ❌      | ✅                  | 2003            |         10 |
| A.1  | Remediation          | 0.1.0     | 05-16       |  22 |   415 | ✅✅    | ✅ (+safety/patch)  | 2003, 2007      |         15 |
| A.4  | Meta-Harness         | **0.2.5** | 05-21       |  33 |   609 | ❌      | ✅ (v0.1/0.2/0.2.5) | none (harness)  |         25 |
| #0   | Supervisor           | 0.1.0     | 05-21       |  12 |   183 | ❌      | ✅                  | none (router)   |         15 |

**Notes.** F.3 is the earliest + ADR-007 reference agent. A.1 is the largest of the agent cohort (22 src / 415 tests). A.4 is the deepest overall (33 src / 609 tests / only one past v0.1). Curiosity/Synthesis/Supervisor/Meta-Harness emit no OCSF by design (producer-of-directives / router / harness; Synthesis + Curiosity emission deferred pending a `class_uid` ADR). **Runbooks present for 9/17** — missing on threat-intel, curiosity, synthesis, compliance, meta-harness, supervisor (a documentation-debt item).

> **Naming inconsistency (Axis 8 cross-ref):** the **D.5 / D.6** codes collide — held by _multi-cloud-posture / k8s-posture_ (Phase-1b) **and** reused in the _data-security / compliance_ plan filenames (Path-B). Two agents per code in the plan namespace. Cosmetic but worth a one-time reconciliation before external docs cite codes.

---

## 2. Wiz coverage (Axis 2) — estimated ~56–60%

**Baseline correction first:** the oft-cited **30.8%** (2026-05-13) was over-reported (weights summed to 1.15); the _corrected_ baseline is **~26.8%** (`docs/_meta/wiz-coverage-math-correction-2026-05-16.md`). Last _measured_ anchors: **54.0%** post-A.1 (05-16), **~59.75%** post-D.5 (05-20). **No readiness snapshot was produced after the full 17-agent push**, so the current number is an **estimate** built bottom-up from the pinned weights + cited per-family coverage.

| Capability (weight)      | Agent(s)                                | Coverage |  Weighted | Basis                   |
| ------------------------ | --------------------------------------- | -------: | --------: | ----------------------- |
| CSPM (0.35)              | cloud-posture, multi-cloud, k8s-posture |      84% |     0.294 | measured                |
| Vulnerability (0.13)     | vulnerability                           |      20% |     0.026 | measured (offline only) |
| CIEM (0.09)              | identity                                |      30% |     0.027 | measured (AWS IAM only) |
| CWPP (0.09)              | runtime-threat                          |      50% |     0.045 | measured                |
| DSPM (0.07)              | data-security                           |      25% |     0.018 | measured (0→25)         |
| CDR/Investigation (0.06) | investigation                           |      85% |     0.051 | measured                |
| Network Threat (0.04)    | network-threat                          |      80% |     0.032 | measured                |
| Compliance/Audit (0.04)  | audit + compliance                      |     100% |     0.040 | measured (saturated)    |
| AppSec (0.04)            | _none_                                  |       0% |         0 | measured                |
| Remediation (0.04)       | remediation                             |      50% |     0.020 | measured (K8s-only)     |
| Threat Intel (0.03)      | threat-intel                            |      25% |    0.0075 | estimate (15→25)        |
| AI/SaaS Posture (0.02)   | _none_                                  |       0% |         0 | measured                |
| **TOTAL**                |                                         |          | **~0.56** |                         |

**Defensible headline: "~56–60% weighted (estimated) vs a corrected ~27% baseline."** (~56% bottom-up from cited sources; ~60% if you trust D.5's unverifiable ~58% pre-D.5 anchor — the referenced `system-readiness-2026-05-19.md` is **not in the repo**.)

**Biggest weighted upside:** **Vulnerability** (0.13 @ 20% — live registry scanning is the single largest lever), **AppSec** (0.04 @ 0% — entirely unbuilt; needs a new agent), **CIEM** (0.09 @ 30% — Azure/GCP), **DSPM** (0.07 @ 25%). **Strongest:** Compliance/Audit (100%), CDR (85%), CSPM (84%).

---

## 3. v0.1 → v0.2 maturity gaps (Axis 3)

Universal deferral: **multi-tenant production** (blocked on the SET LOCAL bug — §8). Per-agent natural v0.2 scope (source: `docs/superpowers/sketches/2026-05-20-agent-version-roadmaps.md` + per-agent READMEs):

| Agent                | v0.1 deferred → natural v0.2                                                                                                          |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| Cloud Posture (F.3)  | LocalStack-only → **live boto3 + account autodiscovery**; ~700→1,200+ patterns; Organizations                                         |
| Vulnerability (D.1)  | offline JSON → **live registry scanning** + image-pull-policy; supply-chain (Phase 2)                                                 |
| Identity (D.2)       | AWS IAM only → **Azure AD/Entra** (v0.2), GCP+federation forensics (v0.3)                                                             |
| Runtime Threat (D.3) | Linux/Falco only, detect-only → Windows CWPP; autonomous-kill → A.1 Tier-1                                                            |
| Audit (F.6)          | file-backed → cross-tenant alerting; SemanticStore migration                                                                          |
| Network Threat (D.4) | static intel + offline flow → **live `describe_flow_logs` + S3/Athena + live IOC (D.8 ✅)**; Tor/beacon baselines (needs TimescaleDB) |
| Multi-Cloud (D.5)    | offline → **live Azure/GCP SDK** (needs per-cloud credential substrate)                                                               |
| K8s Posture (D.6)    | already v0.3 (live cluster) → rule expansion to CIS Benchmark; admission-controller                                                   |
| Investigation (D.7)  | already v0.2 → IOC pivoting (D.8), real-time triage (Phase 2)                                                                         |
| Remediation (A.1)    | K8s 5-class → +3 classes (v0.2), AWS Custodian (v0.3), Azure/GCP (v0.4)                                                               |
| Data Security        | AWS-S3-only offline → live boto3 + classifier expansion + Macie cross-val                                                             |
| Compliance           | CIS-AWS only, FAIL-only → SOC2/PCI/HIPAA/NIST + PASS attestations + `findings.>` subscribe                                            |
| Threat Intel (D.8)   | 3 offline feeds → **live HTTP + MISP/STIX-TAXII + abuse.ch/VT** (populates IOCs)                                                      |
| Curiosity (D.12)     | 1 detector, producer-only → more detectors + consumer wire-up + live-LLM                                                              |
| Synthesis (D.13)     | markdown only, no OCSF → **OCSF emit** + re-narration + fabric event                                                                  |
| Meta-Harness (A.4)   | (see §9 — v0.3 = optimization closure)                                                                                                |
| Supervisor (#0)      | stateless routing → escalation handler + Tier-2/3 → ChatOps; context writes                                                           |

Most v0.1-shipping prerequisites for v0.2 dependency chains are now **satisfied** (D.8 shipped unblocks D.4/D.7 IOC; D.5 unblocks D.6; D.12 unblocks D.13). The remaining blockers are the **live-cloud credential substrate** and **TimescaleDB** (temporal/drift) — both unscoped.

---

## 4. v2.0 substrate readiness — attack-path layer (Axis 4)

| Component                    | State                                                   | Evidence                                                                                                                                                                                                |
| ---------------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Security-graph storage       | **Prototyped — but two divergent substrates**           | Postgres `SemanticStore` (`charter/memory/semantic.py`, canonical, 6+ agent writers via `kg_writer.py`) **vs** a Neo4j writer used only by cloud-posture (`tools/neo4j_kg.py`, 79 LOC). Not reconciled. |
| Attack-path traversal        | **Prototyped (generic BFS, not attack-aware)**          | `SemanticStore.neighbors()` depth-3 BFS (used by investigation `memory_walk`). No edge-weighting, exploitability, or path-ranking.                                                                      |
| Cross-agent correlation      | **Prototyped (real, but filesystem-pinned + pairwise)** | D.7 `related_findings`, D.8 `correlators/` (CVE×KEV, IOC×network/runtime), D.13 `sibling_workspace_reader`. No central engine; reads sibling `findings.json`. NATS broker not installed.                |
| Probability/exposure scoring | **Per-agent table-driven; no graph-wide model**         | D.8 `scorer.py` (KEV→CRITICAL). Composite CVSS×EPSS×KEV×asset-criticality is doc-only (agent spec).                                                                                                     |
| OCSF v1.3 finding-chaining   | **Wire format ✅; chaining partial**                    | Universal `class_uid` + stable `finding_info.uid` + `correlation_id` propagation; no modeled attack-chain.                                                                                              |

**Bottom line:** v2.0 is **~one substrate-decision (an ADR picking the attack-graph home) away from "ready to start,"** but the attack-path semantics, exposure model, and substrate reconciliation are **greenfield** and partly blocked behind the tenant-RLS bug. Expect an ADR + dedicated plan before starting.

---

## 5. v3.0 substrate readiness — Cure track (Axis 5)

**The most-ready layer in the repo — already shipped at v0.1.** The original A.1/A.2/A.3 three-plan split was re-scoped (2026-05-16) into **one** `remediation` agent; all three tiers ship as `--mode` flags:

| Component                | State     | Evidence                                                                                                                                                                                |
| ------------------------ | --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tier-3 / Tier-2 / Tier-1 | **BUILT** | `recommend` / `dry_run` / `execute(+rollback)` modes; 7-stage pipeline; ~4,400 LOC / 22 modules / 15 eval cases. K8s-only (5 action classes).                                           |
| Operator approval gates  | **BUILT** | `authz.py` 4 gates (mode/allowlist/blast-radius cap/rollback window) + earned-autonomy `promotion/` pipeline (4 stages, operator sign-off; Stage-3→4 closed pending customer evidence). |
| Dry-run framework        | **BUILT** | `kubectl --dry-run=server`; emits `dry_run_diffs.json`. K8s-only.                                                                                                                       |
| Rollback orchestration   | **BUILT** | `validator.py`: waits window, **re-runs the detector**, inverse-patches if rule still fires. Per-action `(build, inverse)` pairs.                                                       |

**Deferred per-agent Tier-1 surfaces (documented, unbuilt):** D.4 `block_ip_at_waf` (WAF substrate), D.2 JIT/revoke, D.5 bucket-public-block, multi-cloud Track-A actions, D.1 vuln remediation, A.1 high-blast K8s classes. Each needs its action substrate (WAF/IAM/Custodian) before wiring to A.1's generator.

**Bottom line:** v3.0 is **breadth-expansion** (new action domains + ChatOps approval surface), **not foundational substrate work**. It's effectively already started.

---

## 6. Cross-agent health audit (Axis 6)

- **Suites green.** Sampled on HEAD: investigation 250✅, cloud-posture 88✅(3 live-skip), identity 142✅, vulnerability 111✅, charter 277✅(8 skip), shared 162✅(4 skip). No failures/flakiness. **~4,360 tests** repo-wide (`def test_` count; actual collected is higher via parametrization).
- **Eval-gate adoption: 17/17.** Full.
- **OCSF currency: uniform v1.3.0** (`OCSF_VERSION="1.3.0"` constant). No schema drift.
- **Substrate consistency:** `charter.nlah_loader` 17/17. LLM access split (11 via `charter.llm_adapter`, 6 via `charter.llm.LLMProvider` directly) — **intentional layering, not drift** (worth a one-line ADR note).
- **ADR currency:** 12 ADRs (001–012, no gaps). Churn concentrated in **ADR-007** (reference-agent shape, heavily versioned — the canonical shape all agents track; watch-item: an agent could lag the shape, not currently observed). ADR-006/007 amended in v0.2.5.
- `content-packs` and `edge` carry **0 tests** — flag if they hold logic.

---

## 7. Customer / design-partner visible state (Axis 7)

What a design partner would see **today**:

- **Per-agent CLIs** (each agent has `cli.py`) running in **offline / fixture mode** — real OCSF v1.3 findings JSON output, but against pinned sample data, not live cloud.
- **Runbooks for 9/17 agents** (operator-facing triage guides).
- **No console / UI** — there is **no S.1 surface package** (still 0 LOC; consistent with prior readiness). **No ChatOps/Slack.** No web app.
- **No live multi-cloud demo** — everything is offline-fixture until the v0.2 live-feed work.
- **`control-plane` + `edge` are minimal** (9 src modules combined).

**Implication:** the platform is **engineering-credible but not yet demo-credible to a design partner in a live environment.** The shortest path to a compelling live demo is maturing one pillar agent (F.3) to live cloud feeds + standing up a minimal surface. This is the strategic tension the maturity arc resolves.

---

## 8. Technical debt + risk surface (Axis 8) — honest accounting

**Inline code debt is ~zero** — after filtering false positives, **no real TODO/FIXME/HACK markers** in `packages/**/*.py`. Debt is parked in tracked memory + verification records, not comments (healthy discipline; means the risk surface lives outside the code).

**Tracked, unresolved (verified against HEAD):**

1. **🔴 SET LOCAL tenant-RLS bug — STILL PRESENT (top finding).** `charter/memory/service.py:96` issues `SET LOCAL app.tenant_id = :tid` with a bound param → Postgres rejects placeholders on `SET LOCAL` (`$1` on the wire) → `PostgresSyntaxError`. 5/6 charter live tenant tests fail. **Multi-tenant isolation is broken on real Postgres.** Consciously deferred (single-tenant dev unaffected); fix is known (`SELECT set_config('app.tenant_id', :tid, true)`). **Will surprise a multi-tenant launch** and currently **gates the v2.0 SemanticStore-as-attack-graph path** + cleanup elsewhere.
2. **🟡 KG-loop cross-run AFFECTS-edge dedup** — within-run only; cross-run duplicates accumulate → graph bloat over repeated runs. Consciously accepted; needs a UNIQUE constraint (blocked by substrate-seal) or a read round-trip.
3. **🟡 D.5/D.6 plan-code collision** (§1) — cosmetic naming inconsistency.
4. **🟡 Runbook gap** — 6/17 agents lack runbooks (§1).

**Architectural watch-items (not bugs):** ADR-007 reference-shape churn; the benign two-way LLM-import split (worth an ADR note).

---

## 9. Meta-harness state post-v0.2.5 (Axis 9) — confirmed closed on main

- **v0.2.5 IS closed on `origin/main`** (`4b17250`, PR #240 merged 2026-06-07; PRs #236–#240 all MERGED; closure docs + flag on main). _(A first-pass investigation flagged "#240 not on main"; that was a stale-fetch artifact — corrected after `git fetch`.)_
- **`NEXUS_DSPY_PRODUCTION` is default-OFF** — verified at `compilation_factory.py` (`make_default_dspy_factory` returns `None` unless `=="1"`).
- **No post-closure meta-harness drift** on main.
- **Three v0.3 carry-forwards tracked** (verification record §10 + memory): Task 14 Anthropic switch (deferred), **drift #10** GEPA metric prediction-invariant (needs prediction-sensitive reward), **T2** trace persistence. Honest caveat stands: architecture verified, optimization quality not yet realized; **flag stays OFF until all three clear**.
- Backlog parked per operator: meta-harness behavioral validation (v0.3); Wazuh extraction (parked).

---

## 10. Recommended first maturity-arc agent (Axis 10)

**Selection lens:** strategic weight × **pattern utility** (what reusable lesson does maturing this agent teach?) × baseline stability × clean v0.2 path × substrate availability × demo value.

| Candidate             | Strategic weight           | Pattern utility                                                                                        | Clean v0.2 path                               | Substrate gap                                                                         |
| --------------------- | -------------------------- | ------------------------------------------------------------------------------------------------------ | --------------------------------------------- | ------------------------------------------------------------------------------------- |
| **F.3 Cloud Posture** | **Highest** (CSPM 0.35)    | **Highest** — ADR-007 reference agent; its v0.1→v0.2 "live cloud feed" pattern is reused by ~10 agents | LocalStack → live boto3                       | needs a **live AWS sandbox + credential substrate** (needed for the whole arc anyway) |
| D.1 Vulnerability     | High (0.13, biggest _gap_) | Medium                                                                                                 | offline JSON → live registry                  | live registry creds                                                                   |
| D.4 Network Threat    | Lower (0.04)               | Medium (mirrors D.3)                                                                                   | offline flow → live VPC/Athena + D.8 IOC (✅) | block action needs WAF (defer)                                                        |

**Recommendation: F.3 Cloud Posture.** Three reasons: (1) **maximal pattern reuse** — F.3 is the ADR-007 reference agent; the live-cloud-feed + credential-substrate pattern it pioneers in v0.2 is the exact transition ~10 other agents need, so maturing it _first_ de-risks the entire serial arc; (2) **heaviest strategic weight** — CSPM (0.35) is the platform's biggest Wiz row and the canonical Wiz-equivalence pitch; a live F.3 is the most demo-credible artifact; (3) **stablest baseline** — earliest agent, most-built-upon, well-understood.

**Alternates:** choose **D.1 Vulnerability** if the priority is _raw coverage-% lift_ (its 0.13-weight row at 20% is the single biggest weighted lever). Choose **D.4 Network Threat** (the original instinct) if the priority is a _low-risk warm-up_ — its v0.2 deps (live VPC flow + D.8 IOC) are unblocked and it mirrors the proven D.3 pattern, though its Wiz weight is small and the Tier-1 block action needs a WAF substrate it should defer.

**Cross-cutting prerequisite to flag:** every "live feed" v0.2 needs a **live-cloud credential/sandbox substrate** that does not yet exist. Whichever agent goes first will pioneer it — another argument for the **reference agent (F.3)** to do so, so the substrate pattern is canonical from the start.

---

## Appendix — method + sources

- **Investigation:** 4 parallel read-only agents (inventory; Wiz+gaps; v2.0/v3.0 substrate; health/debt/meta), synthesized + spot-checked here. The one material subagent error (PR #240 closure state) was caught and corrected against `origin/main`.
- **Key sources:** `docs/_meta/wiz-coverage-math-correction-2026-05-16.md`, `system-readiness-2026-05-16-post-a1.md`, `d-5-data-security-v0-1-verification-2026-05-20.md`, `docs/superpowers/sketches/2026-05-20-agent-version-roadmaps.md`, per-agent verification records + READMEs, `charter/memory/service.py`, `agents/remediation/`, the v0.2.5 verification record, and the tracked-debt memory.
- **Estimates flagged:** the ~56–60% Wiz number is an estimate (no post-17-agent measured snapshot exists); per-family coverage % through CSPM/CDR/etc. are measured/cited.
