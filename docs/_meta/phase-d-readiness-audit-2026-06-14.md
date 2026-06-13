# Phase D Readiness Audit — 2026-06-14

**Subject:** main HEAD post-`#646` (Phase C complete; content HEAD `1d7e181`). **Type:** pre-build
verification audit of v0.3 / Phase D scope — NOT a directive, NOT a plan, NOT a code change.
**Method:** ground-truth reading against main (5 dimensions audited in parallel) with file:line
evidence and verbatim source quotes; architectural decisions **surfaced, not answered**; scope
boundaries held (no Phase 0 design). **Discipline:** doc-only, `[LOW-RISK]`, substrate seal EMPTY.
**Institutional artifact #3** after the v0.2 Quality Audit (#622) and the Phase C Completion Record
(#646).

> **Reading guide.** This audit replicates #622's discipline: measure existing state, surface
> decisions, find miscounts before they manufacture work. It does that — and in doing so it
> **materially corrects four premises in the commissioning directive itself.** Those corrections
> are the headline; read §0 first.

---

## §0 — Premise corrections (read first)

The audit found that four framing assumptions in the Phase D scope do not match main. Per the
"trust main over memory" rule (#A4) and "surface new PRD scope" rule (#20), they are stated up
front so the eventual v0.3 directive is calibrated to reality, not to the estimate.

1. **"5 net-new agents (A.2, A.3, D.9, D.10, D.11)" → actually 2–3, and the codes don't exist.**
   - **A.2 and A.3 are not net-new.** They were re-scoped into the single shipped `remediation`
     agent on 2026-05-16. Verbatim, `docs/_meta/nexus-platform-readiness-2026-06-07.md:127`:
     _"The original A.1/A.2/A.3 three-plan split was re-scoped (2026-05-16) into **one**
     `remediation` agent; all three tiers ship as `--mode` flags."_ Their successor is "Platform
     v3.0 — cure breadth" (A.1 _expansion_), not new agents.
   - **No `D.9` / `D.10` / `D.11` codes exist** anywhere in `docs/` or `packages/` (grep). The
     agent series stops at D.13. The genuine net-new surface is **AppSec / IaC / secrets / SBOM**
     and **AI-SPM** and **SSPM** — and the current strategic roadmap (`nexus-agent-maturity-
roadmap-2026-06-07.md:57-58`) collapses these to **two** cycles (AppSec @ Wiz 0.04; AI-SPM +
     SSPM bundled @ 0.02). The D.9/D.10/D.11 → AppSec/SSPM/AI-SPM mapping in this audit is the
     **auditor's labelling for cross-reference only; operator must ratify codes before any build.**

2. **"~63% Wiz-weighted coverage" → recomputed to ~57% (range 55–58%).** No coverage doc states
   63%. The verified recompute (§Dimension 2, arithmetic shown) lands at **0.5673 ≈ 56.7%**, only
   **+2.7pp** above the 54.0% post-A.1 baseline — because the v0.2 cycles bought **liveness
   infrastructure, not depth**, and most capability rows held near baseline. The directive's ~63%
   overstates by ~6pp.

3. **"dementor" inventory seam — the term does not exist in the repo.** `grep -rin "dementor"` over
   all `.md`/`.py` → zero hits. The real inventory substrate is the **`SemanticStore`** graph-write
   seam + per-agent `kg_writer.py` wrappers, with a dormant Neo4j twin (ADR-009). The seam is in
   good shape; the gap is documentation (no node-ownership map), not code. ("dementor" appears to be
   an operator codename not yet landed in docs — flag for capture.)

4. **"Hermes for inventory-hunting" — undocumented framing.** The verbatim phrase appears nowhere in
   `docs/`. The Hermes adoption doc is framed entirely around tool/skill self-evolution. The closest
   repo concepts are "nectar inventory" (a list of Hermes patterns to absorb) and D.12 curiosity's
   "gap-hunting." Treat inventory-hunting as an operator-supplied premise needing a design doc.

**Plus a gating contradiction the operator must resolve:** the roadmap locks net-new agents as
_"explicitly parked until all 17 agents reach Level 3"_ (`nexus-agent-maturity-roadmap-2026-06-07.md:25`),
but the fleet is at **v0.2 (≈ Level 2)**, not Level 3. Under the locked rule, net-new builds are
**not yet eligible to start**. Either the rule relaxes for Phase D, or Phase D is depth-first. This
is decision **Q1** below.

---

## §1 — Audit framework + scope boundaries

- **Measured, did not prescribe.** Recommendations are marked as such; architectural decisions are
  listed in §8, not answered.
- **Ground-truthed against main** with `ls`/`grep`/`find` + verbatim doc quotes. Where memory or the
  directive disagreed with main, main wins and the discrepancy is documented.
- **Scope held.** No Phase 0 inventory-schema/writer-interface/Neo4j design was produced (#A1). Items
  that would be Phase 0 design are flagged "not pursued."
- **Out of scope:** the v0.3 directive itself (comes after this audit), Phase 0 design, Phases 2–5,
  any code change.

---

## §2 — Executive summary

**Fleet state entering Phase D:** 17 agents at v0.2, all safety invariants load-bearing (Phase C,
#646), full repo 7109 passed / 0 failed. v0.2 delivered **breadth + liveness infrastructure**; depth
and the continuous operating loop are the Phase D / v0.3 frontier.

**Top findings by dimension:**

- **D1 (net-new agents):** 2–3 genuine net-new agents (AppSec, AI-SPM, SSPM), all at **0%**, none
  stubbed, all OSS tooling greenfield (Semgrep/Checkov/Trufflehog/Syft/Grype/Garak/ModelScan/PyRIT
  — zero present in any `pyproject.toml`). A.2/A.3 are not new. Strong reuse templates exist (D.1 for
  AppSec scanning; identity's Azure-AD/Graph/OAuth for SSPM; synthesis/curiosity `providers/` for
  AI-SPM LLM access). ~5 architectural Q's per agent surfaced.
- **D2 (depth + coverage):** **Verified ~56.7%** (not ~63%). Highest-leverage depth levers, in
  order: (1) Phase-C-style live→OCSF run-loop wiring across ~12 agents (+5–8pp), (2) D.1
  Vulnerability reachability (0.13 weight, +5.9pp single largest), (3) CSPM rule breadth (0.35
  weight, +3.9pp), (4) D.2 CIEM effective-perms (**built-but-undriven** — cheapest depth win,
  +3.0pp). Detector depth alone caps **~75–80%**; the last ~5–10pp to the 85% _post-GA_ target needs
  the v2.0 attack-path graph + the 2 net-new agents.
- **D3 (Hermes):** The adoption doc's own verdict is **"directly adoptable code: NONE; REBUILD."**
  A.4's DSPy/GEPA machinery exists but is **fully dormant at the `run()` level** (factory never
  constructed/injected); activation needs `NEXUS_DSPY_PRODUCTION=1` **plus** a run()-wiring step
  **plus** 2 of the 3 v0.3 readiness gates (prediction-sensitive reward, trace persistence). `gepa`
  dep is unpinned. Upstream re-check (v0.15.0 trigger) is an unrun follow-up (no network).
- **D4 (continuous loop):** Driver + adapters + 6 per-agent schedulers **exist and are tested, but
  none are instantiated in the production CLI** — `Heartbeat` defaults both sources to no-ops, and
  `cli.py` passes neither. This is consistent with the Phase C doc's own "wired but not auto-driven"
  deferral. **Top activation risk:** budget is **per-invocation, not per-tenant-per-window**
  (`context.py:41` rebuilds it each run) → unbounded daily spend under a loop. No per-tenant
  kill-switch and no customer "last refreshed" signal exist.
- **D5 (Phase 0 seam):** The write seam is **healthy and needs no retrofit** — `SemanticStore` +
  the `kg_writer.py` class-shape + a dormant Neo4j twin make the backend swap a one-layer change
  (ADR-009 §188-196). Retrofit risk is upstream in _documentation_: no node-ownership map exists,
  net-new agents have no declared node types. The genuine cross-track blocker is the **SET LOCAL
  `$1` tenant-RLS bug** gating the multi-tenant graph.

**Recommended v0.3 directive shape (recommendation, not decision):** depth-first (Track 2) is both
the highest-leverage and the only track currently _unblocked_ by the parked-until-L3 rule; the
continuous-loop wiring is a natural consolidated sprint that unlocks deferred breadth; net-new agents
and Hermes activation depend on operator decisions in §8.

---

## Dimension 1 — Net-new agent readiness

**Net-new surface (codes are auditor labels; operator to ratify):**

| Audit label  | Real capability                                           | Wiz weight    | Stub in repo?                                                                | PRD section                                                 | OSS deps present?                                                 |
| ------------ | --------------------------------------------------------- | ------------- | ---------------------------------------------------------------------------- | ----------------------------------------------------------- | ----------------------------------------------------------------- |
| (n/a) AppSec | IaC + secrets-in-code + SBOM/SCA + supply-chain           | 0.04          | **none** (`competitive-benchmark-2026-06-08.md:1019` "0% — no agent exists") | PRD §7.1.6 (secrets), §7.1.7 (IaC); split with D.1 for SBOM | **none** (semgrep/checkov/trufflehog/gitleaks/syft/grype: 0 hits) |
| (n/a) AI-SPM | AI asset inventory + AI-BOM + model/LLM security          | 0.02 (paired) | **none** (`:1029`)                                                           | PRD §7.1.9 (full section)                                   | **none** (garak/modelscan/pyrit/llm-guard: 0 hits)                |
| (n/a) SSPM   | SaaS posture (M365/Workspace/Salesforce/Slack/GitHub-org) | 0.02 (paired) | **none** (`:1041`)                                                           | **no dedicated PRD §** (benchmark only)                     | **none** (per-SaaS API connectors, greenfield)                    |
| A.2 / A.3    | **re-scoped into `remediation`**                          | —             | n/a — shipped as `--mode`                                                    | system-readiness-2026-05-16:169-170 (historical)            | n/a                                                               |

**Reuse templates (grep-confirmed):** AppSec ← D.1 vulnerability (scanner orchestration, registry-
token auth, per-cloud live lanes) + identity STS read-only pattern. SSPM ← identity (live Azure AD
via httpx+GraphReader, SAML/OIDC federation — the exact OAuth/Graph substrate). AI-SPM ←
synthesis/curiosity `providers/{fallback,cost_tracking}.py` + `charter.llm_adapter` + DSPM classifier
for training-data scanning. All three reuse charter/NLAH/eval-runner/OCSF scaffolding.

**PRD ambiguity flagged:** SBOM/SCA is **double-assigned** — PRD §7.1.5 lists Syft/Grype/
Dependency-Track under _Vulnerability (D.1)_, while the benchmark gives SBOM to the new AppSec agent.
Ownership unresolved (→ Q-AppSec-1). AI-SPM training-data overlaps DSPM but the benchmark is explicit
it is _"a net-new agent, not a DSPM feature"_ (`competitive-benchmark:1033`). SSPM/Identity boundary
undefined (both consume Azure AD / Okta / Workspace).

**Per-agent architectural Q's** (surfaced, not answered) — full list in §8.

**Inventory seam preview (design-awareness):** none of the canonical node types
(`platform_architecture.md:326`) cover the net-new agents. AppSec would add Repository / CodeArtifact
/ IaC-Template / Secret + the **code-to-cloud edge** (the marquee differentiator, unmodeled). AI-SPM
adds AIService / Model / TrainingDataset / Endpoint / Registry + ATLAS→`Technique`. SSPM adds SaaSApp
/ SaaSAccount / OAuthGrant / ThirdPartyApp / SharingPolicy. **None documented** (= Phase 0 design;
flagged, not pursued).

---

## Dimension 2 — Depth-track baseline + Wiz-weighted recompute

### The recompute (corrected weights from `wiz-coverage-math-correction-2026-05-16.md`, re-verified sum = 1.0000)

Coverage = the **realized `[estimate]`** midpoint from each agent's v0.2 verification record (every
record's §5 states v0.2 shipped infrastructure/breadth, not depth, and the live→OCSF loop is
deferred to Phase C — so rows did not move to the roadmap's L2 hopes).

| Capability                |   Weight |                                             Realized cov | Contribution |
| ------------------------- | -------: | -------------------------------------------------------: | -----------: |
| CSPM (F.3+D.5+D.6)        |     0.35 |                                                      84% |       0.2940 |
| Vulnerability (D.1)       |     0.13 |                                                      20% |       0.0260 |
| CIEM (D.2)                |     0.09 |    37.5% (AWS-primary; Azure net-new not blended, WI-I1) |       0.0338 |
| CWPP (D.3)                |     0.09 |                                                    52.5% |       0.0473 |
| DSPM                      |     0.07 |                                                      50% |       0.0350 |
| CDR / Investigation (D.7) |     0.06 |                                                    57.5% |       0.0345 |
| Network Threat (D.4)      |     0.04 |                                                    32.5% |       0.0130 |
| Compliance / Audit (F.6)  |     0.04 | 100% (audit-saturated; ⚠ compliance _breadth_ only ~35%) |       0.0400 |
| AppSec                    |     0.04 |                                                       0% |            0 |
| Remediation (A.1)         |     0.04 |                                                      55% |       0.0220 |
| Threat Intel (D.8)        |     0.03 |                                                    72.5% |       0.0217 |
| AI / SaaS Posture         |     0.02 |                                                       0% |            0 |
| **TOTAL**                 | **1.00** |                                                          |   **0.5673** |

### ✅ Verified: **~56.7% (range 55.4–58.1%)** — replaces the unsupported ~63%.

**Caveats that must travel with the number:** (1) all values are `[estimate]` ranges, never
instrumented; (2) CSPM 84% is a carried-forward F.3 judgement (F.3 had _zero_ rule movement in v0.2;
k8s realized only ~30-35%); (3) the Compliance/Audit 100% row credits audit saturation while
compliance _framework breadth_ is only ~35% — re-rating drops the total ~2pp to ~55%; (4) CIEM has
no aggregate by design — AWS-primary chosen.

### Per-agent depth gaps + closure path

Highest-leverage depth investments (weight × coverage-delta), in order: **Phase C live→OCSF wiring**
(~+5–8pp across 12 agents) → **D.1 reachability** (+5.9pp, biggest single lever) → **CSPM rule
breadth** (+3.9pp) → **D.2 effective-perms** (+3.0pp, _already built, undriven_) → **2 net-new
agents** (+4.2pp combined). **Honest ceiling:** detector depth caps ~75–80%; the final push to 85%
needs the v2.0 graph (greenfield, blocked behind the tenant-RLS bug). Full per-agent table + the
dependency map are in the dimension working notes; the load-bearing dependencies are: D.1
supply-chain depends on the AppSec/SBOM agent; multi-tenant depth blocked by SET LOCAL `$1`;
TimescaleDB unscoped for D.4/compliance drift.

---

## Dimension 3 — Hermes self-evolution baseline

**Upstream (from `hermes-self-evolution-adoption-2026-05-23.md`, read in full):** Hermes `v0.14.0`,
Apache-2.0; Phase 1 of 5 shipped ("experimental"), Phases 2–5 are README-only (no code). Doc's own
verdict: **"Directly adoptable code: NONE … Hermes code: REBUILD"** (single-user arch, incompatible
deps — LangChain/ChromaDB/OpenAI vs Nexus charter/SemanticStore/Anthropic). **Follow-up flag:** doc
is a 2026-05-23 snapshot; its own Risk 4 names a **v0.15.0** upstream release as the reassessment
trigger — network not consulted this audit; re-check required.

**A.4 readiness — DSPy path fully dormant at run():** `compilation_cadence.py` (decision-half;
event + lazy-cron cadence) is imported only by `compilation_factory.py`, which is imported by
**nothing** in `src/`. `agent.py run()` calls `run_skill_lifecycle(...)` but **never passes
`dspy_candidate_factory=`**, so the legacy branch always runs. Activation requires **three** things,
not one: (a) `NEXUS_DSPY_PRODUCTION=1` (gates factory _construction_ — `compilation_factory.py:230`),
(b) an unbuilt run()-wiring step in `agent.py`/`cli.py` to actually construct+inject the factory,
(c) v0.3 gates 2+3 (prediction-sensitive GEPA reward; originating-trace persistence) — without
gate 3 the trainset is empty and the factory no-ops even when flagged on. `dspy>=2.5` (no upper
bound); **`gepa` completely unpinned** (`pyproject.toml:28`). `skill_discovery.py` ("Task 5") is
imported by no source module.

**Integration depth (doc's verdicts, restated):** P1 REBUILT (shipped Nexus-native); P2 REBUILD-with-
DSPy/GEPA (in progress, gated); P3 Curator = ADOPT-design/REBUILD-code (deferred to v0.3); P4
Feedback = ADOPT-concept/REBUILD-code (partially realized via dormant G1 modules); P5 Autonomous =
DEFER (v0.4+). "Twelve modules evaluated, zero adopted directly."

**Cross-agent impact:** D.13/D.7/D.12 all already carry the `providers/{fallback,cost_tracking}.py`
scaffold → adopting A.4-compiled skills is **MINOR per agent**. The heavy lift is concentrated in
A.4 and is **already-built-but-dormant** (wire the factory + flip 3 gates), not net-new construction.

**Inventory-hunting (undocumented premise):** the clean seam to preserve is the `DSPyCandidateFactory`
injection point in `run_skill_lifecycle` — generic enough that an inventory-candidate factory could
substitute without forking. But A.4 has **no inventory-writer surface** (writes only report + SKILL.md;
never publishes on the bus). The writer it would feed does not exist (= Phase 0; flagged).

---

## Dimension 4 — Continuous-loop autonomy readiness

**Phase C foundation (verified on main):** `ContinuousDriver` (`packages/runtime/.../continuous.py`)
is clean + failure-isolating (per-tenant try/except; `mark_ran` only on success). `ContinuousTrigger
Source` + `FabricEventsSource` classes exist. **But none are instantiated in production:**
`heartbeat.py:104` defaults `continuous_source` to a no-op; `supervisor/cli.py:267` constructs
`Heartbeat(...)` and passes **neither** source. 6 agents (compliance, curiosity, data-security,
investigation, remediation, synthesis) have `continuous/{scheduler,mode}.py` — **none run()-wired**
(zero `continuous` imports in their `agent.py`). Default-OFF confirmed at two layers (heartbeat
no-op + per-agent `MonitoringMode.HEARTBEAT` → always RECOMMEND). 5 `live-*.yml` are
workflow_dispatch-only. **Consistent with the Phase C doc's own "wired but not auto-driven."**

**Activation checklist (must-have in v0.3):** instantiate + inject the continuous source at
`cli.py:267`; register each agent scheduler with the driver (only done in tests today); a per-tenant
cadence config surface (contracts carry only `budget:`, no interval; `trigger_source` enum has no
`continuous` member); a per-tenant kill-switch (absent); and "all agents OPERATING" (only 6/17 have a
scheduler).

**Blast-radius (top risk):** `BudgetEnvelope` is **per-invocation** (`context.py:41` rebuilds it each
run) → N ticks/day × per-run budget = **unbounded daily spend**; a short interval multiplies LLM/
cloud cost linearly. Audit chain is **one-file-per-run, genesis-rooted each run** (`audit.py:55`) →
no cross-tick chaining/rotation → unbounded audit-file growth under sustained ticks. Multi-tenant
isolation is structurally sound (per-customer `flock` + strict `tenant_id` filtering).

**Signal loop + rollback:** no "last refreshed"/freshness surface exists (`grep` → 0). No per-tenant
runtime kill-switch (the only kill-switch is remediation's per-invocation `enable_execute`). Cleanest
rollback today = the current default-OFF state (don't wire the source).

---

## Dimension 5 — Phase 0 inventory seam

**Seam state — healthy, no retrofit needed.** The graph-write seam is `SemanticStore`
(`charter/memory/semantic.py`: `upsert_entity` :83, `add_relationship` :152, `neighbors` :189,
`MAX_TRAVERSAL_DEPTH=3`). Six agents write via a `kg_writer.py` wrapper; the only edge type in use is
`AFFECTS`. **No** `inventory.upsert_entity` / `upsert_edge` / `graph_write` named API — and per
ADR-009 §188 (_"every agent writes to the graph ONLY through MemoryService.semantic — no direct
drivers, ever"_) one is not needed. **Recommendation:** don't ship a new stub; make `kg_writer.py`
adoption a v0.3 per-agent checklist item.

**Neo4j swap-door — verified dormant-but-intact.** `cloud-posture/.../tools/neo4j_kg.py` is a
full async-Cypher `KnowledgeGraphWriter` (MERGE-based), deliberately class-shape-identical to the
active Postgres `kg_writer.py` (ADR-009:172-174). `neo4j>=5.24.0` stays a dep solely to keep it
importable. The swap is a **one-layer substrate change** (swap `SemanticStore`'s session factory),
triggered only at D.7 depth≥4 over >1M edges/tenant — reaffirmed, not triggered.

**Retrofit risk is documentation, not code:** no node-ownership map exists (the phrases "Agent
ownership of the inventory" / "capability-driven ownership" → 0 hits). Ownership today is
**capability/domain** (archived specs) + an **ad-hoc per-agent `entity_type` namespace** (`asset`/
`finding` = cloud-posture; `cve`/`ioc`/`ttp` = threat-intel; `hypothesis` = curiosity; etc.). Net-new
agents have **no declared node types**. Defining them = Phase 0 design (flagged, not pursued).

**Cross-track coupling chokepoint:** the single seam abstraction decouples all tracks from the
backend choice; the genuine multi-track blocker is the **SET LOCAL `$1` tenant-RLS bug** (gates
multi-tenant graph writes every track eventually needs), and depth (Track 2) is what eventually
_triggers_ the Neo4j swap.

---

## §8 — Architectural decisions surfaced (operator input needed)

Listed, not answered — these shape the v0.3 directive.

- **Q1 — Parked-until-L3 vs Phase D start.** Net-new agents are locked "parked until all 17 reach
  Level 3"; the fleet is at v0.2. Does Phase D (a) stay depth-first to push toward L3, (b) relax the
  rule to start net-new in parallel, or (c) a hybrid (depth on the high-weight agents + 1 net-new
  pilot)? **Recommendation:** (c) — depth-first with AppSec (highest-weight net-new, 0.04) piloted.
- **Q2 — Net-new agent count + codes.** Ratify: 2 cycles (AppSec; AI-SPM+SSPM bundled) or 3 separate
  agents? Assign real D-codes (D.9/D.10/D.11 are auditor inventions).
- **Q3 — Continuous-loop activation in v0.3?** Wire-and-activate (full operating loop, needs the
  per-tenant-window budget + kill-switch + cadence-config work) vs wire-but-keep-default-OFF
  (instantiate the source, register schedulers, leave the flag off). **Recommendation:** wire +
  default-OFF in v0.3; activate per-tenant in a later gated step once the budget/kill-switch land.
- **Q4 — Per-window budget model.** Activating the loop needs a cumulative per-tenant-per-window cap
  (today budget is per-invocation). Charter change — substrate. In v0.3 or deferred?
- **Q5 — Hermes/DSPy in v0.3?** Flip `NEXUS_DSPY_PRODUCTION` + build the run()-wiring + land gates
  2/3 — or hold the whole self-evolution track for v0.4? (Upstream v0.15.0 re-check is a prerequisite.)
- **Q6 — SBOM/SCA ownership** (AppSec vs D.1) and **SSPM/Identity boundary** and **AI-SPM/DSPM
  training-data boundary** — three scope-boundary decisions blocking net-new design.
- **Q7 — Node-ownership map** (Phase 0 design): commission it before or during net-new builds, so
  agents are built inventory-aware? **Recommendation:** a lightweight per-agent node-type
  declaration as a v0.3 design-awareness checklist (not the full schema).
- Per-agent Q's (Q-AppSec-1..5, Q-AISPM-1..5, Q-SSPM-1..5, Q-A2/A3-1..2) recorded in the dimension
  working notes.

---

## §9 — Honest deferrals + scope boundaries

- **Phase 0 design is NOT in this audit** — node schema, writer-interface extraction, node-ownership
  map, Neo4j cutover are all flagged-not-pursued.
- **The v0.3 directive is NOT this audit** — it follows, calibrated to these findings.
- **Upstream Hermes re-check** (v0.15.0) was not performed (no network) — required before any Hermes
  decision.
- **The "dementor" codename + "inventory-hunting" framing** need to land in a doc before they can be
  built against.

---

## §10 — Risk register

| Risk                                                        | Severity | Evidence                                    | Mitigation                                                                  |
| ----------------------------------------------------------- | -------- | ------------------------------------------- | --------------------------------------------------------------------------- |
| Continuous loop activated with per-invocation budget        | **High** | `context.py:41`                             | Per-tenant-window budget (Q4) before activation                             |
| 85% target read as detector-achievable                      | **High** | roadmap + detection-maturity doc            | Directive must state ~75–80% detector ceiling; graph + net-new for the rest |
| Net-new build started while parked-until-L3 holds           | Med      | roadmap:25                                  | Resolve Q1 explicitly in the directive                                      |
| SET LOCAL `$1` tenant-RLS bug gates multi-tenant graph/loop | **High** | `project_f5_set_local_tenant_rls_bug`; main | Substrate fix is a prerequisite for multi-tenant Phase D                    |
| DSPy "flip the flag" assumed sufficient                     | Med      | `compilation_factory.py` dormant at run()   | Directive must scope the run()-wiring + gates 2/3, not just the flag        |
| Coverage tracked as ~63%                                    | Med      | this audit                                  | Adopt ~57% as the calibrated baseline                                       |
| No per-tenant kill-switch / freshness signal                | Med      | grep → 0                                    | Build both as activation prerequisites                                      |
| `gepa` dep unpinned                                         | Low      | `pyproject.toml:28`                         | Pin before any DSPy activation                                              |

---

## §11 — Calibrated v0.3 estimate

**Honest, calibrated to the above (not the directive's assumptions):**

- **Scope is smaller on net-new than framed** (2–3 agents, not 5) but **larger on prerequisites**
  (per-window budget, kill-switch, cadence config, DSPy run()-wiring, node-ownership doc, the
  tenant-RLS substrate fix) than a pure "wire what exists" sprint.
- **Highest-leverage, unblocked work = depth** (Track 2) + the **continuous-loop wiring**
  (default-OFF). These can start immediately.
- **Net-new + Hermes activation are decision-gated** (Q1/Q2/Q5) and the multi-tenant paths are
  **substrate-gated** (SET LOCAL fix).
- **Coverage trajectory:** ~57% now → ~62–65% after live-loop wiring + the top depth levers →
  ~75–80% detector ceiling; **85% needs the v2.0 graph + 2 net-new agents** (a v2.0/v3.0 horizon,
  not v0.3 alone).
- A PR-count / calendar figure is **deliberately not asserted** until Q1–Q3 are decided — the count
  swings by a large factor depending on whether net-new and loop-activation are in or out of v0.3.

---

## Status

Phase D readiness established. The fleet is a sound base (v0.2, all invariants load-bearing); the
v0.3 frontier is **depth + the continuous operating loop**, with net-new agents and Hermes as
decision-gated tracks and the multi-tenant substrate fix (SET LOCAL `$1`) as the key prerequisite.
The four premise corrections in §0 and the seven decisions in §8 are the inputs the v0.3 directive
should be built on.
