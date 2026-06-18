# v0.4 Fleet Test Directive — The First Real Pressure Test

**Date:** 2026-06-18
**Author:** Operator (Praba)
**Status:** PROPOSED — pending operator approval + team brainstorms
**Target main:** post-#761 (Stage 3 rest closed)
**Anchored to:** v0.4 directive §R1 (instrumented 85% PRD coverage); detection-maturity doc canonical yardstick

---

## §0 Why this exists

The fleet has shipped. v0.3 closed OPERATING. v0.4 added depth + Hermes 2-5 + two net-new agents (D.10 SSPM + D.11 AI-SPM) + the cross-run dedup + kg_query 3-hop correlation surface.

**6,916 unit + integration tests verify each agent in isolation.**

**ZERO tests verify the fleet works as a fleet.**

We have not tested:

- Whether all 18 agents can run against a shared environment and produce coherent findings.
- Whether the kg_writers from 15 agents populate Postgres in a way that's actually traversable.
- Whether Hermes closes the loop for every agent — not just one.
- Whether cross-domain bridges (HOSTS_AI, IRSA_MAPPING, AUTHORIZED, SSO_INTO) actually chain in `kg_query` attack-path queries.
- Whether the substrate survives concurrent multi-tenant load.
- Whether blast-radius from a known violation surfaces the resources actually affected.
- Whether the LLM trio (Investigation + Synthesis + Curiosity) reasons correctly over a graph populated by the rest of the fleet.

This is unacceptable for "v0.4 OPERATING" to mean anything. The hard 85% PRD claim per directive R1 needs **instrumented evidence**, not estimates anchored on per-agent maturity. This directive sets the test scale that produces that evidence.

**Slogan:** Test the brain cells AND the brain. Each level. Each interaction. Each pressure.

---

## §1 The five phases

```
T1 — PER-AGENT E2E HARNESS         | foundation     | ~2 weeks | sequential
T2 — CROSS-AGENT CORRELATION       | spine works    | ~2 weeks | parallel after T1
T3 — HERMES LOOP CLOSURE           | feedback works | ~2 weeks | parallel with T2
T4 — CONCURRENCY + SCALE           | survives load  | ~2 weeks | parallel
T5 — PURE-BREED INTEGRATION FINALE | platform works | ~2-3 wk  | after T1+T2+T3

TOTAL: ~9 weeks with parallelism (~10-11 weeks sequential ceiling)
```

### T1 — Per-agent E2E harness (foundation)

**Goal:** Each agent works alone, against real backends, end-to-end.

**Scope:** One E2E test per agent — 18 tests total.

For each agent:

- Seed the agent's tool surface with realistic input (real cloud SDK fakes, real Falco events, real Kubernetes manifests, etc.)
- Inject opt-in `semantic_store` (real Postgres or in-memory; operator decides per Q-set)
- Run `agent.run()` end-to-end through the real code path
- Assert:
  - OCSF event emission valid against schema (2002 / 2003 / 2004 / 2005 / 2007 / 6003 per agent)
  - kg_writer wrote the expected entity types per ADR-018
  - kg_writer wrote the expected edges
  - F.6 audit chain stays clean and hash-verifiable
  - `tenant_id` propagates correctly (no cross-tenant edge leak)
  - Same input on `tenant_a` + `tenant_b` produces two separated subgraphs
  - Live-lane gates honored (default-off → byte-identical offline)
  - Detection found the seeded violation (no false negatives at the agent level)

**Deliverable:** 18 E2E tests in `packages/agents/<agent>/tests/e2e/test_fleet_e2e.py` per agent.

**Why first:** All later phases reuse these per-agent harnesses. Pure-breed in T5 IS these 18 tests running concurrently against shared state.

---

### T2 — Cross-agent correlation harness

**Goal:** The cells communicate through the ADR-018 spine. Toxic-combo detection actually surfaces.

**Scope:** 10–15 hand-built cross-domain scenarios.

Each scenario:

- Seed a topology in `SemanticStore` representing a real-world toxic combination
- Run `kg_query.blast_radius` from a starting node
- Run `kg_query.attack_path` between two nodes
- Assert traversal correctness (cycles excluded, depth-cap 3 honored, expected paths surface)

**Mandatory scenarios:**

1. D.1 CVE on resource X → D.3 runtime activity on X → A.4 blast_radius from X
2. D.10 SSPM finds OAuth app → D.2 federated identity → A.4 attack_path via AUTHORIZED + SSO_INTO
3. D.11 finds Bedrock without guardrail → cloud-posture links to AWS account → A.4 attack_path via HOSTS_AI
4. D.6 K8s privileged pod → IRSA_MAPPING → D.2 over-permissive role → A.4 attack_path
5. D.14 AppSec finds secret in repo → DEFINED_IN IaC artifact → cloud-posture resource deployed from it → A.4 attack_path
6. D.4 Data-security finds PII in S3 → D.2 over-permissive IAM → A.4 blast_radius
7. D.4 Network-threat sees COMMUNICATES_WITH from external IP → cloud-posture finds public endpoint → A.4 attack_path
8. D.8 Threat-intel matches IOC → D.3 runtime sees the IOC connection → A.4 blast_radius
9. D.5 Multi-cloud Azure finds public storage → D.4 Data-security classifies content → A.4 blast_radius
10. D.9 Compliance maps PCI 2.2 → 3 findings from D.1+D.3+D.4 → A.4 traversal
    11–15. Operator-defined scenarios per design-partner pain points (Livingston freight-forwarder context: hybrid AWS+Azure+on-premise; SSO from M365 → AWS via IAM Identity Center → privileged role → exposed S3 bucket with PII).

**Assertions per scenario:**

- Expected entities exist
- Expected edges exist (no missing bridges)
- `blast_radius` result = expected affected resource set
- `attack_path` result = expected edge chain
- Cycles excluded correctly
- Depth-cap 3 honored

**Deliverable:** `packages/agents/meta-harness/tests/e2e/test_correlation_scenarios.py` with 10–15 named scenarios.

---

### T3 — Hermes loop closure on every agent

**Goal:** The feedback loop closes for EVERY agent, not just one.

**Scope:** For each detection agent (12+ agents):

- Run a skill execution → `SkillTraceStore.record` writes the trace
- Run again with a different scenario → trainset now has 2 examples
- Mock compilation_cadence trigger → GEPA invoked with 2-example trainset (no LLM call in CI; verify trainset shape)
- Inject tie scenario → `skill_judge` runs additive ranking → verify additive (pass-rate floor stays hard)
- Mark skill for deprecation → dual-trigger fires → sunset period applied
- Run `dspy_flip_gate.evaluate` with synthetic evidence → verdict correct
  - 4 criteria True → AUTHORIZED
  - Any False → NOT_AUTHORIZED + named missing criteria

**Mandatory assertions:**

- Trace store has expected entries per (agent_id, skill_id) keyed pair
- Tenant isolation on trace store (tenant_a traces invisible to tenant_b)
- Compilation cadence triggered (factory-construction path verified)
- LLM-judge additive (never replaces pass-rate floor)
- Deprecation respects sunset period
- Gate 3 verdict + named criteria correct

**Deliverable:** `packages/agents/meta-harness/tests/e2e/test_hermes_per_agent.py` with one closure scenario per agent.

---

### T4 — Concurrency + scale pressure

**Goal:** The substrate survives production-shape load.

**Scope:** Real-Postgres-backed pressure tests:

#### T4.1 — Multi-agent parallel writes (UNIQUE race)

- Spawn N=18 agents writing kg_writer outputs concurrently
- Same edges sometimes written from multiple agents (intentional)
- Verify: no UNIQUE constraint violation crashes
- Verify: ON CONFLICT DO NOTHING semantics hold (first-wins; idempotent)
- Verify: no edge duplication

#### T4.2 — Multi-tenant parallel discovery

- 100 tenants × parallel discovery cycles
- Verify: per-tenant lock contention bounded
- Verify: no cross-tenant edge leak under load
- Verify: throughput target (TBD per operator Q-set)

#### T4.3 — Graph size at scale

- 10K entities × 100K edges per tenant
- Run `SemanticStore.neighbors(depth=3)` → measure latency
- Run `kg_query.attack_path` on dense graph → verify termination + correctness
- Verify: depth-cap 3 prevents runaway BFS

#### T4.4 — SkillTraceStore under load

- Concurrent record-at-deploy from multiple agents
- Verify: `ON CONFLICT` on (tenant_id, agent_id, skill_id) holds
- Verify: trainset builder returns correct N-example sets under contention

**Deliverable:** `packages/charter/tests/pressure/test_substrate_pressure.py` — gated behind `NEXUS_PRESSURE_TEST=1`.

---

### T5 — Pure-breed integration finale

**Goal:** Prove the entire platform does what it exists to do.

**Scope:** ONE integrated end-to-end test scenario.

#### The scenario

Seed a realistic mid-size enterprise environment (live-lane fakes; choice of real sandbox accounts per operator Q-set):

- 1 AWS account: 50 IAM users, 10 roles, 30 S3 buckets, 5 EC2 instances, 2 EKS clusters, 3 RDS, 5 Bedrock endpoints, 2 SageMaker
- 1 Azure tenant: 20 users, 5 storage accounts, 2 AKS, 3 Azure OpenAI
- 1 GCP project: 10 buckets, 1 GKE, 2 Vertex AI endpoints
- 1 M365 tenant (SSPM scope)
- 1 GitHub org (D.14 + D.10)
- 1 Slack workspace (D.10)
- Kubernetes events stream (D.3)
- Suricata + Zeek event stream (D.4 network)
- Falco event stream (D.3 runtime)

**Seeded intentional violations (the "ground truth"):**

1. Public S3 with PII (D.4 data + D.3 cloud-posture)
2. IAM role with wildcard policy (D.2 inline-policy doc fetch)
3. EKS pod with privileged SA + IRSA to wildcard IAM role (D.6 → IRSA bridge → D.2)
4. Falco event: shell spawn in privileged container (D.3 runtime)
5. Suricata: DNS DGA from compromised endpoint (D.4 network)
6. CVE on ECR image deployed to EKS (D.1 vuln → D.6 K8s)
7. Bedrock endpoint without guardrail, public (D.11)
8. M365 admin without MFA (D.10 SSPM)
9. GitHub OAuth app with org-write scope, unused 90 days (D.10 SSPM)
10. Repo with hard-coded secret + IaC misconfig + SAST violation (D.14 AppSec)
11. CSPM finding chain: misconfigured CloudTrail → no log delivery → no detection coverage (D.3 cloud-posture)
12. SSO from M365 → AWS via IAM Identity Center → privileged role → all the above (the cross-domain attack chain)

#### The execution

1. Supervisor agent receives the orchestration directive
2. Supervisor routes work to every detection agent in parallel
3. Each agent runs its real code path:
   - Detection: finds violations
   - Inventory: writes entities to shared Postgres SemanticStore via kg_writer
4. Hermes loop runs:
   - Skill executions emit
   - Traces persist in SkillTraceStore
   - Compilation cadence triggers (real path or mocked per Q-set)
   - LLM-judge ranks competing skill outputs
   - Deprecation evaluates lifecycle
5. LLM trio reasons over populated graph:
   - Investigation correlates findings
   - Synthesis narrates the cross-domain story
   - Curiosity surfaces hypotheses about uncovered surfaces
6. A.4 Meta-Harness runs:
   - `kg_query.blast_radius` from the privileged EKS pod → expected: all 5 affected resources
   - `kg_query.attack_path` from external-internet → privileged role → exposed S3 → PII data
7. F.6 audit chain runs throughout; verify integrity at the end
8. Re-run entire scenario on `tenant_b` with same seed → verify total isolation

#### The assertions

**Detection layer:**

- All 12 seeded violations surfaced as OCSF findings (no false negatives)
- False positives bounded (operator-set acceptable FP rate per Q-set)
- OCSF schema valid for every emission across all 6 event classes

**Inventory layer:**

- Postgres has expected node count per category (within ±5% of seeded ground truth)
- All 15 kg_writers wrote at least one entity (none silently inert)
- Cross-domain bridge edges present:
  - HOSTS_AI (cloud account → AI service)
  - IRSA_MAPPING (K8s SA → IAM role)
  - AUTHORIZED (OAuth app → SaaS tenant)
  - DEFINED_IN (IaC artifact → repo)
  - STORES_DATA (data classification → cloud resource)

**Correlation layer:**

- `blast_radius` from privileged EKS pod returns exactly: { EKS cluster, S3 bucket with PII, IAM role, dependent Lambda, downstream RDS }
- `attack_path` from internet → PII data follows: external → public bucket → IAM principal → SSO → M365 → privileged role → EKS → PII
- All 4 cross-domain bridges traversed in the attack path

**Hermes layer:**

- SkillTraceStore has entries for every agent that emitted a skill
- Compilation cadence triggered for at least one scoring trigger
- LLM-judge produced ranking on at least one tie scenario
- Deprecation evaluated at least one skill lifecycle
- Gate 3 verdict = NOT_AUTHORIZED with correct missing criteria (Task-14 + measured-delta)

**Audit layer:**

- F.6 audit chain stays hash-verifiable end-to-end (no broken links)
- Every tool call audited (per ADR-007 v1.3 always-on contract)
- Resolver tokens never present in audit log entries

**Tenant isolation:**

- `tenant_a` graph and `tenant_b` graph are byte-disjoint
- No cross-tenant edge leak anywhere
- Same scenario seed produces same per-tenant outputs

**Deliverable:** `packages/integration/tests/e2e/test_pure_breed.py` — gated behind `NEXUS_PURE_BREED=1` (heavy test; not in default CI lane).

---

## §2 What "PASS" means

```
T1 PASS: All 18 per-agent E2E tests green. No false negatives at agent level.
T2 PASS: All 10–15 cross-agent scenarios green. Bridges traverse correctly.
T3 PASS: Hermes closes the loop on every detection agent.
T4 PASS: Substrate survives concurrency + scale targets (operator-set in Q-set).
T5 PASS: Pure-breed scenario produces expected blast_radius + attack_path;
         all 12 violations surfaced; tenant isolation verified; audit chain clean.

OPERATING DECLARATION CONDITION:
  v0.4 OPERATING declared when T5 passes + Wazuh 12-item enrichment landed
  (Stage 4 from earlier v0.4 directive).

INSTRUMENTED 85% PRD CLAIM:
  T5 provides the EVIDENCE for the hard 85% claim. Pre-T5, the number stays
  [estimate]. Post-T5, it becomes INSTRUMENTED — count of violations surfaced
  / count of violations seeded × per-domain Wiz-weighting.
```

---

## §3 Swiss bar (non-negotiable)

```
1. Real code paths everywhere. No mock theater at fleet scale.
2. Real Postgres in T4 + T5 (in-memory acceptable for T1; operator decides
   per phase in Q-set).
3. Live-lane fakes must mirror real provider response shapes exactly.
4. No "TODO fix later" anywhere in test infrastructure.
5. No scaffolding disguised as test (e.g., assert True; or asserts that
   would pass with broken code).
6. Tenant isolation tested in EVERY phase, not just T5.
7. Failure messages must point to the broken assertion + the seeded ground
   truth violated.
8. Each phase's test infra is the FINAL form — gets used by next phase +
   becomes CI regression gate.
9. Coverage claims stay [estimate] until T5 produces instrumented evidence.
10. No PR ships without test infra updates if it touches agent behavior.
```

---

## §4 Sequencing + parallelism

```
WEEK 1-2: T1 (sequential foundation)
          18 per-agent E2E tests; pattern locked

WEEK 3-4: T2 + T3 + T4 (parallel where independent)
          T2: cross-agent correlation (uses T1 harnesses)
          T3: Hermes loop per agent (independent surface)
          T4: substrate pressure (independent surface; charter-only)

WEEK 5-6: T2 + T3 + T4 close
          All test infra in place; CI regression gates active

WEEK 7-9: T5 pure-breed finale
          Seeded scenario; whole fleet runs; assertions; tenant isolation

TOTAL: ~9 weeks honest (with parallelism)
       ~11 weeks ceiling (sequential)
       ~7 weeks aggressive (tight parallelism; experienced team velocity)
```

---

## §5 Operator decisions (Q-set)

```
Q1 — Postgres real or in-memory per phase?
   T1: rec in-memory (fast CI lane)
   T2: rec in-memory (correlation logic, not perf)
   T3: rec in-memory
   T4: REAL Postgres required (it's the pressure test)
   T5: REAL Postgres (it's the pure-breed; verify production substrate)

Q2 — Live-lane fakes only, or also sandboxed real cloud accounts?
   (a) Live-lane fakes only — cheap, fast, deterministic
   (b) Sandboxed real cloud accounts (AWS Goat / BadZure or custom) — real
       provider behavior, $$$, ongoing infra cost
   Rec: (a) for v0.4; (b) for v0.5 design-partner pitches.

Q3 — Pure-breed (T5) gated default-off in CI?
   Rec: YES. NEXUS_PURE_BREED=1 gates the heavy test. Default CI runs T1-T4.
   T5 runs nightly + on release branches.

Q4 — False-positive rate acceptance?
   Rec: per-domain target; operator sets per agent. Default 5% FP per detection
   class until production data tunes.

Q5 — Concurrency targets for T4?
   Rec: 18 parallel agents; 100 parallel tenants; 10K entities × 100K edges
   per tenant. Operator can revise per design-partner scale.

Q6 — Wiz/Orca/Lacework benchmark comparison in v0.4?
   Rec: DEFER to v0.5. T5 pure-breed produces evidence of platform correctness;
   competitive benchmarking is v0.5 design-partner work.

Q7 — Review mode?
   Rec: per-PR review on test INFRASTRUCTURE PRs (foundation harnesses,
   substrate-adjacent test code, ADR for Gate 3 evidence rubric); self-merge
   on per-scenario tests + per-agent tests once pattern locked.

Q8 — Test infra calendar trade-off?
   (a) Land T1-T5 in full ~9 weeks; v0.4 OPERATING after T5 + Wazuh
   (b) Land T1-T3 in 6 weeks; declare v0.4 OPERATING; T4-T5 in v0.5
   Rec: (a) — instrumented 85% claim needs T5; otherwise OPERATING is
   premature.

Q9 — Brainstorm cadence?
   Rec: meta-brainstorm first (this directive's content + Q-set answers);
   then per-phase brainstorms as we hit each (same v0.2-style template).
```

---

## §6 What this directive does NOT cover

```
- Red-team / penetration testing — v0.5 (Wazuh enrichment + Garak campaign
  on D.11 can provide partial validation in v0.4)
- Analyst-level UX measurement — v0.5 design-partner work
- Sandboxed cloud accounts — v0.5 (cost + ongoing infra burden)
- Wiz/Orca benchmark comparison — v0.5
- Production-load real-world stress (1M+ entities; 10K tenants) — v0.5+
- DSPy production flag flip (gated by Gate 3 evidence; separate operator go)
- v0.5 readiness audit (separate Stage 5 work)
```

---

## §7 What changes about v0.4 calendar

```
Before this directive:
  v0.4 = Stage 1 + 2 + 3 + 4 (Wazuh) + 5 (close) — 22-30 weeks
  Stage 4 + 5 remaining — 3-4 weeks
  v0.4 OPERATING: ~Week 22-26 (60% confidence)

After this directive:
  v0.4 = Stage 1 + 2 + 3 + Test Harness (T1-T5) + Stage 4 + 5
  Test harness adds ~9 weeks (with parallelism)
  v0.4 OPERATING: ~Week 28-32 (60% confidence)

The trade:
  - +6-8 weeks calendar
  - Instrumented 85% claim (not [estimate])
  - Real evidence the platform works as a fleet
  - CI regression gates that prevent future drift
  - Design-partner pitch backed by reproducible evidence

Operator judgment: is the trade worth it?
  Yes if: v0.4 OPERATING needs to mean something to design partners
  No if:  v0.4 OPERATING is internal-only milestone; defer rigor to v0.5

Recommended: Yes. The 85% claim is too important to ship on [estimate].
```

---

## §8 What success looks like

```
At T5 PASS:

  ✓ Every agent verified end-to-end against its tool surface
  ✓ Every cross-domain bridge traverses correctly in kg_query
  ✓ Hermes loop closes on every detection agent
  ✓ Substrate survives concurrency + scale targets
  ✓ Pure-breed scenario produces correct blast_radius + attack_path
  ✓ Tenant isolation verified under fleet-wide load
  ✓ 85% PRD claim is INSTRUMENTED with reproducible evidence
  ✓ CI gates prevent future fleet-level regression
  ✓ Design-partner pitch backed by real test artifacts
  ✓ v0.4 OPERATING means something defensible

That's what this directive ships.
```

---

## §9 Operator approval

```
This directive requires operator approval to proceed.

After approval:
  1. CC writes meta-brainstorm (this directive's content distilled + Q-set
     answers) — operator review/merge
  2. CC writes T1 brainstorm — operator review/merge — T1 cascade
  3. T2 + T3 + T4 brainstorms in parallel after T1 lands
  4. T5 brainstorm after T1+T2+T3 close
  5. v0.4 OPERATING declaration after T5 + Wazuh + Stage 5 close

HOLD posture: no further v0.4 execution work until this directive is
approved and Q-set is answered.
```

---

## §10 Cross-references

```
- v0.4 directive: docs/_meta/v0-4-directive-2026-06-16.md (§R1 instrumented
  coverage commitment)
- Inventory catalogue: docs/_meta/v0-4-inventory-catalogue-2026-06-16.md
- Detection-maturity yardstick:
  docs/_meta/agent-detection-maturity-v0-1-to-v0-3-2026-06-07.md
- ADR-007 (audit chain always-on)
- ADR-018 (graph type catalogue)
- ADR-019 (KnowledgeGraphWriter base)
- ADR-021 (T2 trace persistence)
- ADR-022 (cross-run dedup + edge accessor)
- Gate 3 spec: packages/agents/meta-harness/src/meta_harness/dspy_flip_gate.py
```
