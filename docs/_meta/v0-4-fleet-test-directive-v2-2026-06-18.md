# v0.4 Fleet Test Directive v2 — Five-Level Capability Test Plan

**Date:** 2026-06-18
**Author:** Operator (Praba)
**Status:** PROPOSED — supersedes v1 directive (#762)
**Target main:** post-#764 (D.15 kg_writer landed; Stage 1 fully closed)
**Anchored to:** v0.4 directive §R1 (instrumented 85% PRD coverage)

---

## §0 Why this v2 exists

The v1 directive (#762) drew an integration test plan and called it the foundation of capability testing. That was wrong.

**Integration tests** verify wiring — code path completes, kg_writer writes, OCSF emission validates, audit chain stays clean. Cheap, fast, deterministic. These are **smoke tests**.

**Capability tests** verify the agent ACTUALLY DETECTS — given a realistic environment with known violations, does the agent's full detection logic (tools + Hermes + reasoning) surface them? With what precision? What recall? What false-positive rate?

The v1 pattern of "seed a violation → assert agent finds it" is **hide-and-seek**, not capability measurement. We put the needle at coordinate (X, Y); agent looks at (X, Y); agent finds needle. That tests routing, not competence.

A real capability test exposes the agent to an environment with KNOWN GROUND TRUTH the agent does NOT know about. The agent runs full detection. We measure precision, recall, FP rate, detection time.

**A software test without a test case is not a test.** Each capability test needs documented INPUT + GROUND TRUTH + PASS CRITERIA — not just fixture seeding.

This v2 directive replaces v1 with a 5-level capability test plan. Each level has its own purpose, its own test case format, its own pass criteria.

**The directive provides the FRAMEWORK. The team writes the test cases in per-level brainstorms.**

**Slogan:** Brutally honest measurement at every level. Each agent. Each capability. No tip-of-iceberg. No scaffolding.

---

## §1 The Five Levels

```
LEVEL 1 — INTEGRATION (wiring works)               | ~2 weeks
LEVEL 2 — CAPABILITY (agent actually detects)      | ~4 weeks
LEVEL 3 — CORRELATION (cells communicate)          | ~2 weeks
LEVEL 4 — HERMES LOOP (feedback improves quality)  | ~2 weeks
LEVEL 5 — PRESSURE (substrate survives load)       | ~2 weeks
LEVEL 6 — PURE-BREED FINALE (platform competence)  | ~2-3 weeks

TOTAL: ~14-15 weeks (sequential ~17 weeks ceiling)
With parallelism: ~12-13 weeks
```

Each level has a purpose nothing else covers. Each level produces test artifacts the next level reuses. Nothing throwaway.

---

## §2 LEVEL 1 — INTEGRATION (per-agent wiring smoke)

### §2.1 Purpose

Verify wiring: does `agent.run()` complete without error, write expected entities to the SemanticStore via its kg_writer, emit valid OCSF, propagate tenant_id correctly, and honor the audit chain?

This is a SMOKE test, not a capability test. It catches integration bugs cheaply before capability testing exposes them as harder-to-debug failures at higher levels.

### §2.2 Scope

20 agents × 1 integration test each at `packages/agents/<agent>/tests/integration/test_wiring.py`.

### §2.3 Standard wiring assertions (every test, no exceptions)

- `agent.run()` completed without unhandled exception
- OCSF emission has valid schema against the agent's declared class
- kg_writer wrote at least one entity of expected type per ADR-018
- `tenant_id` present on every written entity
- F.6 audit chain hash-verifies (no broken links)
- Same input on `tenant_a` + `tenant_b` produces 2 disjoint subgraphs
- Live-lane gates default-off produce byte-identical output

### §2.4 Per-tier honesty (no fake-greens)

Some agents don't write to graph; some don't emit OCSF findings. No assertion silently skipped. Every omission documents WHY in the test code.

Tier shapes (team enumerates per agent in Level 1 brainstorm):

- **Tier A** — writes to graph, emits OCSF findings: full assertions
- **Tier B (read-only)** — reads graph, doesn't write: drop kg_writer assertion with documented reason
- **Tier B (action)** — emits actions, not findings: assert OCSF action emission shape
- **Tier B (orchestration)** — agent-specific wiring assertions documented per agent

### §2.5 Level 1 Pass Criteria

- All 20 integration tests green
- 0 false negatives at integration layer
- F.6 audit chain hash-verifies across all 20 runs
- Tenant isolation verified across all 20 runs

### §2.6 Level 1 Honest Limitations

- Does NOT measure detection capability
- Does NOT measure precision or recall
- Does NOT exercise Hermes reasoning
- Does NOT validate cross-agent behavior

### §2.7 What the team writes in Level 1 brainstorm

- Per-agent input source for the wiring test (from each agent's existing fakes)
- Per-tier classification with documented reason
- Shared `packages/integration/fleet_testkit/` helper design
- Sequencing (reference agents per-PR review; remaining cascade self-merge)

---

## §3 LEVEL 2 — CAPABILITY (per-agent test case banks)

### §3.1 Purpose

Verify each agent's detection capability against realistic environments with known ground truth. The agent runs FULL detection logic — tool calling, Hermes reasoning (where applicable), real algorithms — against an environment containing an UNKNOWN-to-the-agent set of violations.

This is what you'd recognize as a software test: test case → ground truth → actual output → pass criteria.

### §3.2 Test case format (mandatory; same shape every agent)

Every capability test case is a YAML file:

```yaml
test_case_id: "TC-<AGENT>-<NNN>"
description: "<single sentence describing what this case tests>"
agent: "<agent identifier>"
category: "<see §3.3 categories>"
environment:
  fixture_path: "fixtures/<scenario>.yaml"
  realism_notes: |
    <where the fixture data came from + why it's realistic>
ground_truth_violations:
  - id: "GT-<TC>-<N>"
    type: "<finding type per OCSF class>"
    resource: "<resource identifier in fixture>"
    severity: "<critical|high|medium|low|info>"
    expected_detect: true
    <additional fields per detection class>
expected_non_detections:
  - id: "ND-<TC>-<N>"
    resource: "<resource that looks suspicious but isn't>"
    reason: "<why this should NOT be detected>"
    expected_detect: false
pass_criteria:
  precision: ">= <threshold>"
  recall: ">= <threshold>"
  false_positives_max: <integer>
  detection_time_max_seconds: <integer>
```

### §3.3 Coverage categories (every agent's bank covers these)

Each agent's test case bank must cover these categories:

1. **CLEAN BASELINE** — Environment with NO violations the agent targets. Pass criteria: 0 detections (FP test).
2. **STANDARD VIOLATIONS** — Realistic violations the agent is designed to catch. Pass criteria: high recall.
3. **EDGE CASES** — Violations that test detection boundaries (severity ambiguity, partial matches, layered configurations).
4. **FALSE-POSITIVE TRAPS** — Configurations that LOOK like violations but aren't (e.g., patched-but-base-layer-vulnerable image; properly-scoped IAM condition; legitimate service-to-service traffic).
5. **CROSS-DOMAIN INPUTS** — Where the agent processes inputs that touch multiple domains (e.g., D.6 K8s pod with IRSA annotation linking to D.2 IAM).
6. **ENRICHMENT/CONTEXT** — Where the agent must enrich its finding from external context (CVE → EPSS; IOC → threat actor; CIS control → finding).
7. **NEGATIVE SPACE** — Things the agent SHOULDN'T claim (out-of-scope domains, off-tenant data, expired threat intel).

Team writes specific test cases per category in the Level 2 brainstorm.

### §3.4 What each capability test does

For each test case:

1. **Setup** — Load realistic environment fixture. Agent does NOT see the `ground_truth_violations` file. Configure live-lane fakes to mirror real provider responses.

2. **Execute** — Run agent's REAL detection path (tool calling + Hermes where applicable). LLM provider = FakeLLMProvider with deterministic responses. No mocking of detection logic itself. Time the detection.

3. **Measure** — True positives (TP) / false negatives (FN) / false positives (FP). Precision = TP / (TP + FP). Recall = TP / (TP + FN). Detection time.

4. **Assert** — Precision ≥ threshold. Recall ≥ threshold. FP count ≤ ceiling. Detection time ≤ ceiling.

### §3.5 Minimum test cases per agent

```
DETECTION AGENTS:
  D.1 vulnerability:     minimum 10 cases
  D.2 identity:          minimum 10 cases
  D.3 runtime-threat:    minimum 10 cases
  D.4 network-threat:    minimum 10 cases
  D.4 data-security:     minimum 10 cases
  D.6 K8s-posture:       minimum 10 cases
  D.14 AppSec:           minimum 10 cases
  F.3 cloud-posture:     minimum 10 cases
  D.7 investigation:     minimum 8 cases
  D.8 threat-intel:      minimum 8 cases
  D.9 compliance:        minimum 8 cases
  D.10 SSPM:             minimum 8 cases
  D.11 AI-SPM:           minimum 8 cases
  D.15 multi-cloud:      minimum 8 cases

LLM AGENTS:
  D.12 curiosity:        minimum 6 cases
  D.13 synthesis:        minimum 6 cases

ORCHESTRATION/ACTION:
  A.1 remediation:       minimum 6 cases
  A.4 meta-harness:      minimum 6 cases
  F.6 audit:             minimum 4 cases
  Supervisor:            minimum 4 cases

Total minimum: ~146 test cases across the fleet.
Team can EXPAND per agent as gaps surface during brainstorming.
Team CANNOT reduce below these minimums without operator approval.
```

### §3.6 Pass criteria framework (default thresholds; per-agent tunable)

Per detection class defaults — starting points for v0.4; operator amends per agent as production data tunes:

```
Vulnerability / CVE                  precision ≥ 0.95   recall ≥ 0.95   FP ≤ 5%
Identity (CIEM)                      precision ≥ 0.90   recall ≥ 0.90   FP ≤ 10%
Runtime threat (CWPP)                precision ≥ 0.85   recall ≥ 0.90   FP ≤ 10%
Network threat (NDR)                 precision ≥ 0.85   recall ≥ 0.90   FP ≤ 15%
Data security (DSPM)                 precision ≥ 0.95   recall ≥ 0.90   FP ≤ 5%
Cloud posture (CSPM)                 precision ≥ 0.95   recall ≥ 0.95   FP ≤ 5%
K8s posture (KSPM)                   precision ≥ 0.95   recall ≥ 0.95   FP ≤ 5%
Investigation correlation (CDR)      precision ≥ 0.80   recall ≥ 0.85
Threat-intel enrichment              precision ≥ 0.95   recall ≥ 0.95
Compliance mapping                   precision = 1.00   recall ≥ 0.95
SaaS posture (SSPM)                  precision ≥ 0.90   recall ≥ 0.95   FP ≤ 10%
AI posture (AI-SPM)                  precision ≥ 0.90   recall ≥ 0.90   FP ≤ 10%
AppSec (SCA / SAST / Secrets / IaC)  precision ≥ 0.85   recall ≥ 0.90   FP ≤ 15%
```

Each test case can override per scenario when justified.

### §3.7 Per-agent test case bank ownership

Each agent's package owns its bank:

```
packages/agents/<agent>/tests/capability/test_cases/*.yaml
packages/agents/<agent>/tests/capability/fixtures/
packages/agents/<agent>/tests/capability/test_runner.py
```

Shared `packages/integration/fleet_testkit/` provides:

- Test case YAML loader/validator
- Precision/recall computation
- FP rate measurement
- Detection-time measurement
- Pass criteria evaluator

### §3.8 Level 2 Pass Criteria

- Every agent meets its minimum case count
- Every case has documented INPUT + GROUND TRUTH + PASS CRITERIA
- Per-agent aggregate precision ≥ agent threshold
- Per-agent aggregate recall ≥ agent threshold
- Per-agent FP rate ≤ ceiling
- 0 test cases silently skipped
- Every failure has a measured value vs threshold

### §3.9 Level 2 Honest Limitations

- Measures per-agent capability in ISOLATION
- Does NOT measure cross-agent correlation (Level 3)
- Does NOT measure Hermes loop quality (Level 4)
- Does NOT measure substrate behavior under load (Level 5)

### §3.10 What the team writes in Level 2 brainstorm

Per-agent (one brainstorm per agent OR one consolidated brainstorm — team picks):

- Coverage category enumeration for that agent
- **The specific test cases (YAML files) — team writes these**
- Fixture design (how to make the environment realistic)
- Per-agent threshold overrides (if different from §3.6 defaults)
- Edge cases worth covering specific to that agent's tool surface

The directive defines the FRAMEWORK; the team defines the CONTENT.

---

## §4 LEVEL 3 — CORRELATION (cross-agent capability)

### §4.1 Purpose

Verify cross-agent correlation through the ADR-018 spine actually works on realistic multi-domain scenarios. Cells must communicate. Bridges (HOSTS_AI, IRSA_MAPPING, AUTHORIZED, SSO_INTO, DEFINED_IN, EXPOSES_DATA, CLASSIFIED_AS) must traverse correctly.

### §4.2 Test case format

Each correlation test case must specify:

- Multi-domain environment seeded into SemanticStore
- Which agents contribute inventory + findings
- Expected `kg_query.blast_radius` result (exact set)
- Expected `kg_query.attack_path` result (edge chain in order)
- Bridge types traversed (named ADR-018 EdgeType members)

### §4.3 Coverage categories

Team writes scenarios covering:

1. **Single-bridge traversal** — each cross-domain bridge tested individually
2. **Multi-bridge chains** — 3+ hops crossing multiple domains
3. **Cycle handling** — graph has cycles; query must terminate
4. **Depth-cap enforcement** — graph extends beyond depth 3
5. **Disconnected subgraphs** — no path exists; query returns empty cleanly
6. **Tenant isolation under correlation** — same query, different tenants
7. **Operator-defined scenarios** — from design-partner pain points

### §4.4 Minimum test cases

Team enumerates in Level 3 brainstorm. Recommended floor: 15 scenarios covering all 7 categories with every ADR-018 bridge type traversed at least once.

### §4.5 Pass criteria

Per scenario:

- Expected entities exist (count match)
- Expected edges exist (no missing bridges)
- `blast_radius` returns expected affected resource set (exact match)
- `attack_path` returns expected edge chain in order
- Cycles excluded correctly
- Depth-cap 3 honored
- Tenant isolation holds

### §4.6 Level 3 Pass Criteria

- All correlation test cases green
- 0 missing bridges
- 0 cross-tenant edge leaks
- Attack path reconstruction matches ground truth exactly

### §4.7 Level 3 Honest Limitations

- Uses pre-seeded inventory (not full agent discovery)
- Does NOT measure end-to-end fleet behavior (Level 6)
- Measures correlation correctness, not detection capability (Level 2)

### §4.8 What the team writes in Level 3 brainstorm

- The specific cross-agent correlation scenarios
- Realistic enterprise-shape topologies
- Bridge coverage matrix (every bridge type covered)
- Operator-input scenarios per design-partner context

---

## §5 LEVEL 4 — HERMES LOOP (feedback quality measurement)

### §5.1 Purpose

Verify Hermes feedback loop IMPROVES quality over runs. Not just "loop closes" but "loop produces measurably better skills."

### §5.2 Hermes consumer scope

Per R-3′ resolution (Q5 in §10): operator decides scope. Team's brainstorm enumerates which agents are in-scope.

Today: 4 agents close the loop (curiosity, investigation, synthesis, meta-harness).

### §5.3 Test case format

Each test case must specify:

- Hermes consumer agent
- Loop stage exercised (record → cadence → judge → deprecation → Gate 3)
- Synthetic skill scenario
- Expected loop output
- Measured quality delta (where applicable)

### §5.4 Coverage categories

Team writes test cases covering:

1. **Trace persistence** — record-at-deploy correctness
2. **Trainset assembly** — multi-example from store
3. **Compilation cadence** — triggers based on cadence policy
4. **LLM-judge additive ranking** — pass-rate floor preserved
5. **Skill deprecation** — dual-trigger + sunset
6. **Gate 3 verdict mechanic** — 4-criteria evaluation correctness
7. **Tenant isolation** — SkillTraceStore tenant-scoped
8. **GEPA delta measurement** — synthetic skill quality improvement

### §5.5 Minimum test cases

Team enumerates in Level 4 brainstorm. Recommended floor: 10 cases covering all 8 categories + GEPA delta measurement.

### §5.6 GEPA delta measurement (the load-bearing capability test)

Per scenario:

- Synthetic skill with known suboptimal prompt
- Run on test corpus → measure baseline pass-rate
- Compile via GEPA with N-example trainset
- Run compiled skill on same corpus → measure delta
- Assert: delta > 0 (compiled skill improves quality)

This is the GEPA delta measurement Gate 3 needs anyway.

### §5.7 Level 4 Pass Criteria

- All Hermes consumer test cases pass
- SkillTraceStore tenant isolation verified
- Gate 3 verdict correctness verified across mechanic permutations
- GEPA delta measurement produces positive delta on synthetic skill

### §5.8 Level 4 Honest Limitations

- v0.4 uses SYNTHETIC test corpus (real production traces v0.5)
- Task-14 Anthropic validation is separate work
- Real-world skill improvement measurement waits for production deployment

### §5.9 What the team writes in Level 4 brainstorm

- The specific Hermes consumer scenarios per agent
- Synthetic skill design for GEPA delta measurement
- Test corpus selection
- Gate 3 mechanic permutation cases

---

## §6 LEVEL 5 — PRESSURE (substrate under load)

### §6.1 Purpose

Verify substrate (Postgres + SemanticStore + SkillTraceStore + audit chain) survives production-shape load.

### §6.2 Coverage categories

Team writes pressure scenarios covering:

1. **Concurrent kg_writer writes** — UNIQUE constraint races
2. **Multi-tenant parallel discovery** — lock contention
3. **Graph size at scale** — neighbors + kg_query latency
4. **SkillTraceStore under concurrent record** — ON CONFLICT correctness
5. **F.6 audit chain at large event counts** — chain verification cost
6. **SQLite vs Postgres parity** — same assertions hold on both backends

### §6.3 Minimum test cases

Team enumerates in Level 5 brainstorm. Recommended floor: 7 pressure scenarios across all 6 categories.

### §6.4 Pass criteria (operator-set in Q-set)

Default suggestions (team refines in brainstorm; operator approves):

- 20 parallel agents: 0 UNIQUE failures; 0 deadlocks
- 100 parallel tenants: 0 cross-tenant leaks; lock contention < 100ms p99
- 10K entities × 100K edges: `neighbors(depth=3)` p99 < 500ms
- 1M audit events: hash chain verify < 5s

### §6.5 Level 5 Honest Limitations

- Uses synthetic load patterns
- Real production traffic shapes may differ
- 1M+ entity scale → v0.5+

### §6.6 What the team writes in Level 5 brainstorm

- Specific load patterns per scenario
- Real-Postgres infrastructure setup
- Concurrency target rationale
- Synthetic-vs-real-shape acknowledgement

---

## §7 LEVEL 6 — PURE-BREED FINALE (platform competence proof)

### §7.1 Purpose

Prove the entire platform performs as designed when running its full fleet against a realistic environment. All 5 prior levels' artifacts feed into this.

This is what makes "v0.4 OPERATING" mean the platform is competent.

### §7.2 Pure-breed scenario structure

Team writes ONE integrated scenario covering:

- Realistic mid-size enterprise environment (cloud + K8s + SaaS + AI + identity)
- Set of seeded violations representing real-world attack patterns
- Full fleet runs against it
- All capability metrics measured at fleet scale
- Cross-agent correlation produces expected blast_radius + attack_path
- Hermes loop closes
- Audit chain hash-verifiable end-to-end
- Tenant isolation verified under fleet-wide load

### §7.3 Pure-breed measurement (the OPERATING claim evidence)

At Level 6 PASS:

```
DETECTION COVERAGE (from Level 2 aggregate):
  - Per-agent precision/recall across all test case banks
  - Cross-fleet aggregate weighted by Wiz coverage methodology
  - INSTRUMENTED 85% PRD claim = aggregate detection capability metric

CORRELATION COVERAGE (from Level 3):
  - Cross-domain bridge traversal correctness
  - Attack path reconstruction accuracy

HERMES LOOP QUALITY (from Level 4):
  - GEPA delta measurement on synthetic corpus
  - Gate 3 mechanic verified

SUBSTRATE RESILIENCE (from Level 5):
  - Concurrent multi-tenant write throughput
  - Query latency at scale

FLEET INTEGRATION (Level 6 itself):
  - All seeded violations surfaced
  - blast_radius matches ground truth
  - attack_path traverses all expected bridges
  - Tenant isolation under fleet-wide load
  - Audit chain hash-verifiable end-to-end

This is the EVIDENCE for "v0.4 OPERATING" declaration.
Not [estimate]. Instrumented capability measurement.
```

### §7.4 What the team writes in Level 6 brainstorm

- The pure-breed scenario itself
- Seeded violations + ground truth set
- Fleet orchestration design
- Aggregate metric computation
- The "OPERATING" declaration checklist

---

## §8 Swiss Bar (non-negotiable across all 6 levels)

```
1. Real code paths everywhere. No mock theater at any level.
2. In-memory backends acceptable for L1-L4; real Postgres required L5+L6.
3. Live-lane fakes mirror real provider response shapes exactly.
4. No "TODO fix later" anywhere in test infrastructure.
5. No scaffolding disguised as test (no assert True; no asserts that pass
   with broken code; no fake greens via assertion absence).
6. Every test has a documented test case with INPUT + GROUND TRUTH +
   PASS CRITERIA. Fixtures alone don't count as test cases.
7. Tenant isolation tested at EVERY level, not just L6.
8. Failure messages point to broken assertion + the ground truth violated.
9. Each level's test artifacts are FINAL form; reused by next level;
   become CI regression gates.
10. Coverage claims stay [estimate] until L6 produces instrumented evidence.
11. No PR ships without test infra updates if it touches agent behavior.
12. No tier may fake-green via silent assertion skip; every omission
    documented in-test with reason.
13. Per-agent capability thresholds documented; FP/precision/recall
    measured explicitly (not implied).
14. Hermes consumer scope honestly enumerated (no R-3′-style retcon).
15. Edge names used in assertions verified against ADR-018 catalogue
    before assertion written (no R-4-style fabrication).
```

---

## §9 Sequencing + Parallelism

```
WEEK 1-2:   LEVEL 1 INTEGRATION (sequential foundation; 20 wiring tests)

WEEK 3-6:   LEVEL 2 CAPABILITY (per-agent test case banks; ~146 tests)
            Per-agent capability work runs in parallel within Level 2

WEEK 7-8:   LEVEL 3 CORRELATION + LEVEL 4 HERMES LOOP (parallel)
            L3 uses L2 fixtures
            L4 independent surface (charter-touching)

WEEK 9-10:  LEVEL 5 PRESSURE (parallel with L4 tail)
            Real Postgres required; independent of L1-L4 work

WEEK 11-14: LEVEL 6 PURE-BREED FINALE
            Uses all 5 prior levels' artifacts
            Most expensive phase; deserves 3-4 weeks

TOTAL: ~14-15 weeks (sequential ~17 ceiling, aggressive ~12)
```

---

## §10 Operator Q-set

```
Q1 — Per-agent test case bank ownership: per-agent package or central?
     Rec: per-agent package (alongside the agent code).

Q2 — Pass criteria thresholds: §3.6 defaults, or per-agent operator-set?
     Rec: start with §3.6 defaults; operator amends per agent as production
     data tunes.

Q3 — Realism source for environment fixtures:
     (a) Synthetic fixtures we generate (cheap, deterministic, fast)
     (b) Recorded real-provider responses (more realistic, harder to maintain)
     (c) Sandboxed real cloud accounts (most realistic, $$$)
     Rec: (a) for v0.4; (b) selectively where it pays off; (c) for v0.5.

Q4 — Per-agent test case bank size:
     (a) Honor §3.5 minimums (~146 cases)
     (b) Expand to 10-25 per agent (~300 cases) for deeper coverage
     (c) Less than minimums — slimmer; faster build
     Rec: (a) minimum; expand per agent as gaps surface during brainstorming.

Q5 — Hermes consumer scope (R-3′):
     (a) Narrow: 4 agents only (curiosity/investigation/synthesis/meta-harness)
     (b) Broad: enumerate NLAH-emission-ready agents
     (c) Build: expand deterministic agents into Hermes (v0.5 work)
     Rec: (a) for v0.4.

Q6 — Pressure test (Level 5) gated default-off in CI?
     Rec: YES. NEXUS_PRESSURE=1 gates the heavy test.

Q7 — Pure-breed (Level 6) gated default-off in CI?
     Rec: YES. NEXUS_PURE_BREED=1 gates the heaviest test.

Q8 — Calendar trade-off:
     (a) Full L1-L6 in v0.4 (~14-15 weeks); INSTRUMENTED OPERATING claim
     (b) L1-L3 only (~6-8 weeks); declare OPERATING with [estimate]
     (c) Hybrid: L1-L4 in v0.4 (~10-11 weeks); L5-L6 in v0.5
     Rec: (a) — the brutally honest measurement is the whole point.

Q9 — Review mode per level:
     L1 infra: per-PR review; L1 cascade: self-merge after pattern lock
     L2 banks per agent: per-PR review (test case quality matters);
                         self-merge cascade after first 2 agents lock pattern
     L3 correlation: per-PR review on scenarios; self-merge cascade
     L4 Hermes loop: per-PR review on Gate 3 evidence test
     L5 pressure: per-PR review on substrate-adjacent test code
     L6 pure-breed: per-PR review (it's THE test)

Q10 — Brainstorm cadence + content ownership:
     Rec: meta-brainstorm first (this directive + Q-set answers);
     then per-level brainstorm as we hit each (v0.2-style template);
     team writes the actual test cases in per-level brainstorms.
     The directive provides framework; the team provides content.
```

---

## §11 What this directive does NOT cover (v0.5+)

```
- Sandboxed real cloud accounts (cost + ongoing infra burden)
- Wiz/Orca/Lacework benchmark comparison
- Production-load real-world stress (1M+ entities; 10K tenants)
- Task-14 Anthropic validation for DSPy production flip
- Analyst-level UX measurement
- Red-team / penetration testing campaigns
- Per-tenant production deployment hardening
- BigQuery + RDS row-content + Snowflake DSPM
- D.15 live connector activation (still fixture-mode)
- Expansion of Hermes consumer scope to deterministic agents
```

---

## §12 What changes about v0.4 calendar

```
Before this v2 directive:
  v0.4 = Stage 1 + 2 + 3 + v1 test (9 weeks) + Stage 4 + 5
  v1 test was integration-only
  v0.4 OPERATING: ~Week 28-32 (60% confidence)

After this v2 directive:
  v0.4 = Stage 1 + 2 + 3 + v2 test (14-15 weeks) + Stage 4 + 5
  v2 test is full capability measurement
  v0.4 OPERATING: ~Week 33-37 (60% confidence)

The additional trade:
  - +5-6 weeks calendar
  - INSTRUMENTED CAPABILITY claim (precision/recall/FP per agent)
  - Each agent's competence MEASURED, not implied
  - Reusable CI regression gates for future
  - Design-partner pitch backed by capability metrics

Recommended: Yes. "OPERATING" with [estimate] is what v0.3 had.
"OPERATING" with capability measurement is what v0.4 promised.
```

---

## §13 What success looks like

At Level 6 PASS:

- Each agent's detection capability MEASURED (precision/recall/FP per case)
- Cross-agent correlation MEASURED (bridge traversal accuracy)
- Hermes loop quality MEASURED (GEPA delta on synthetic corpus)
- Substrate resilience MEASURED (concurrency + scale targets)
- Fleet integration MEASURED (pure-breed scenario competence)
- Per-agent capability deltas trackable over time
- "v0.4 OPERATING" means INSTRUMENTED capability, not estimated
- Design-partner pitch backed by reproducible capability evidence
- CI regression gates prevent future capability drift
- Each agent is brutally honest about what it CAN and CANNOT do

That's what this v2 directive ships.

---

## §14 Operator approval

This v2 directive supersedes v1 (#762) and v1 meta-brainstorm (#763).
v1 + #763 preserved as institutional record but no longer drive execution.
v1 T1 brainstorm (#765) is now obsolete — close it without merging.

HOLD posture: no further v0.4 execution work until:

1. This v2 directive merges
2. v2 meta-brainstorm written + Q-set answered
3. Per-level brainstorm for Level 1 written + reviewed

After approval cascade:

1. CC writes v2 meta-brainstorm (distill + Q-set answers carried)
2. CC writes Level 1 brainstorm (integration smoke pattern)
3. CC writes Level 2 brainstorm (capability test case bank pattern; **team enumerates specific test cases per agent IN that brainstorm**)
4. Levels 3-6 brainstorms as we hit each
5. v0.4 OPERATING declared after Level 6 + Wazuh + Stage 5 close

HOLD until v2 directive on main + meta-brainstorm reviewed.

---

## §15 Cross-references

```
Supersedes:
  - docs/_meta/v0-4-fleet-test-directive-2026-06-18.md (v1)
  - docs/superpowers/plans/2026-06-18-fleet-test-meta-brainstorm.md (v1 meta, #763)
  - v1 T1 brainstorm PR #765 (close without merge)

Builds on:
  - docs/_meta/v0-4-directive-2026-06-16.md (§R1 instrumented coverage)
  - docs/_meta/v0-4-inventory-catalogue-2026-06-16.md
  - docs/_meta/agent-detection-maturity-v0-1-to-v0-3-2026-06-07.md
  - ADR-007 (audit chain always-on)
  - ADR-018 (graph type catalogue)
  - ADR-019 (KnowledgeGraphWriter base)
  - ADR-021 (T2 trace persistence)
  - ADR-022 (cross-run dedup + edge accessor)
  - Gate 3 spec: packages/agents/meta-harness/src/meta_harness/dspy_flip_gate.py
```
