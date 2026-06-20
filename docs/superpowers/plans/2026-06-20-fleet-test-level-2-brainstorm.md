# Fleet Test Level 2 — Capability (per-agent test-case banks) brainstorm

_2026-06-20 · v2 directive (#766) §3 · meta-brainstorm #767 · follows L1 close (#769/#770)_

## 1. What L2 is

The real software test: each agent runs its **full detection path** against a realistic
environment with **ground truth it doesn't know about**, and we **measure** precision / recall /
FP / detection-time against documented pass criteria. Not hide-and-seek (that was the v1 mistake L1
already corrected) — capability measurement. This is the phase that turns the 85% PRD claim from
`[estimate]` into instrumented evidence.

**Framework vs content (Q10, locked):** this brainstorm defines the _framework_ — the
`fleet_testkit` L2 evaluator, the per-agent bank layout, the coverage-category mapping, the
matching model, sequencing. The **team writes the ~146 YAML test cases** (the content) in the L2
execution cascade, **per-PR review on every bank** (Q9 — ground-truth correctness is semantic; CI
can't catch a plausible-but-wrong ground truth).

## 2. `fleet_testkit` L2 additions (the shared evaluator)

L1 shipped the smoke surface; L2 adds the measurement surface (still in
`packages/integration/src/fleet_testkit/`):

- **`load_test_case(path) -> TestCase`** — parse + **validate** the §3.2 YAML schema
  (`test_case_id`, `description`, `agent`, `category`, `environment.fixture_path`,
  `ground_truth_violations[]`, `expected_non_detections[]`, `pass_criteria`). A malformed case is
  a hard error, never a silent skip (swiss-bar #5/#12).
- **`score(detected, ground_truth, non_detections, *, match) -> CapabilityResult`** — given the
  agent's emitted findings + the case's ground truth + a per-agent **match function**, compute
  TP/FN/FP, precision, recall, FP-count. `match(finding, gt) -> bool` is the per-agent crux
  (§4).
- **`evaluate(result, pass_criteria) -> Verdict`** — assert precision ≥, recall ≥, FP ≤,
  detection-time ≤; the failure message names the **measured value vs threshold** and the
  ground-truth id violated (swiss-bar #8/#13).
- **detection-time** capture helper (wall-clock around the real `run()`).
- OCSF reading reuses L1's bare-or-wrapped `assert_ocsf_valid` discipline (the 6 bare-emit agents
  validate the same way they did at L1; finding #1 ruling).

Per-agent layout (§3.7): `packages/agents/<agent>/tests/capability/{test_cases/*.yaml, fixtures/,
test_runner.py}`. `test_runner.py` = the thin per-agent driver: load each YAML → build the
environment from `fixture_path` (reusing the agent's existing live-lane fakes) → run the real
detection path (FakeLLMProvider, deterministic, where the agent uses an LLM) → `score` with the
agent's `match` → `evaluate`.

## 3. Coverage categories (§3.3) + minimums (§3.5)

Every agent's bank covers the 7 categories: **clean baseline** (0-detection FP test), **standard
violations** (recall), **edge cases**, **false-positive traps**, **cross-domain inputs**,
**enrichment/context**, **negative space**. Minimums per §3.5 (~146 total): detection agents
8–10, LLM agents 6, orchestration/action 4–6. The team **cannot** drop below a minimum without
operator sign-off; it **may** expand as gaps surface.

Default thresholds per §3.6 (per-class; per-case override when justified, documented). Compliance
mapping = **precision 1.00** (exact) is the strictest; CVE/CSPM/KSPM/DSPM 0.95/0.95.

## 4. The crux — ground-truth matching (per-agent `match`)

The hard part isn't the P/R/FP math (shared); it's mapping an **emitted OCSF finding** to a
**ground_truth_violation**. The match key is per-agent because resource identity differs:

- vulnerability: `(CVE id, affected resource/image)` ↔ gt `(type=cve, resource)`.
- cloud-posture / posture agents: `(rule_id/check, resource uid)` ↔ gt `(type, resource)`.
- identity: `(principal, finding type)`; runtime/network: `(event signature, host/flow)`.
- LLM agents (curiosity/synthesis): semantic — match on the cited resource/region in the
  finding's evidence (curiosity's WI-X11 hallucination guard already ties findings to cited
  entities, so the match key exists).

Each agent's `test_runner.py` supplies its `match`; the brainstorm's job is to name the key per
agent (the L2 execution PRs implement it). A finding matching a `ground_truth_violation` =TP; an
unmatched gt =FN; a finding matching nothing (or matching an `expected_non_detection`) =FP.

## 5. Sequencing

1. **Build the `fleet_testkit` L2 evaluator** (`load_test_case` / `score` / `evaluate` /
   detection-time) + lock the per-agent bank pattern on **2 reference agents** — **vulnerability**
   (CVE, crisp resource match, 0.95/0.95) + **cloud-posture** (CSPM rule→resource, 0.95/0.95).
   **Per-PR review** (evaluator is shared infra; these 2 banks set the YAML + matching + fixture
   template). _Rec these 2._
2. **Per-agent bank cascade** — the remaining 18 agents' banks, **each its own per-PR-review PR**
   (Q9 — no self-merge at L2; every ground-truth file gets operator eyes). Banks are independent →
   can be authored in parallel, but each merges on its own review.
3. L2 PASS (§3.8): every agent meets its minimum case count; every case has INPUT + GROUND TRUTH +
   PASS CRITERIA; per-agent aggregate P ≥ / R ≥ / FP ≤ thresholds; 0 silent skips; every failure
   shows measured-vs-threshold.

## 6. L2 Q-set

- **L2-Q1 — evaluator home + runner split.** Shared `score`/`evaluate`/`load_test_case` in
  `fleet_testkit`; thin per-agent `test_runner.py` supplies `match` + fixture build. _Rec: yes_
  (directive §3.7).
- **L2-Q2 — reference agents.** vulnerability + cloud-posture to lock the YAML+matching+fixture
  pattern (per-PR), then the 18-bank cascade. _Rec: yes._
- **L2-Q3 — bank authorship cadence.** Author banks **in parallel** (independent) but **merge each
  per-PR** (Q9). Confirm that's the intended throughput (parallel author, serial review). _Rec:
  yes._
- **L2-Q4 — match-key registry. RULED (operator 2026-06-20): appendix up front, MANDATORY
  infrastructure.** The match-key registry (Appendix A) is canonical: one entry per agent
  (agent → identity match function + rationale). **Every per-bank PR review verifies the bank's
  `match()` honors the registry**; registry updates require **operator approval** (same discipline
  as ADR-018 edge-type additions). Rationale: this is the L2 analogue of the Q9 sharpening — Q9
  catches _wrong ground truth_, Q4 catches _wrong match key_; both silently inflate precision and
  CI cannot detect either, so both need human review against an agreed reference (see §7).
- **L2-Q5 — FakeLLMProvider determinism for LLM agents** (curiosity/synthesis): the case's
  expected LLM responses live in the fixture (deterministic), no live calls. _Rec: yes_ (directive
  §3.4: FakeLLMProvider, no detection-logic mocking).

## 7. Swiss bar

Directive §8 binding. L2-load-bearing: **#6** every case = INPUT + GROUND TRUTH + PASS CRITERIA
(fixtures alone aren't a test); **#13** P/R/FP measured explicitly, never implied; **#5/#12** no
fake-green via silent skip; **#7** tenant isolation in the bank too (a case can assert off-tenant
data is not detected — negative space). FakeLLMProvider deterministic; real detection path (no
mocking the detector). Bare-or-wrapped OCSF validation per the L1 finding-#1 ruling.

**Swiss-bar implication — the three silently-inflated-precision guards.** L2 has three failure
modes that pass CI while lying, each defused by a human-checked reference (none catchable by an
assertion):

| Guard             | Failure it prevents   | Reference the reviewer checks against           |
| ----------------- | --------------------- | ----------------------------------------------- |
| Swiss-bar **#15** | fabricated edge names | ADR-018 `EdgeType` catalogue                    |
| **Q9 sharpening** | wrong ground truth    | per-PR review on **every** bank (no self-merge) |
| **Q4 registry**   | wrong match key       | the **match-key registry** (Appendix A)         |

The match-key registry is the Q4 member of this lineage — same discipline as #15: a canonical
reference, reviewer-verified, operator-gated to change.

## 8. Non-goals (L2)

Cross-agent correlation (L3), Hermes-loop quality (L4), pressure (L5), pure-breed (L6). Real
Postgres (L5/L6). Sandboxed cloud accounts / recorded real-provider responses (v0.5 — Q3 synthetic
for v0.4). The two v0.5 backlog items (envelope ADR, ADR-018 entity_type migration) are NOT L2
work — L2 tests around the current behavior honestly.

## 9. Open for operator

Confirm L2-Q1..Q5. On approval: build the `fleet_testkit` L2 evaluator + the match-key registry
(Appendix A) + the 2 reference banks (vulnerability, cloud-posture) per-PR, then the 18-bank
per-PR cascade.

---

## Appendix A — Match-key registry (CANONICAL · operator-gated)

The identity that ties an **emitted finding** to a **`ground_truth_violation`** (a TP), per agent.
`match(finding, gt)` compares the **key fields** below; an unmatched gt = FN, an unmatched finding
(or one matching an `expected_non_detection`) = FP. The registry names the **key**; each per-bank
PR implements `match()` honoring it and the reviewer verifies the impl against this table. **Changes
require operator approval** (ADR-018-edge-addition discipline). Exact OCSF field paths are pinned
when each bank is built; the _identity_ is fixed here.

| Agent               | OCSF          | Match key (compared identity)                             | Rationale                                                                         |
| ------------------- | ------------- | --------------------------------------------------------- | --------------------------------------------------------------------------------- |
| vulnerability       | 2002          | (cve_id, affected resource/image uid)                     | a CVE is identified by its id on a specific image/resource                        |
| cloud-posture       | 2003          | (rule/check id, resource uid)                             | a posture check fails against one resource                                        |
| multi-cloud-posture | 2003          | (rule id, resource uid)                                   | Azure/GCP resource id + check, same shape as F.3                                  |
| k8s-posture         | 2003          | (CIS check id, cluster-object uid)                        | a CIS control on a specific k8s object                                            |
| data-security       | 2003          | (classifier label, data-store resource uid)               | a PII/PHI/PCI class found on one data store                                       |
| identity            | 2003/2004     | (finding type, principal arn/id)                          | an over-perm/exposure on one IAM principal                                        |
| threat-intel        | 2003          | (indicator or cve id, correlated entity)                  | enrichment matches an IOC/CVE to an entity                                        |
| sspm                | 2003          | (check id, SaaS resource uid: tenant/oauth-app)           | a SaaS posture check on one tenant/app                                            |
| aispm               | 2003/2004     | (check or probe id, AI resource uid: service/model)       | a posture/injection finding on one AI asset                                       |
| runtime-threat      | 2004          | (rule/signature, workload uid: host/container)            | a runtime event on one workload                                                   |
| network-threat      | 2004          | (signature, flow/endpoint key)                            | a network alert on one flow/endpoint                                              |
| appsec              | 2003          | (finding type/rule, code location: repo+path or artifact) | a SAST/secret/IaC finding at one code location                                    |
| curiosity           | 2004          | (gap kind, cited region/entity)                           | a hypothesis is tied to the coverage gap it cites (WI-X11 guard already binds it) |
| synthesis           | 2004          | (narrative subject, cited source-finding id set)          | a synthesis report is identified by the findings it correlates                    |
| investigation       | 2005          | (incident subject, correlated entity/finding id set)      | an incident is identified by the entities/findings it ties together               |
| remediation         | 2007          | (action type, target resource uid)                        | a remediation action on one resource                                              |
| audit               | 6003          | (integrity/tamper event type, audited entry/source id)    | a tamper/integrity finding on one audited entry                                   |
| supervisor          | — (routing)   | (trigger key, dispatched agent id)                        | ground truth = expected routing decision for a trigger (no OCSF)                  |
| meta-harness        | — (scorecard) | (scored agent id, expected grade/score band)              | ground truth = expected scorecard for a seeded eval (no OCSF)                     |

Notes: the two **no-OCSF** agents (supervisor, meta-harness) measure capability against their
non-finding output (routing correctness / scoring correctness) — the registry key reflects that.
The bare-OCSF agents (appsec/curiosity/synthesis/investigation/remediation/audit) match on the same
key whether or not the envelope is present (L1 finding-#1 ruling).
