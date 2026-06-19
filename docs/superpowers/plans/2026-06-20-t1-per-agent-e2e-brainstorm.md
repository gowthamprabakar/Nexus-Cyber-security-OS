# T1 — Per-Agent E2E Harness brainstorm (Fleet Test, foundation)

_2026-06-20 · v0.4 Fleet Test Directive (#762) T1 · meta-brainstorm (#763) · v0.2-style template_

## 1. What T1 is

The foundation phase: **one E2E test per agent, run through the real code path against real
backends (in-memory Postgres per Q1), asserting the agent works alone.** T1's harness pattern is
reused by T2/T3/T5 — getting the pattern right is the whole point of doing T1 first. Per R-1:
**20 harnesses, one per package** (meta-harness thin; T3 covers it in depth).

The directive's eight per-agent assertions: (1) OCSF valid, (2) kg_writer wrote expected entity
types, (3) kg_writer wrote expected edges, (4) F.6 audit chain clean + hash-verifiable, (5)
`tenant_id` propagates (no cross-tenant leak), (6) same input on two tenants → two disjoint
subgraphs, (7) live-lane gates honored (default-off → byte-identical), (8) detection found the
seeded violation (no false negatives).

## 2. Recon — the 20-agent matrix (read against main 2026-06-20)

| Agent                      | `run()` semantic_store      | kg_writer            | OCSF                              | Hermes  | input surface                    |
| -------------------------- | --------------------------- | -------------------- | --------------------------------- | ------- | -------------------------------- |
| vulnerability (D.1)        | kwarg                       | yes                  | 2002                              | no      | container images / Trivy         |
| cloud-posture (F.3)        | kwarg                       | yes (`tools/`)       | 2003                              | no      | AWS Prowler + IAM                |
| multi-cloud-posture (D.15) | kwarg                       | yes (`tools/`, #764) | 2003                              | no      | Azure/GCP feeds                  |
| k8s-posture                | kwarg                       | yes                  | 2003                              | no      | kube-bench/Polaris feeds         |
| data-security              | kwarg                       | yes                  | 2003                              | no      | S3/DynamoDB/RDS                  |
| identity (D.2)             | kwarg                       | yes                  | 2003, 2004                        | no      | AWS IAM / federation             |
| compliance (D.9)           | kwarg                       | **no**               | 2003                              | no      | F.3+D.5 findings + CIS           |
| threat-intel (D.8)         | kwarg                       | yes                  | 2003                              | no      | NVD/KEV/MITRE feeds              |
| sspm (D.10)                | kwarg                       | yes                  | 2003                              | no      | GitHub/M365/Slack                |
| aispm (D.11)               | kwarg                       | yes                  | 2003, 2004                        | no      | AWS/Azure/GCP AI + Garak         |
| runtime-threat (D.3)       | kwarg                       | yes                  | 2004                              | no      | Falco/Tracee feeds               |
| network-threat (D.4)       | kwarg                       | yes                  | 2004                              | no      | Suricata/VPC-flow/DNS            |
| curiosity (D.12)           | kwarg                       | yes                  | 2004                              | **yes** | SemanticStore sibling state      |
| synthesis (D.13)           | kwarg (+`llm_provider` req) | yes                  | 2004                              | **yes** | sibling workspace findings       |
| appsec (D.14)              | kwarg                       | yes                  | 2003                              | no      | git repos + SAST/secret scanners |
| investigation (D.7)        | **positional, required**    | **no** (reads)       | 2005                              | **yes** | AuditStore + SemanticStore       |
| remediation (A.1)          | **none**                    | **no**               | 2007                              | no      | findings.json → kubectl patch    |
| audit (F.6)                | **no** (`audit_store`)      | **no**               | 6003 (via F.6, not findings.json) | no      | audit JSONL ingest               |
| supervisor (#0)            | **no** (dispatcher)         | **no**               | none                              | no      | event bus / queue / CLI          |
| meta-harness (A.4)         | kwarg (diff shape)          | yes                  | none                              | **yes** | NLAH + eval suites               |

**Gap lists driving the tiering:**

- **No standard `run(contract, *, semantic_store=None)`**: investigation (required positional),
  synthesis (also requires `llm_provider`), remediation (none), audit (`audit_store`), supervisor
  (unused), meta-harness (`customer_id`/`workspace_root` shape). → Tier B, tailored harnesses.
- **No kg_writer** (can't assert #2/#3): compliance, investigation, remediation, audit, supervisor.
- **No OCSF in findings.json** (can't assert #1 there): supervisor, meta-harness; audit emits
  6003 via the F.6 path, not findings.json.
- **Hermes/skill-lifecycle today = only curiosity, investigation, synthesis, meta-harness** — the
  deterministic detection agents do **not** run `skill_lifecycle`. This contradicts R-3's "T3 =
  14 detection + 3 LLM + cloud-posture." **Surfaced as R-3' for the T3 brainstorm** (don't resolve
  here): T3 must reconcile "close the Hermes loop" against the fact that most detection agents are
  deterministic v0.2 with no skill stage. T1 doesn't touch this.

## 3. The harness pattern (the reusable foundation)

A shared test-support module + a per-agent test that wires it. Per the directive, the per-agent
file is `packages/agents/<agent>/tests/e2e/test_fleet_e2e.py`; the **shared helpers** live in a
new **`packages/integration`** package (also the future home of the T5 pure-breed test, per the
directive's `packages/integration/tests/e2e/test_pure_breed.py` deliverable).

`packages/integration` provides:

- `fleet_testkit.semantic_store()` — the in-memory `SemanticStore` fixture (sqlite +
  `Base.metadata.create_all`), the exact pattern `test_semantic_store.py` / the D.15 e2e use.
- `fleet_testkit.assert_ocsf(envelope_or_dict, *, class_uid)` — unwrap via
  `shared.fabric.envelope.unwrap_ocsf` + assert structural invariants (class_uid correct,
  `finding_info.types[0]` discriminator present, required OCSF fields). (Q4: stricter schema?)
- `fleet_testkit.assert_audit_chain_clean(audit_path)` — load + hash-verify the F.6 chain.
- `fleet_testkit.two_tenant_disjoint(store, run_a, run_b)` — run the same seed under two tenants,
  assert byte-disjoint subgraphs (assertion #6).
- `fleet_testkit.assert_inert_offline(run_without_store)` — assertion #7 (no store → no writes,
  findings byte-identical).

Each per-agent `test_fleet_e2e.py`:

1. Seeds the agent's tool surface with a **known violation** using the existing live-lane fakes
   (Q2 = fakes-only), monkeypatching the I/O readers (the established per-agent pattern).
2. Runs the real `run(...)` with an injected in-memory `semantic_store`.
3. Calls the shared assertions for the subset that applies to its tier (§4).

## 4. Assertion applicability by tier (honest — gaps are not faked green)

| Tier             | Agents                                                                                                                                                                                                                                                            | Assertions applied               |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------- |
| **A — full**     | vulnerability, cloud-posture, multi-cloud-posture, k8s-posture, data-security, identity, threat-intel, sspm, aispm, runtime-threat, network-threat, appsec, curiosity, synthesis                                                                                  | all 8                            |
| **B — no graph** | compliance (OCSF+audit+tenant, **no #2/#3**), investigation (OCSF 2005 + reads-graph + audit; assert it _reads_ the seeded graph, not writes)                                                                                                                     | 1,4,5,6,7,8                      |
| **B — action**   | remediation (OCSF 2007 from seeded findings.json; assert the recommend-only default + audit; no graph)                                                                                                                                                            | 1,4,5,7,8                        |
| **B — special**  | audit (assert 6003 tamper-detect via F.6 path + chain integrity; no findings.json OCSF, no graph), supervisor (assert routing decision correctness + audit; no OCSF/graph), meta-harness (**thin**: assert it runs + emits a scorecard + audit clean; depth → T3) | tailored subset, each documented |

No agent asserts an assertion it structurally cannot satisfy; every omission is named in its test
docstring with the reason (swiss-bar #5 — no scaffolding-green).

## 5. Sequencing

1. **Stand up `packages/integration` + `fleet_testkit` + lock the pattern on 2 reference agents**
   — one posture (**cloud-posture**, 2003 + spine writer) + one detection (**runtime-threat**,
   2004 + push-feed). Per-PR review (Q7 — foundation infra). This proves the pattern generalizes
   across the two dominant shapes before the cascade.
2. **Cascade the remaining 18** per-agent harnesses — self-merge (Q7), each importing
   `fleet_testkit`. Tier-B agents reviewed per-PR only if they extend the testkit surface.
3. T1 PASS = 20 green harnesses; pattern + CI gate locked → unblocks T2/T3/T4.

## 6. Q-set for T1

- **T1-Q1 — shared-helper home.** New `packages/integration` package for `fleet_testkit` +
  (later) T5? _Rec: yes_ — the directive already names `packages/integration/tests/e2e/` for T5;
  stand it up now so T1 helpers and T5 share one home. (Alternative: a charter test-support
  module — rejected, charter is substrate, not test infra.)
- **T1-Q2 — Tier-B tailored subsets.** Confirm the §4 per-tier assertion subsets, especially:
  supervisor T1 = "routing decision correctness + audit clean" (no OCSF/graph); meta-harness T1 =
  thin (runs + scorecard + audit), depth deferred to T3; investigation = assert it _reads_ the
  seeded graph (it's a read-only orchestrator, no kg*writer). \_Rec: as tabled.*
- **T1-Q3 — reference agents.** cloud-posture + runtime-threat to lock the pattern (per-PR), rest
  self-merge. _Rec: yes._ (Alternative pair if you prefer a different archetype.)
- **T1-Q4 — OCSF validation strictness.** Assert via `unwrap_ocsf` + structural invariants
  (class*uid + `finding_info.types[0]` + required fields), or add a full OCSF JSON-schema
  validator to `fleet_testkit`? \_Rec: structural invariants for T1* (no OCSF schema validator
  exists in-repo today); a full schema validator is a v0.5 hardening if needed.
- **T1-Q5 — seeded-violation source.** Each harness seeds via the **existing live-lane fakes**
  (monkeypatched readers), not new fixtures. _Rec: yes_ (Q2 fakes-only; reuse, don't reinvent).
- **T1-Q6 — review mode.** Per-PR on `packages/integration`/`fleet_testkit` + the 2 reference
  harnesses; self-merge on the other 18. _Rec: as locked in directive Q7._

## 7. Swiss bar

Directive §3 (ten rules) binding verbatim — real code paths, no mock theater, **tenant isolation
in every harness** (assertions #5/#6 are mandatory for every agent that touches a store), no
scaffolding-green (Tier-B omissions are documented, not faked), each harness is its final form +
a CI regression gate. Plus standing bars: opt-in/default-off live lanes byte-identical (assertion
#7), in-memory backend at T1 is the documented aiosqlite path (not mock theater), sequence via main.

## 8. Non-goals (T1)

- Cross-agent correlation (T2), Hermes-loop closure (T3), concurrency/scale (T4), the pure-breed
  finale (T5).
- Resolving R-3' (which agents close the Hermes loop) — that's the T3 brainstorm's job; flagged here.
- Real Postgres (Q1 → T4/T5 only) and sandboxed cloud accounts (Q2 → v0.5).
- Wiring `run()` signatures into a uniform shape — Tier-B agents keep their shapes; the harness
  adapts (no agent refactor for test convenience).

## 9. Open for operator

Confirm T1-Q1..Q6, and acknowledge **R-3'** (Hermes-loop reality: only 4 agents run the skill
lifecycle today) as a T3-brainstorm input. On approval: stand up `packages/integration` +
`fleet_testkit` + the 2 reference harnesses (per-PR), then cascade the other 18 (self-merge).
