# Attack-Path Roadmap to the North Star

**Living doc — the macro map. Created 2026-06-22.** Every piece of work should ladder to this.

## North Star (one sentence)

> A customer connects a cloud account and, within minutes, sees their top ~10 **real attack paths** — prioritized, explained, with a fix — at a **measured** detection coverage that credibly reads as "half of Wiz, on the things that matter."

## The strategy in one idea

**Organize by attack path, not by agent.** The north star is ~10 attack-path archetypes. Each is fed by a small, overlapping set of agents. So the same program (a) verifies the agents that matter, (b) builds the product, (c) escapes the limbo — all at once.

- **Phase 1 (now):** ~10 hardcoded toxic-combination _patterns_. Fast to value. Additive — no ceiling, no rewrite.
- **Phase 2 (Wiz-class):** a _generic_ path engine — the graph discovers arbitrary exposure→access→impact chains. The typed graph + `kg_query` 3-hop BFS already seeds this. Patterns → engine is an evolution.

## The Discipline (how we escape the limbo)

1. **Done = I watched it work.** An agent/path is **REAL** only when its detection runs against a realistic source (moto / LocalStack / kind / real LLM) in a **CI test that actually executes** — not docs, not fixtures, not hand-fakes, not operator-only-never-run.
2. **Three honest grades, always:** **REAL** (CI-verified against realistic reality) · **WIRED** (code exists, fake/gate-tested, real path never verified) · **CLAIMED** (doc says so, code/reality disagrees — e.g. the LTREE bug). Deferred agents get an honest **operator-verified** label — never a fake REAL.
3. **The anti-limbo rule:** when we hit a deeper problem, ask _"does this block the next attack path or the north star?"_ No → write it in the Parked ledger, keep moving. Yes → in scope.

## The ~10 Attack-Path Archetypes (ranked, with feeders + status)

> Status: ✅ REAL (CI-verified) · 🟡 feeders partly REAL · ⬜ not started. Feeders in **bold** are already REAL-verified.

| #   | Attack path                                                                          | Feeder agents                                                         | Status                                                                                                                                      |
| --- | ------------------------------------------------------------------------------------ | --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Public resource + sensitive data + over-permissioned identity                        | **data-security**, **identity**                                       | ✅ path + feeders REAL (moto, 2026-06-22)                                                                                                   |
| 2   | Internet-exposed workload + critical/exploitable vulnerability (KEV)                 | **vulnerability** (real trivy), **cloud-posture** (ECS exposure)      | ✅ REAL (2026-06-22) — `find_internet_exposed_vulnerable_workload` (mechanism-② bridge)                                                     |
| 3   | Public resource + exposed secret/credential                                          | **data-security** (secrets)                                           | ✅ REAL (moto-proven, 2026-06-22) — `find_public_secret_exposure`                                                                           |
| 4   | Over-permissioned identity → fine-grained access → sensitive resource                | **identity** (concrete policy Resources), **data-security**           | ✅ REAL (moto-CI, 2026-06-22) — `find_fine_grained_data_exposure`                                                                           |
| 5   | Internet-exposed + vulnerable + high-privilege + sensitive (the "crown jewel" 4-hop) | **vulnerability**, **identity**, **data-security**, **cloud-posture** | ✅ REAL (2026-06-22) — `find_crown_jewel_exposure` (assembles 2 + 4)                                                                        |
| 6   | Privileged K8s workload running a vulnerable image                                   | **k8s-posture**, **vulnerability**                                    | ✅ REAL (kind + trivy, 2026-06-26) — `find_privileged_vulnerable_workload`                                                                  |
| 7   | Public + unencrypted storage + sensitive data                                        | **data-security**                                                     | ✅ REAL (moto-CI, 2026-06-22) — `find_public_unencrypted_exposure`                                                                          |
| 8   | External/cross-account trust + over-permission → sensitive resource                  | **identity** (offline trust-policy), **data-security**                | ✅ REAL (moto-CI, 2026-06-22) — `find_external_trust_exposure`                                                                              |
| 9   | Vulnerable container image (registry) deployed to internet-facing workload           | vulnerability (registry), k8s-posture/network                         | ⤳ subsumed by path 2 (same `RUNS_IMAGE→VULNERABLE_TO→exposed` chain; registry-scan source is operator-verified — trivy can't scan moto-ECR) |
| 10  | Exposed AI/ML service + sensitive training data                                      | **aispm**, **data-security**                                          | ✅ REAL (moto, 2026-06-26) — `find_exposed_ai_with_sensitive_data`                                                                          |

**Core feeder set (covers ~all paths): data-security ✅, identity ✅ (basic / depth pending), vulnerability ✅ (real trivy, trivy-gated), cloud-posture ✅ (ECS exposure, moto), network-threat, k8s-posture, compliance, aispm — ~8 agents, heavy reuse. 4 of 8 now REAL-verified.**

**Mechanism-② bridge proven (ADR-023):** path 2 closed the first cross-agent join where the two agents do NOT share a canonical key — vulnerability keys images by ref, the spine keys workloads by ARN. `cloud-posture.record_workloads` writes `RUNS_IMAGE` onto the SAME image-ref node vulnerability writes CVEs onto, so a graph walk crosses the gap. This is the template for the remaining misfit joins (network IP→`OWNED_BY`, runtime host→`RUNS_ON`).

## Verification Order (value × feeder-reuse)

Prioritize paths that are high-value AND unlock the most reuse:

1. **Path 1 — DONE.** Template proven (data-security + identity REAL via moto).
2. **Path 2 — DONE.** vulnerability REAL (real `trivy fs`) + cloud-posture ECS exposure REAL (moto) + the **mechanism-② `RUNS_IMAGE` bridge** (ADR-023) joining vuln-images↔workloads. Unlocks 5, 9.
3. **Path 4 — DONE.** identity depth: `_fine_grained_grants` extracts concrete-Resource S3 access offline → fine-grained `HAS_ACCESS_TO` (the non-admin least-privilege violation path 1's admin-only seed misses). moto-REAL.
4. **Path 6** → stand up **kind**, verify **k8s-posture** REAL. Unlocks 6, 9.
5. **Paths 3, 7, 8 — DONE** (reuse verified feeders + one new pattern each). **Path 10** → aispm feeder.
6. **Path 5 — DONE.** The crown jewel: assembled paths 2 + 4 on one workload pivot (exposed + vulnerable + `ASSUMES` a role that reaches sensitive data). Added the workload→task-role `ASSUMES` bridge. **7 of 10 paths REAL (1,2,3,4,5,7,8).** Remaining: **9** (registry image→workload, reuses `RUNS_IMAGE`), **6** (kind + k8s-posture), **10** (aispm).

Each path = (verify its new feeder REAL in CI) + (wire the correlation pattern) + (ship it, demoable). ~1 shippable path/week after the first.

## The product surface — `AttackPathRanker` (the north star, in code)

`meta_harness.attack_paths.AttackPathRanker` is the deliverable: it runs all seven REAL
detectors over a tenant's graph and returns ONE worst-first ranked `AttackPath` list
(type + severity + human title + entities) — "connect an account → see your top attack
paths, prioritized." Severity is the triage judgment: crown_jewel 95 > public_secret 90 >
internet_exposed_vulnerable 80 > public_unencrypted 75 > external_trust 70 >
fine_grained_data 60. Pure aggregation over already-REAL detectors; hermetic. This is what a
demo/API renders. **9 of 10 archetypes REAL feed it (1,2,3,4,5,6,7,8,10); path 9 subsumed by
path 2 → all 10 covered.** Feeders REAL: data-security, identity, vulnerability, cloud-posture,
k8s-posture, aispm (6/8). Severity order: crown_jewel 95 > public_secret 90 >
internet_exposed_vulnerable 80 > privileged_vulnerable 78 > public_unencrypted 75 >
external_trust 70 > exposed_ai_sensitive_data 68 > fine_grained_data 60.

## Measurement (so "50-60% of Wiz" is a fact, not a feeling)

The L2 capability banks (`packages/integration/src/fleet_testkit/tests/banks/path{N}_*/`) score each
path's precision/recall against ground-truth fixtures, driven by `fleet_testkit.bank_runner`. **All 8
distinct detectors are banked** (path 1 subsumed by 4); the **fleet scorecard** (`test_fleet_scorecard.py`)
runs them all and prints one number. As of 2026-06-26: **8 paths, 29 cases, 23 TP / 0 FP / 0 FN →
fleet precision 1.000 / recall 1.000** (paths 2/5 trivy-gated, 6 kind+trivy-gated, run where the tools
exist). The score is the regression floor, not a coverage claim — it is 1.000 **on the bank**, which is
why the gaps below matter.

### Known detection gaps vs Wiz (honest counter-evidence — `test_known_limitations.py`)

The banks measure what we catch; these characterization tests pin what we MISS, so the scorecard's
1.000 is read in context. Closing a gap fails its test on purpose (prompting an update here):

- **Compressed / encoded blobs.** The data-security classifier matches patterns in _decoded UTF-8 text_
  only. A secret or PII inside a **gzip archive** or **base64 blob** is missed (measured: gzipped/base64
  AKIA key → 0 hits; plaintext and JSON-embedded → detected). Wiz/Macie decompress archives + decode
  common encodings. Affects paths 3, 7 and every `EXPOSES_DATA` consumer (1, 4, 5, 8, 10). **Biggest
  single data-coverage gap.**
- **AWS secret access keys.** The AKIA access-key _ID_ is detected, but the **secret access key** (the
  actual credential) has no dedicated pattern; the generic-token rule fires only when the keyword
  (`secret`/`token`/`api_key`) _immediately_ precedes the value. So `secret = <40-char>` is caught but
  the real-world labels **`aws_secret_access_key = <40-char>`** and **`SecretAccessKey: <40-char>`** are
  missed (measured). Secret scanners use entropy + the `aws_secret_access_key` context. (path 3, ripples
  to 1/4/5/8.)
- **Group-inherited IAM access.** `identity._fine_grained_grants` resolves a principal's attached +
  inline policies but **not policies inherited via group membership** — a user whose only S3 access is
  via a group is invisible to path 4 (and path 8). Group membership _is_ read (`group_memberships`); the
  grant resolution just doesn't follow it. Documented v0.2 deferral, now measured.
- **Federated (OIDC/SAML) external trust.** `identity._externally_trusted_arns` flags cross-_account_
  trust (`Principal.AWS`) but not roles assumable via an external **OIDC/SAML provider** (e.g. GitHub
  Actions OIDC, an external IdP) — a real external-access vector. Path 8 = cross-account, not federation.
- (add gaps here as probing finds them — this is where real coverage limits get recorded.)

## Parked (does NOT block the north star — honest debt, deferred)

- DB-level tenant RLS hardening (store-layer GUC + FORCE RLS) — app-level isolation holds; revisit before real customer data. [see truth-audit doc]
- Azure/GCP-only detection paths — likely **operator-verified**, not CI-REAL (mocks too weak). Labeled honestly.
- Auto-driven continuous loop; supervisor `del semantic_store` placeholder; pgvector ANN; effective-perms simulator (live-AWS only).
- Access-Analyzer external-access (online API, not moto-drivable) — **operator-verified only**. Path 8 ships the **offline trust-policy** variant (`_externally_trusted_arns`, CI-REAL); the Access-Analyzer cross-resource findings are a superset that needs live AWS to verify.

## Honest ceiling

~10 patterns ≈ pitchable demo (~6–10 wks). More patterns = additive, indefinite. Generic path engine = the true Wiz-class match (longer arc) — but the architecture supports it with no rewrite. Slow and steady, no ceiling that forces starting over.
