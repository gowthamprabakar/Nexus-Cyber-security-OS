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

| #   | Attack path                                                                          | Feeder agents                                            | Status                                    |
| --- | ------------------------------------------------------------------------------------ | -------------------------------------------------------- | ----------------------------------------- |
| 1   | Public resource + sensitive data + over-permissioned identity                        | **data-security**, **identity**                          | ✅ path + feeders REAL (moto, 2026-06-22) |
| 2   | Internet-exposed workload + critical/exploitable vulnerability (KEV)                 | vulnerability, cloud-posture/network (exposure)          | ⬜                                        |
| 3   | Public resource + exposed secret/credential                                          | **data-security** (secrets), cloud-posture/appsec        | 🟡                                        |
| 4   | Over-permissioned identity → privilege-escalation → sensitive resource               | identity (fine-grained effective-perms), cloud-posture   | ⬜ (needs identity depth)                 |
| 5   | Internet-exposed + vulnerable + high-privilege + sensitive (the "crown jewel" 4-hop) | vulnerability, identity, **data-security**, network      | ⬜                                        |
| 6   | Privileged/host-mounted K8s workload + sensitive data/secret access                  | k8s-posture, **data-security**                           | ⬜ (needs kind)                           |
| 7   | Public + unencrypted storage + sensitive data + compliance violation                 | cloud-posture, **data-security**, compliance             | ⬜                                        |
| 8   | External/cross-account trust + over-permission → sensitive resource                  | identity (external-access/federation), **data-security** | ⬜                                        |
| 9   | Vulnerable container image (registry) deployed to internet-facing workload           | vulnerability (registry), k8s-posture/network            | ⬜                                        |
| 10  | Exposed AI/ML service + sensitive training data / prompt-injection risk              | aispm, **data-security**                                 | ⬜                                        |

**Core feeder set (covers ~all paths): data-security ✅, identity (✅ basic / depth pending), vulnerability, cloud-posture, network-threat, k8s-posture, compliance, aispm — ~8 agents, heavy reuse.**

## Verification Order (value × feeder-reuse)

Prioritize paths that are high-value AND unlock the most reuse:

1. **Path 1 — DONE.** Template proven (data-security + identity REAL via moto).
2. **Path 2** → verify **vulnerability** REAL (Trivy + real test image / moto-ECR). Unlocks 2, 5, 9.
3. **Path 4** → **identity depth** (fine-grained HAS_ACCESS_TO from concrete policy Resources). Unlocks 4, 5, 8.
4. **Path 6** → stand up **kind**, verify **k8s-posture** REAL. Unlocks 6, 9.
5. **Paths 3, 7, 8, 10** → mostly reuse verified feeders + one new pattern each.
6. **Path 5** → the crown jewel; lands once 2 + 4 feeders are REAL.

Each path = (verify its new feeder REAL in CI) + (wire the correlation pattern) + (ship it, demoable). ~1 shippable path/week after the first.

## Measurement (so "50-60% of Wiz" is a fact, not a feeling)

Use the L2 capability banks to score each path's precision/recall against ground-truth fixtures. Coverage becomes a measured number as paths complete.

## Parked (does NOT block the north star — honest debt, deferred)

- DB-level tenant RLS hardening (store-layer GUC + FORCE RLS) — app-level isolation holds; revisit before real customer data. [see truth-audit doc]
- Azure/GCP-only detection paths — likely **operator-verified**, not CI-REAL (mocks too weak). Labeled honestly.
- Auto-driven continuous loop; supervisor `del semantic_store` placeholder; pgvector ANN; effective-perms simulator (live-AWS only).

## Honest ceiling

~10 patterns ≈ pitchable demo (~6–10 wks). More patterns = additive, indefinite. Generic path engine = the true Wiz-class match (longer arc) — but the architecture supports it with no rewrite. Slow and steady, no ceiling that forces starting over.
