# Nexus Cyber OS — System Readiness

|                    |                                                                                                 |
| ------------------ | ----------------------------------------------------------------------------------------------- |
| **Snapshot date**  | 2026-05-09                                                                                      |
| **Phase position** | Phase 1a (Foundation), Week ~2 of 12                                                            |
| **Audience**       | Engineering, founders, design partners' security teams                                          |
| **Purpose**        | Honest assessment of what's built, what's not, and what's needed before any external commitment |
| **Cadence**        | Re-issue at end of each phase milestone (Phase 1a complete → Phase 1b complete → …)             |

---

## TL;DR

**The platform is in foundation mode.** The runtime charter (the "physics" every agent runs under) is done. The first agent (Cloud Posture) has all four tool wrappers built and the OCSF-compliant finding schema in place. The fabric layer (subjects + envelope + correlation_id) is scaffolded. Three load-bearing architectural decisions (LLM provider strategy, fabric layer, async tool wrappers) are now codified as ADRs.

**The platform is not yet ready** for any of: customer deployment, end-to-end detection, eval-suite gating, console use, ChatOps approvals, remediation, self-evolution, or coverage claims against Wiz. None of those are deficiencies — they're scheduled work for Phase 1a–1c.

**Coverage against Wiz today:** ~1% on the user-weighted capability framework. The 85% target is the M30 GA goal; today is M1.5.

**Recommendation:** **Do not show this to a paying prospect yet.** It is suitable to show a design partner who has signed an LOI and understands they're seeing pre-MVP work. Phase 1a's exit gate (one end-to-end agent invocation against AWS dev account, eval suite passing) is the earliest credible "we have something working" moment.

---

## What's built and verified

| Layer                        | State       | Evidence                                                                                                                                                                                                                                                                                                                                                                                                          |
| ---------------------------- | ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Runtime charter (F.1)**    | ✅ complete | [`packages/charter/`](../../packages/charter/) — context manager, contracts, budget envelope, tool registry, hash-chained audit, verifier, CLI                                                                                                                                                                                                                                                                    |
| **Hello-world reference**    | ✅ complete | F.1 commit `21c9abd` — proves end-to-end charter pipeline (audit chain emits and verifies on a trivial agent)                                                                                                                                                                                                                                                                                                     |
| **Fabric scaffolding (5.5)** | ✅ complete | [`packages/shared/src/shared/fabric/`](../../packages/shared/src/shared/fabric/) — subject builders, OCSF envelope wrap/unwrap, ULID correlation_id with asyncio-task-isolated contextvar                                                                                                                                                                                                                         |
| **Cloud Posture tools**      | ✅ partial  | 4/4 planned tool wrappers built and async: [Prowler subprocess](../../packages/agents/cloud-posture/src/cloud_posture/tools/prowler.py), [S3 describe](../../packages/agents/cloud-posture/src/cloud_posture/tools/aws_s3.py), [IAM analyzer](../../packages/agents/cloud-posture/src/cloud_posture/tools/aws_iam.py), [Neo4j KG writer](../../packages/agents/cloud-posture/src/cloud_posture/tools/neo4j_kg.py) |
| **OCSF finding schema**      | ✅ complete | [`schemas.py`](../../packages/agents/cloud-posture/src/cloud_posture/schemas.py) — class_uid 2003 (Compliance Finding), severity_id mapping, FINDING_ID_RE regex, NexusEnvelope round-trip, FindingsReport aggregate                                                                                                                                                                                              |
| **Architectural ADRs**       | ✅ 5 of 5   | [ADR-001](decisions/ADR-001-monorepo-bootstrap.md), [ADR-002](decisions/ADR-002-charter-as-context-manager.md), [ADR-003](decisions/ADR-003-llm-provider-strategy.md), [ADR-004](decisions/ADR-004-fabric-layer.md), [ADR-005](decisions/ADR-005-async-tool-wrapper-convention.md)                                                                                                                                |
| **CI**                       | ✅ baseline | GitHub Actions on every PR (lint, tests, security scan); pre-commit hooks (ruff, prettier, commitlint); conventional-commits enforced                                                                                                                                                                                                                                                                             |
| **Repo bootstrap (P0.1)**    | ✅ complete | Turborepo, uv (Python), pnpm (TS), `go.work` (Go), Apache 2.0 + BSL 1.1 split, license attribution, CODEOWNERS                                                                                                                                                                                                                                                                                                    |

### Numbers (verifiable from `git log` and `pytest` today)

|                              |                                                                                                                                  |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Total Python source LOC      | **2,851**                                                                                                                        |
| Source files in monorepo     | 28 (mypy strict over all of them)                                                                                                |
| Test files                   | 23                                                                                                                               |
| Tests passing                | **110 / 110**                                                                                                                    |
| Ruff lint errors             | 0                                                                                                                                |
| Mypy strict errors           | 0                                                                                                                                |
| Commits this session         | 11                                                                                                                               |
| F.3 plan tasks shipped       | 9 of 16 (1, 2, 3, 4, 4.5, 5, 5.5, 6, 6.5)                                                                                        |
| Empty packages awaiting work | `packages/console/`, `packages/edge/`, `packages/content-packs/{healthcare,tech,generic}/`, `packages/control-plane/` (skeleton) |

---

## Architectural decisions in force

| ADR     | Status   | What it pins                                                                                                                                                            |
| ------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ADR-001 | accepted | Single-repo monorepo (Turborepo + uv + pnpm + go.work). Apache 2.0 (charter, eval-framework) + BSL 1.1 (everything else). Self-hosted GHA runners.                      |
| ADR-002 | accepted | Charter is a Python context manager (`with Charter(contract) as ctx:`). Lifecycle is explicit; audit entries guaranteed on every code path.                             |
| ADR-003 | accepted | **Tiered `LLMProvider` interface** (frontier/workhorse/edge) in `packages/charter`. No agent imports `anthropic` directly. Sovereign/air-gap = config swap.             |
| ADR-004 | accepted | **NATS JetStream fabric** with five named buses (events / findings / commands / approvals / audit). OCSF v1.3 on `findings.>`. ULID correlation_id end-to-end.          |
| ADR-005 | accepted | **Async-by-default tool wrappers**. `asyncio.create_subprocess_exec` for binaries; `asyncio.to_thread` for sync SDKs (boto3, neo4j-sync). `httpx.AsyncClient` for HTTP. |

---

## Capability coverage — your weighted framework

Re-running the math from the May 9 audit:

| Capability                    | Weight | What exists today                                                                                                 | Coverage |
| ----------------------------- | -----: | ----------------------------------------------------------------------------------------------------------------- | -------: |
| **CSPM**                      |   0.20 | Prowler async wrapper compiles + tests pass; agent driver (Task 10) not yet built; OCSF schema in place; AWS only |  **~3%** |
| **CWPP**                      |   0.15 | Falco listed in arch, not integrated. D.3 (Phase 1b).                                                             |       0% |
| **Vulnerability**             |   0.15 | Trivy listed, not integrated. D.1 (Phase 1b).                                                                     |       0% |
| **CIEM**                      |   0.10 | IAM analyzer tool exists (`list_users_without_mfa`, `list_admin_policies`); no agent driver, no graph yet. D.2.   |      ~1% |
| **DSPM**                      |   0.08 | D.5 (Phase 1b).                                                                                                   |       0% |
| **Compliance**                |   0.10 | OCSF Compliance Finding class wired in `schemas.py`; no framework definitions, no controls, no evidence. D.6.     |      ~2% |
| **Network**                   |   0.05 | D.4 (Phase 1b).                                                                                                   |       0% |
| **AppSec**                    |   0.05 | D.9 (Phase 1b).                                                                                                   |       0% |
| **Investigation/Remediation** |   0.07 | Charter audit chain ✓; D.7 / A.1–A.3 not started.                                                                 |      ~5% |
| **Threat Intel**              |   0.03 | D.8 (Phase 1b).                                                                                                   |       0% |
| **AI/SaaS Posture**           |   0.02 | D.10 / D.11 (Phase 1b).                                                                                           |       0% |

**Weighted coverage:**

```
0.20·0.03 + 0.15·0 + 0.15·0 + 0.10·0.01 + 0.08·0 + 0.10·0.02
+ 0.05·0 + 0.05·0 + 0.07·0.05 + 0.03·0 + 0.02·0
= 0.0060 + 0.0010 + 0.0020 + 0.0035
= 1.25%
```

**1.25%** weighted. By the user-supplied calibration (`<60% = behind plan, 60–75% = on plan, 75–85% = ahead, >85% at this stage = optimistic`), we are at "Phase 1a, Week 2" — pre-baseline. The number doesn't yet tell you we're behind plan; it tells you Phase 1a hasn't reached its first deliverable. The right read of this number: it's the floor we measure progress against, not a signal of execution health.

---

## What's not built and won't be ready in Phase 1a

This is the honest list. Each item maps to a sub-plan in [`build-roadmap.md`](../superpowers/plans/2026-05-08-build-roadmap.md):

- **17 of 18 agents** — Vulnerability, Identity, Runtime Threat, Network Threat, Data Security, Compliance, Investigation, Threat Intel, Remediation, Curiosity, Synthesis, Meta-Harness, Audit, App/Supply-Chain, SaaS Posture, AI Security. (The first agent — Cloud Posture — is itself only ~60% built; agent driver and end-to-end LocalStack run not yet shipped.)
- **Edge plane** — empty `packages/edge/` directory. No Go binary, no Helm chart, no edge-side runtime. Owned by E.1 / E.2 / E.3 in Phase 1b.
- **Console** — empty `packages/console/`. No Next.js app, no chat sidebar, no findings drill-down. Owned by S.1 / S.2 in Phase 1b.
- **ChatOps approval flows** (Slack / Teams / Email) — owned by S.3, Phase 1b.
- **Three-tier remediation** — owned by A.1 → A.2 → A.3, Phase 1b → 1c.
- **Self-evolution / Meta-Harness Agent** — owned by A.4, Phase 1c.
- **Eval framework** (F.2) — package skeleton only; no case format, no runner, no gates, no traces, no comparison reports. Phase 1a deliverable.
- **Vertical content packs** — empty `packages/content-packs/{healthcare,tech,generic}/`. Phase 1b/1c.
- **NATS JetStream client + cluster** — fabric scaffolding (5.5) only ships the schema and the IDs; no broker connection, no consumer groups, no operator. Phase 1b (E.2 expansion).
- **`charter.llm` LLMProvider implementation** — interface specified in ADR-003; code lands at Task 8.5, then Task 9 consumes it.
- **Multi-cloud support** — AWS only. Azure: D.\* tasks Phase 2. GCP: deferred per PRD.
- **Phase-0 spikes (P0.3 – P0.9)** — none of the seven spikes have been executed. Decisions about Cloud Custodian vs Terraform (P0.3), NLAH writability (P0.4), Neo4j scale (P0.6), Anthropic budget enforcement (P0.7), edge install flow (P0.8), and content pack workflow (P0.9) are unresolved.
- **Cost model validation** — the LLM-COGS line in [`platform_architecture.md §7.1`](../architecture/platform_architecture.md#L644) ($600–1500/mo per mid-market customer) has not been pressure-tested against actual agent invocations and is likely off by an order of magnitude.

---

## Readiness gates

Concrete things we are or aren't ready for. **Do not commit external work past a gate that's not green.**

| Gate                                          |    Ready?     | Why / why not                                                                                                                        |
| --------------------------------------------- | :-----------: | ------------------------------------------------------------------------------------------------------------------------------------ |
| Show the runtime charter to a partner         |    🟢 yes     | F.1 ships, hello-world reference proves the pipeline, 50+ tests pass.                                                                |
| Open-source the charter package               |    🟡 soon    | Apache 2.0 license is in place. Defer until F.2 lands (eval-framework is the second OSS package; release them together per ADR-001). |
| Run a single agent against a real AWS account |     🔴 no     | Cloud Posture agent driver (Task 10) not yet built. Tools exist, charter exists, schemas exist; integration is the missing piece.    |
| Stand up an edge agent in a customer cluster  |     🔴 no     | `packages/edge/` is empty. Phase 1b work.                                                                                            |
| Sell to a paying customer                     |     🔴 no     | Phase 1 success criteria require all 18 agents + SOC 2 Type I + edge deployment; achievable M9–M12. Today is M1.5.                   |
| Pass a procurement security review            |     🔴 no     | No SOC 2, no penetration test, no DPA, no BAA. Phase 1a deliverable for Type I scoping; Type II at M18.                              |
| Claim "85% Wiz coverage"                      |     🔴 no     | We are at ~1.25%. The 85% target is M30 GA. No coverage claim is honestly defensible today.                                          |
| Show a design partner with an LOI             | 🟢 cautiously | The runtime charter, the OCSF schema choice, and the ADR set are credible artifacts to share. Be explicit it's pre-MVP.              |

---

## Top risks (live, ranked)

1. **The architecture's air-gap / sovereign / FedRAMP-High promises are incompatible with Phase 1a's API-only LLM strategy.** ADR-003 is the structural fix (tiered provider + interface + sovereign-deployment config), but the actual self-hosted-LLM track has zero implementation today and is outside Phase 1a scope. Selling defense / classified customers is not on the table until Phase 4+, and any earlier commitment will be a contradiction.

2. **Cost model is optimistic.** Mid-market LLM line at $600–1500/mo per customer probably underprices true Phase 1a usage by 5–10×. Charter has per-execution budget enforcement (we built it); per-customer monthly aggregator does not exist yet. Build it before any customer hits production usage.

3. **Empty fabric broker.** ADR-004 codifies five buses + OCSF wire format; the JetStream cluster + leaf-node + ACLs have zero implementation. Risk: by the time we wire it (E.2), we'll discover schema or routing issues at scale that should have been spiked earlier. Recommendation: P0.10 spike before E.1 starts.

4. **Vendor concentration on Anthropic.** ADR-003 names the abstraction; no second provider has been wired against it. Risk: Anthropic outage or policy change with no fallback in production. Mitigation: ship `FakeLLMProvider` (Task 8.5) and a second provider (Bedrock or vLLM) before agent #2 lands.

5. **No customer environment exists to learn from.** Every architectural decision so far is theoretically informed. The 30-customer discovery sprint named in [`platform_architecture.md §8.1`](../architecture/platform_architecture.md#L726) is unstarted. Risk of building a beautifully designed platform that the actual customer doesn't want. Mitigation: prioritize the discovery sprint in parallel with the build.

6. **Operations debt under-resourced for Phase 1.** Three stateful systems × two planes = six DBs to operate (TimescaleDB, PostgreSQL, Neo4j on each side). For 8 engineers serving 5–8 design partners, this is a lot of moving parts. Mitigation candidate: defer Neo4j until graph queries are demonstrated necessary; collapse to PostgreSQL + JSONB + pgvector for Phase 1a.

7. **Husky pre-commit hooks deprecated** ([`.husky/`](../../.husky/) emits warnings on every commit). Cosmetic today; will fail in husky v10. Schedule before next husky upgrade.

---

## Recommended next 4–6 weeks

In dependency order:

1. **Finish F.3 Cloud Posture Agent end-to-end** (Tasks 7 → 16). Critical path. ~3 weeks of focused work. Exit: agent runs against a real AWS dev account, produces OCSF findings + markdown summary, audit chain verifies, eval suite ≥ 10 cases pass.

2. **F.2 Eval Framework v0.1.** Currently a skeleton. Without it, Task 8.5 (LLMProvider) has no parity gate, Task 12 (eval runner) has nothing to extract from, and Meta-Harness (A.4) has no place to land later. ~3 weeks parallelizable with F.3.

3. **P0.7 spike — Anthropic budget enforcement at customer level.** Foundation for the per-tenant aggregator missing from the charter. ~1 week.

4. **P0.10 (new sub-plan) — JetStream cluster + leaf-node + first consumer.** Validates ADR-004 before edge plane work begins. ~2 weeks.

5. **F.4 Auth + tenant manager.** Auth0 SSO, SCIM, RBAC, MFA. Parallel-safe with F.3; ~3 weeks.

6. **First design-partner LOI conversion.** Requires (1) and (5) done. Calendar-bounded by external negotiation; not engineering-bounded.

---

## Looking forward — the next 3 months

| Month        | Outcome                                                                                                                              |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------ |
| M2 (current) | F.3 Tasks 7–10 ship; eval-framework MVP; first end-to-end Cloud Posture invocation in dev. Capability coverage moves from ~1% → ~5%. |
| M3           | F.3 complete; F.2 v1; Auth + tenant manager (F.4); memory engines integration (F.5); audit agent (F.6). **Phase 1a exit gate.**      |
| M4           | First detection-breadth agents land (D.1 Vulnerability, D.2 CIEM); first edge agent prototype (E.1) running in a Helm dry-run.       |

---

## What this document is — and isn't

This document is **a snapshot of system readiness as of 2026-05-09**. It is intentionally honest about what's missing because the alternative — telling ourselves the spec is the system — would burn money and trust.

Re-issue this document at the end of each phase milestone. Each issue should:

- update all numbers from `git log` and `pytest`,
- re-run the weighted coverage math,
- re-evaluate every readiness gate,
- prune resolved risks and add new ones.

This is the project's mirror. Keep it accurate.

---

## References

- [Build roadmap (master plan-of-plans)](../superpowers/plans/2026-05-08-build-roadmap.md)
- [F.3 Cloud Posture plan with execution status](../superpowers/plans/2026-05-08-f-3-cloud-posture-reference-nlah.md)
- [F.1 Runtime charter plan](../superpowers/plans/2026-05-08-f-1-runtime-charter-v0.1.md)
- [P0.1 Repo bootstrap plan](../superpowers/plans/2026-05-08-p0-1-repo-bootstrap.md)
- [Platform architecture (the spec)](../architecture/platform_architecture.md)
- [Runtime charter (the laws)](../architecture/runtime_charter.md)
- [PRD](../strategy/PRD.md)
- [VISION](../strategy/VISION.md)
- [Version history (the journal)](version-history.md)
- ADRs: [001](decisions/ADR-001-monorepo-bootstrap.md) · [002](decisions/ADR-002-charter-as-context-manager.md) · [003](decisions/ADR-003-llm-provider-strategy.md) · [004](decisions/ADR-004-fabric-layer.md) · [005](decisions/ADR-005-async-tool-wrapper-convention.md)
