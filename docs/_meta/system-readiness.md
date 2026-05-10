# Nexus Cyber OS — System Readiness

|                    |                                                                                                                                          |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------- |
| **Snapshot date**  | 2026-05-10 (end of day — F.2 closeout)                                                                                                   |
| **Phase position** | Phase 1a (Foundation), Week ~2 of 12                                                                                                     |
| **Audience**       | Engineering, founders, design partners' security teams                                                                                   |
| **Purpose**        | Honest assessment of what's built, what's not, and what's needed before any external commitment                                          |
| **Cadence**        | Re-issue at end of each phase milestone (Phase 1a complete → Phase 1b complete → …); date-stamped historical snapshots in this directory |
| **Supersedes**     | [system-readiness-2026-05-09.md](system-readiness-2026-05-09.md)                                                                         |

---

## TL;DR

**Two foundations now real.** This morning we marked F.3 (Cloud Posture reference agent) code-complete. End-of-day, F.2 (Eval Framework v0.1) joined it: 16 of 16 tasks done, 6 of 6 verification gates green, 94.93% coverage, ADR-008 accepted ([verification record](f2-verification-2026-05-10.md)). The Apache 2.0 OSS pair (charter + eval-framework) is now ready to release alongside each other per [ADR-001](decisions/ADR-001-monorepo-bootstrap.md) when [O.6](../superpowers/plans/2026-05-08-build-roadmap.md) ships. **Cross-provider parity (ADR-003) is no longer aspirational** — `run_across_providers` + `diff_results` is the substrate today.

**What's still the same:** the platform is **not** ready for paying customers, edge deployment, vertical content packs, multi-cloud, ChatOps, remediation, self-evolution, or "85% Wiz" coverage claims. None of those are deficiencies — they're scheduled work for Phase 1a's remaining tracks (F.4 auth, F.5 memory, F.6 audit) and Phase 1b/1c.

**Coverage against Wiz today:** ~6.7% on the user-weighted capability framework, unchanged from this morning (F.2 extends substrate, not customer-visible detection). The eval substrate compounds future progress — every Track-D agent ships through the same case-schema → runner → suite → comparison → gate flow, with a one-line `pyproject.toml` entry-point change.

**Recommendation:** still don't show this to a paying prospect. **Suitable** to demo end-to-end to a design partner who has signed an LOI. **Newly suitable** for a published-today OSS announcement of the Apache 2.0 charter + eval-framework pair (gated only by O.6 hardening and a tag).

---

## What changed since the morning snapshot (2026-05-10 AM)

|                                 | Morning (F.3 closeout) |                                       End of day (F.2 closeout) |
| ------------------------------- | ---------------------: | --------------------------------------------------------------: |
| **F.2 tasks shipped**           |                0 of 16 |                                                    **16 of 16** |
| **F.3 tasks shipped**           |               20 of 20 |                                                        20 of 20 |
| **Total tests passing**         |                    203 |                                   **348** (+ 5 skipped, opt-in) |
| **Cloud-posture coverage**      |                 96.09% |                                                          96.09% |
| **Eval-framework coverage**     |                    n/a |                                                      **94.93%** |
| **Source files (mypy strict)**  |                     37 |                                                          **57** |
| **Total Python LOC (monorepo)** |                  6,679 |                                                       **9,334** |
| **ADRs in force**               |                      7 |                            **8** (added ADR-008 eval-framework) |
| **Commits this session**        |                     36 |                                                          **89** |
| **OSS-pair shipping ready**     |           Charter only |               **Charter + eval-framework** (gated by O.6 + tag) |
| **Cross-provider parity gate**  |           Aspirational | **Buildable today** via `run_across_providers` + `diff_results` |
| **Weighted Wiz coverage**       |                  ~6.7% |                                                           ~6.7% |

## What changed since 2026-05-09 (yesterday)

|                                 | Yesterday (2026-05-09) |                                                                       Today (2026-05-10) |
| ------------------------------- | ---------------------: | ---------------------------------------------------------------------------------------: |
| **F.3 tasks shipped**           |                9 of 16 |                                                  **20 of 20** (16 numbered + 4 inserted) |
| **F.2 tasks shipped**           |                      0 |                                                                             **16 of 16** |
| **Total tests passing**         |                    110 |                                                            **348 (+ 5 skipped, opt-in)** |
| **Source files (mypy strict)**  |                     28 |                                                                                   **57** |
| **Total Python LOC (monorepo)** |                  2,851 |                                                                                **9,334** |
| **ADRs in force**               |                      5 | **8** (added ADR-006 OpenAI-compatible, ADR-007 reference agent, ADR-008 eval-framework) |
| **Commits this session**        |                     11 |                                                                                   **89** |
| **Live LLM round-trip proven**  |                     No |              **Yes** — `qwen3:4b` via Ollama, 17.67s incl. audit emission inside Charter |
| **Weighted Wiz coverage**       |                 ~1.25% |                                                                                **~6.7%** |

---

## What's built and verified

| Layer                                        | State                | Evidence                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| -------------------------------------------- | -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Runtime charter (F.1)**                    | ✅ complete          | [`packages/charter/`](../../packages/charter/) — context manager, contracts, budget envelope, tool registry, hash-chained audit, verifier, CLI, `current_charter()` contextvar (added in Task 8.5)                                                                                                                                                                                                                                                                                                                                       |
| **Hello-world reference**                    | ✅ complete          | F.1 commit `21c9abd`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| **Fabric scaffolding** (5.5)                 | ✅ complete          | [`packages/shared/src/shared/fabric/`](../../packages/shared/src/shared/fabric/) — subjects, OCSF envelope wrap/unwrap, ULID correlation_id with asyncio-task isolation                                                                                                                                                                                                                                                                                                                                                                  |
| **LLM provider abstraction** (8.5 + ADR-006) | ✅ complete          | [`charter.llm`](../../packages/charter/src/charter/llm.py) — `LLMProvider` Protocol + `FakeLLMProvider`. [`charter.llm_anthropic`](../../packages/charter/src/charter/llm_anthropic.py) — Anthropic. [`charter.llm_openai_compat`](../../packages/charter/src/charter/llm_openai_compat.py) — covers OpenAI / vLLM / Ollama / OpenRouter / Together / Fireworks / Groq / DeepSeek / llama.cpp / LM Studio. **Live-tested against qwen3:4b on Ollama; audit emission verified inside a Charter context.**                                 |
| **Cloud Posture Agent (F.3)**                | ✅ **code-complete** | [`packages/agents/cloud-posture/`](../../packages/agents/cloud-posture/): 4 async tool wrappers (Prowler / S3 / IAM / Neo4j KG); OCSF v1.3 Compliance Finding schema layer; markdown summarizer; NLAH (domain brain + tools index + 2 OCSF-shaped few-shot examples + loader); LLM adapter (5 providers via `NEXUS_LLM_*` env); async agent driver wiring everything; 10/10 eval cases passing; CLI (`cloud-posture eval` + `cloud-posture run`); LocalStack integration tests; AWS dev-account smoke runbook; package README + ADR-007. |
| **Architectural ADRs**                       | ✅ 7 of 7            | [001](decisions/ADR-001-monorepo-bootstrap.md), [002](decisions/ADR-002-charter-as-context-manager.md), [003](decisions/ADR-003-llm-provider-strategy.md), [004](decisions/ADR-004-fabric-layer.md), [005](decisions/ADR-005-async-tool-wrapper-convention.md), [006](decisions/ADR-006-openai-compatible-provider.md), [007](decisions/ADR-007-cloud-posture-as-reference-agent.md)                                                                                                                                                     |
| **CI**                                       | ✅ baseline          | GitHub Actions — Python tests via `uv run pytest`, lint via `uv run ruff check / format --check`, mypy strict; pre-commit hooks (ruff / prettier / commitlint); conventional commits enforced                                                                                                                                                                                                                                                                                                                                            |
| **Repo bootstrap (P0.1)**                    | ✅ complete          | Turborepo + uv + pnpm + go.work; Apache 2.0 + BSL 1.1 split; CODEOWNERS; .github templates                                                                                                                                                                                                                                                                                                                                                                                                                                               |

### Numbers (verifiable from `git log` and `pytest` today)

|                               |                                                                                                                                                                                           |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Total Python source LOC       | **6,679** (across 74 files)                                                                                                                                                               |
| Source files in monorepo      | 37 (mypy strict over all of them)                                                                                                                                                         |
| Test files                    | 34                                                                                                                                                                                        |
| Tests passing (default)       | **203 / 203** + 5 skipped (opt-in via `NEXUS_LIVE_*` env vars)                                                                                                                            |
| Tests with all live gates set | **210 / 210** (Ollama × 2 proven live; LocalStack × 3 reproducible when docker is up)                                                                                                     |
| Cloud Posture coverage        | **96.09%**                                                                                                                                                                                |
| Ruff lint errors              | 0                                                                                                                                                                                         |
| Mypy strict errors            | 0                                                                                                                                                                                         |
| F.3 tasks shipped             | **20 of 20** (every numbered task + every queued half-task)                                                                                                                               |
| Empty packages awaiting work  | `packages/console/`, `packages/edge/`, `packages/content-packs/{healthcare,tech,generic}/`, `packages/control-plane/` (skeleton), `packages/eval-framework/` (skeleton — F.2 not started) |

---

## Architectural decisions in force (7 ADRs)

| ADR     | Status   | What it pins                                                                                                                                                           |
| ------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ADR-001 | accepted | Single-repo monorepo (Turborepo + uv + pnpm + go.work). Apache 2.0 (charter, eval-framework) + BSL 1.1 (everything else). Self-hosted GHA runners.                     |
| ADR-002 | accepted | Charter is a Python context manager. Lifecycle is explicit; audit entries guaranteed on every code path.                                                               |
| ADR-003 | accepted | **Tiered `LLMProvider` interface** (frontier / workhorse / edge) in `packages/charter`. No agent imports `anthropic` directly. Sovereign / air-gap = config swap.      |
| ADR-004 | accepted | **NATS JetStream fabric** with five named buses. **OCSF v1.3 on `findings.>`**. ULID correlation_id end-to-end.                                                        |
| ADR-005 | accepted | **Async-by-default tool wrappers**. `asyncio.create_subprocess_exec` for binaries; `asyncio.to_thread` for sync SDKs; `httpx.AsyncClient` for HTTP.                    |
| ADR-006 | accepted | **One `OpenAICompatibleProvider`** subsumes vLLM / Ollama / OpenAI / OpenRouter / Together / Fireworks / Groq / DeepSeek. Sovereign / air-gap LLM track is real today. |
| ADR-007 | accepted | **Cloud Posture is the reference NLAH** for the other 17 agents. Codifies 10 template patterns; reviewers gate new agents against them.                                |

---

## Capability coverage — your weighted framework

Re-running the math against today's state:

| Capability                    | Weight | What exists today                                                                                                                                                                                      | Coverage |
| ----------------------------- | -----: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------: |
| **CSPM**                      |   0.20 | Cloud Posture **complete** end-to-end: tools, OCSF schemas, summarizer, charter integration, agent driver, eval (10/10), CLI, smoke runbook. AWS only. 96.09% test coverage. **First runnable agent.** | **~30%** |
| **CWPP**                      |   0.15 | Falco listed in arch, not integrated. D.3 Phase 1b.                                                                                                                                                    |       0% |
| **Vulnerability**             |   0.15 | Trivy listed, not integrated. D.1 Phase 1b.                                                                                                                                                            |       0% |
| **CIEM**                      |   0.10 | IAM tools shipped (`list_users_without_mfa`, `list_admin_policies`) and used inside Cloud Posture, but no standalone CIEM agent. D.2 Phase 1b.                                                         |      ~3% |
| **DSPM**                      |   0.08 | D.5 Phase 1b.                                                                                                                                                                                          |       0% |
| **Compliance**                |   0.10 | OCSF Compliance Finding class wired (class_uid 2003); FINDING_ID_RE enforced; no framework definitions, no controls, no evidence. D.6.                                                                 |      ~3% |
| **Network**                   |   0.05 | D.4 Phase 1b.                                                                                                                                                                                          |       0% |
| **AppSec**                    |   0.05 | D.9 Phase 1b.                                                                                                                                                                                          |       0% |
| **Investigation/Remediation** |   0.07 | Charter audit chain ✓ verified end-to-end (7 entries / hash-valid); LLM provider abstraction in place + live-proven; sub-agent orchestration / Tier-1+2 remediation not started (D.7 / A.1–A.3).       |     ~10% |
| **Threat Intel**              |   0.03 | D.8 Phase 1b.                                                                                                                                                                                          |       0% |
| **AI/SaaS Posture**           |   0.02 | D.10 / D.11 Phase 1b.                                                                                                                                                                                  |       0% |

**Weighted coverage:**

```
0.20·0.30 + 0.15·0 + 0.15·0 + 0.10·0.03 + 0.08·0 + 0.10·0.03
+ 0.05·0 + 0.05·0 + 0.07·0.10 + 0.03·0 + 0.02·0
= 0.060  + 0       + 0       + 0.003   + 0     + 0.003
+ 0      + 0      + 0.007   + 0       + 0
= 6.7%
```

**~6.7% weighted, up from ~1.25% yesterday.** The jump is concentrated in CSPM — one agent of 18 reached ~30% of its capability weight. The honest read: this is the _floor_ for measuring future progress. We move to ~12% when the next two agents (Vulnerability or Identity) ship to template, ~25% by the time half the Track-D agents land in Phase 1b. The 85% target is still M30 GA work.

---

## What's not built and won't be ready in Phase 1a

The honest list. Each item maps to a sub-plan in [`build-roadmap.md`](../superpowers/plans/2026-05-08-build-roadmap.md):

- **17 of 18 agents** — Vulnerability, Identity, Runtime Threat, Network Threat, Data Security, Compliance, Investigation, Threat Intel, Remediation, Curiosity, Synthesis, Meta-Harness, Audit, App/Supply-Chain, SaaS Posture, AI Security, Supervisor. **Cloud Posture is done.**
- **Edge plane** — empty `packages/edge/`. No Go binary, no Helm chart, no edge-side runtime. E.1 / E.2 / E.3 in Phase 1b.
- **Console** — empty `packages/console/`. No Next.js app. S.1 / S.2 in Phase 1b.
- **ChatOps approval flows** — S.3, Phase 1b.
- **Three-tier remediation** — A.1 → A.2 → A.3, Phase 1b → 1c.
- **Self-evolution / Meta-Harness Agent** — A.4, Phase 1c.
- ~~**Eval framework (F.2)**~~ — **shipped** end of day 2026-05-10. 16/16 tasks; 6/6 verification gates green; 146 tests; 94.93% coverage; ADR-008 accepted; cloud-posture migrated off `_eval_local`. See [`docs/_meta/f2-verification-2026-05-10.md`](f2-verification-2026-05-10.md).
- **Vertical content packs** — empty `packages/content-packs/{healthcare,tech,generic}/`. Phase 1b/1c.
- **NATS JetStream client + cluster** — fabric scaffolding (5.5) ships only the schema and the IDs; no broker connection, no consumer groups. Phase 1b (E.2 expansion).
- **Multi-cloud** — AWS only. Azure: D.\* Phase 2. GCP: deferred per PRD.
- **Phase-0 spikes (P0.3 – P0.9)** — none of the seven spikes have been executed. Cloud Custodian vs Terraform decision (P0.3), NLAH writability (P0.4), Neo4j scale (P0.6), Anthropic budget enforcement at customer level (P0.7), edge install flow (P0.8), content pack workflow (P0.9) all unresolved.
- **Cost model validation** — the LLM-COGS line in [`platform_architecture.md §7.1`](../architecture/platform_architecture.md#L644) ($600–1500/mo per mid-market customer) has not been pressure-tested. Cloud Posture v0.1 doesn't call the LLM at all so it provides zero data on this. Investigation/Synthesis agents will produce the first real signal.

---

## Readiness gates

| Gate                                              |        Ready?         | Why / why not                                                                                                                                                                                                                                               |
| ------------------------------------------------- | :-------------------: | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Show the runtime charter to a partner             |        🟢 yes         | F.1 ships; hello-world proves the pipeline; 50+ tests pass.                                                                                                                                                                                                 |
| Open-source the charter package                   |     🟢 unblocked      | Apache 2.0 license in place. **F.2 eval-framework also code-complete** — the OSS pair can release together per [ADR-001](decisions/ADR-001-monorepo-bootstrap.md). Final blocker is now O.6 (tag + contribution guide + code of conduct).                   |
| **Run a single agent against a real AWS account** | 🟡 **operator-ready** | **Was 🔴 yesterday. Now: agent driver works, CLI ships, runbook is documented and live-tested up to the documented Prowler-binary gate. Only blockers are operator-side (AWS read-only creds + `pipx install prowler` + docker for LocalStack pre-check).** |
| Stand up an edge agent in a customer cluster      |         🔴 no         | `packages/edge/` is empty. Phase 1b.                                                                                                                                                                                                                        |
| Sell to a paying customer                         |         🔴 no         | Phase 1 success criteria require all 18 agents + SOC 2 Type I + edge. M9–M12.                                                                                                                                                                               |
| Pass a procurement security review                |         🔴 no         | No SOC 2, no penetration test, no DPA, no BAA. Phase 1a deliverable for Type I scoping; Type II at M18.                                                                                                                                                     |
| Claim "85% Wiz coverage"                          |         🔴 no         | We are at ~6.7%. The 85% target is M30 GA. No coverage claim is honestly defensible today.                                                                                                                                                                  |
| **Show a design partner with an LOI**             |  🟢 **strengthened**  | **Was "🟢 cautiously" yesterday. Now: end-to-end demo is real — `cloud-posture run --contract` against their dev account produces OCSF findings + summary + verifiable audit chain. Runbook ships.**                                                        |

---

## Top risks (live, ranked)

1. ~~**Sovereign / FedRAMP-High implementability blocked**~~ → **largely retired.** ADR-006's `OpenAICompatibleProvider` is shipped, with `for_vllm_local()` and `for_ollama()` convenience constructors. Live integration tests verify the round-trip against `qwen3:4b` on Ollama, with audit emission inside a Charter context. **Remaining work:** cross-provider eval parity (gated by F.2). This was risk #1 yesterday — moves down the list.

2. **Cost model unvalidated** — unchanged. Mid-market LLM line at $600–1500/mo per customer in [`§7.1`](../architecture/platform_architecture.md#L644) not pressure-tested. Cloud Posture v0.1 doesn't call the LLM, so no real signal yet. Per-customer monthly aggregator in the charter still doesn't exist. Build it before any LLM-driving agent (Investigation, Synthesis, Meta-Harness) goes to a real customer.

3. **Empty fabric broker** — unchanged. ADR-004 codifies five buses + OCSF wire format; the JetStream cluster + leaf-node + ACLs have zero implementation. Recommendation: **P0.10 (new sub-plan)** spike before E.1 starts.

4. **No customer environment exists to learn from** — unchanged. Every architectural decision so far is theoretically informed. The 30-customer discovery sprint named in [`§8.1`](../architecture/platform_architecture.md#L726) is unstarted. Mitigation: prioritize the discovery sprint in parallel with the build.

5. **Operations debt under-resourced for Phase 1** — unchanged. 3 stateful systems × 2 planes = 6 DBs to operate (TimescaleDB, PostgreSQL, Neo4j on each side). For 8 engineers serving 5–8 design partners, this is a lot of moving parts. Mitigation candidate: defer Neo4j until graph queries are demonstrated necessary; collapse to PostgreSQL + JSONB + pgvector for Phase 1a.

6. **Vendor concentration on Anthropic for production traffic** — **further retired**. ADR-006 abstracted the call site; ADR-008 + F.2's `run_across_providers` is the parity-gate substrate. The Anthropic ↔ Ollama ↔ vLLM ↔ OpenAI swap is a config change with a measurable gate. **Remaining gap:** no agent has actually been pinned to a non-Anthropic provider in CI yet — but the gate that would block a regression now exists.

7. **Husky pre-commit hooks deprecated** — unchanged. Cosmetic today; will fail in husky v10. Schedule before next husky upgrade.

---

## Recommended next 4–6 weeks

In dependency order. F.2 is now retired from this list — it shipped end-of-day 2026-05-10.

1. **F.4 Auth + tenant manager.** Auth0 SSO, SCIM, RBAC, MFA. Parallel-safe with F.5. ~3 weeks. **Highest leverage now** — every Track-D agent eventually needs tenant-scoped auth; lands the SOC 2 Type I starting condition.

2. **F.5 Memory engines integration.** TimescaleDB (episodic) + PostgreSQL (procedural) + Neo4j Aura (semantic). Per-tenant workspace pattern enforced. ~3 weeks. Could be reduced to PostgreSQL + JSONB + pgvector for Phase 1a per risk #5.

3. **F.6 Audit Agent (#14).** Append-only hash-chained log writer at the _platform_ level (not just per-invocation). Builds on the charter audit primitive that F.3 just verified. ~2 weeks.

4. **D.1 Vulnerability Agent.** First agent built to the Cloud Posture template. **Risk-down moment** for [ADR-007](decisions/ADR-007-cloud-posture-as-reference-agent.md) — tests whether the 10 patterns generalize. ~4 weeks. Now also exercises the new eval-framework pipeline: registers a new runner via the `nexus_eval_runners` entry-point group and wires its eval cases through `eval-framework run / compare / gate`.

5. **P0.7 spike — Anthropic budget enforcement at customer level.** Foundation for the per-tenant aggregator missing from the charter. ~1 week.

6. **P0.10 (new sub-plan) — JetStream cluster + leaf-node + first consumer.** Validates ADR-004 before edge plane work begins. ~2 weeks.

7. **O.6 OSS releases.** Apache 2.0 charter + eval-framework can now ship together. Tag, push to public GitHub, contribution guide, code of conduct. ~2 weeks. **Newly unblocked today** — before F.2 closeout, this couldn't ship.

8. **First design-partner LOI conversion.** Demo-able end-to-end via the smoke runbook. Calendar-bounded by external negotiation; not engineering-bounded.

---

## Looking forward — the next 3 months

| Month            | Outcome                                                                                                                                                                                                                                         |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **M2 (current)** | F.3 done ✅. F.2 done ✅. F.4 auth lands. F.5 memory engines wired. F.6 audit agent in dev. **Phase 1a hits the half-way mark.** Capability coverage moves from ~6.7% → ~12% as the second agent (Vulnerability or Identity) lands to template. |
| M3               | F.6 Audit Agent. D.1 Vulnerability + D.2 Identity in dev. **Phase 1a exit gate** — multi-agent reasoning, eval framework gating NLAH changes, auth in place, memory engines flowing.                                                            |
| M4               | First detection-breadth agents in dev (D.1–D.6). First edge agent prototype (E.1) running in a Helm dry-run. Capability coverage ~25%.                                                                                                          |

---

## What this document is — and isn't

This document is **a snapshot of system readiness as of 2026-05-10**. It is intentionally honest about what's missing because the alternative — telling ourselves the spec is the system — would burn money and trust.

Re-issue at the end of each phase milestone. Each issue should:

- update all numbers from `git log` and `pytest`,
- re-run the weighted coverage math,
- re-evaluate every readiness gate,
- prune resolved risks and add new ones,
- date-stamp the prior file as a historical archive (`system-readiness-<date>.md`) so the always-latest file at `system-readiness.md` stays linkable.

This is the project's mirror. Keep it accurate.

---

## Historical snapshots

- [system-readiness-2026-05-09.md](system-readiness-2026-05-09.md) — Phase 1a Week 2 baseline (110 tests, 9/16 F.3 tasks shipped, ~1.25% weighted Wiz coverage)
- this file's morning revision (F.3-closeout) is preserved in git history at commit `b539150`; reachable via `git show b539150:docs/_meta/system-readiness.md`

---

## References

- [Build roadmap (master plan-of-plans)](../superpowers/plans/2026-05-08-build-roadmap.md)
- [F.3 plan with execution status — code-complete](../superpowers/plans/2026-05-08-f-3-cloud-posture-reference-nlah.md)
- [F.3 final verification record (2026-05-10)](f3-verification-2026-05-10.md)
- [F.1 Runtime charter plan](../superpowers/plans/2026-05-08-f-1-runtime-charter-v0.1.md)
- [P0.1 Repo bootstrap plan](../superpowers/plans/2026-05-08-p0-1-repo-bootstrap.md)
- [Platform architecture (the spec)](../architecture/platform_architecture.md)
- [Runtime charter (the laws)](../architecture/runtime_charter.md)
- [PRD](../strategy/PRD.md) · [VISION](../strategy/VISION.md)
- [Version history](version-history.md)
- ADRs: [001](decisions/ADR-001-monorepo-bootstrap.md) · [002](decisions/ADR-002-charter-as-context-manager.md) · [003](decisions/ADR-003-llm-provider-strategy.md) · [004](decisions/ADR-004-fabric-layer.md) · [005](decisions/ADR-005-async-tool-wrapper-convention.md) · [006](decisions/ADR-006-openai-compatible-provider.md) · [007](decisions/ADR-007-cloud-posture-as-reference-agent.md)
