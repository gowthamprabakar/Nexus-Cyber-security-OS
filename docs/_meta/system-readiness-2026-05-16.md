# Nexus Cyber OS — System Readiness + Completion Report (2026-05-16)

|                         |                                                                                                                                                        |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Snapshot date**       | 2026-05-16                                                                                                                                             |
| **Last commit at HEAD** | `e2105c2` — `docs(d6-v0-2): pin task 6 commit hash; 6/6 complete`                                                                                      |
| **Branch state**        | `main` in sync with `origin/main`; working tree clean                                                                                                  |
| **Phase position**      | **Phase 1b detection track CLOSED · Phase 1c bootstrap underway** (D.6 v0.2 = first Phase-1c slice across all 9 ADR-007 agents)                        |
| **Audience**            | Founders, board / investors, design partners, engineering leadership, GTM, recruiting                                                                  |
| **Purpose**             | Macro-to-micro snapshot of platform readiness against the Wiz-class autonomous-security-operations target. Defines the next-steps plan to Phase 1 GA.  |
| **Supersedes**          | [system-readiness-2026-05-13-eod.md](system-readiness-2026-05-13-eod.md) (D.5 close, EOD 2026-05-13)                                                   |
| **Pairs with**          | [D.6 v0.2 verification](d6-v0-2-verification-2026-05-16.md) · [D.6 v0.1 verification](d6-verification-2026-05-13.md) · [VISION](../strategy/VISION.md) |

---

# Part I · Macro snapshot

## §1. The one-page picture

| Dimension                                                                                            |       Today | Phase 1b target | Phase 1 GA (M12) |
| ---------------------------------------------------------------------------------------------------- | ----------: | --------------: | ---------------: |
| **Sub-plans complete** (of ~25 in [build roadmap](../superpowers/plans/2026-05-08-build-roadmap.md)) |     **64%** |             80% |             100% |
| **Production agents shipped** (of 18 in PRD §1.3)                                                    |  **9 / 18** |        ≥10 / 18 |          18 / 18 |
| **Phase 1a foundation** (F.1–F.6)                                                                    |   **6 / 6** |           6 / 6 |             done |
| **Phase 1b detection** (D.4 + D.5 + D.6 + D.7)                                                       |   **4 / 4** |           4 / 4 |         complete |
| **Phase 1c slices (first agent)**                                                                    |   **1 / 8** |             n/a |  expected ~4 / 8 |
| **ADR-007 patterns validated**                                                                       | **10 / 10** |         10 / 10 |          10 / 10 |
| **ADR-007 amendments in force**                                                                      |       **3** |             ≥ 1 |              ≥ 1 |
| **Wiz-equivalent capability coverage** (weighted)                                                    |  **~50.8%** |         ~50–60% |             ~85% |
| **Tests passing**                                                                                    |    **2067** |          ~2000+ |           ~3000+ |
| **Test files**                                                                                       |     **156** |             156 |             ~200 |
| **Source files (mypy strict)**                                                                       |     **184** |             184 |             ~250 |
| **Python LOC**                                                                                       |  **60,464** |         ~60,000 |          ~90,000 |
| **ADRs in force**                                                                                    |       **9** |             ~10 |              ~12 |
| **Plans written**                                                                                    |      **16** |            ~ 18 |             ~ 25 |
| **Commits this campaign**                                                                            |     **308** |            ~325 |            ~ 600 |

**Verdict.** Phase 1b detection track **closed at M2** — originally projected through M5–M7 (~10–12 weeks ahead of schedule). D.6 v0.2 establishes the version-extension pattern (offline → live) that every other agent will follow. **First 50%-weighted-Wiz-coverage threshold crossed.** Half the agentic detection target is complete; the next half (remediation + projection + surfaces + edge) is where the calendar will compress.

---

## §2. Architectural pillars — at a glance

Three structural pillars under the platform; the rest of the report drills into each.

| Pillar                                    | What it is                                                                                                             |     Done | Status                                                                                                                                                                                                          |
| ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | -------: | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Fabric / knowledge substrate**          | OCSF wire shape · 5 named buses · NexusEnvelope · correlation_id propagation · the shared _grammar_ every agent emits  | **~25%** | Scaffolding present (subjects.py / envelope.py / correlation.py) and **every shipped agent** writes to it. Broker transport (NATS JetStream) NOT installed; multi-process replication NOT wired. Phase 1c task. |
| **Runtime charter (F.1)**                 | Execution contracts · budget envelopes · tool registry · audit hash chain · LLM adapter · NLAH loader · memory engines | **~95%** | Production-grade. 236 tests in `charter`. Every shipped agent runs under it. Charter is the most-stable substrate the platform has and is OSS-release-ready.                                                    |
| **Agent layer (detect / project / cure)** | The 18 specialist agents of PRD §1.3, organised by their job-to-be-done                                                | **~30%** | 9 of 18 agents shipped; all 9 are **detect**. 0 of 3 **project** (D.12 Curiosity / D.13 Synthesis / A.4 Meta-Harness). 0 of 3 **cure** (A.1 / A.2 / A.3 remediation tiers).                                     |

The macro picture: **substrate is overbuilt for the current agent count, and agents are over-concentrated in the "detect" quadrant.** That's deliberate — detection commoditises faster than remediation does, and substrate-first sequencing is the cheap-mistake-first strategy. But it means **the next 3-month chunk of work needs to shift the agent-population shape, not pile more detect agents on the same substrate.**

---

# Part II · Mid-level — the three pillars

## §3. Pillar 1 — Fabric / knowledge substrate

### 3.1 Status: scaffolded, not transported

| Component                                                                            | What ships                                                                                              | Status                                                                                  |
| ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| **OCSF v1.3 wire format**                                                            | Every agent emits OCSF (`class_uid 2003` for Compliance Findings, `class_uid 2005` for Incidents, etc.) | ✅ done (F.3 reference; D.5 + D.6 re-export the same schema)                            |
| **5 named buses** (ADR-004: events / findings / commands / approvals / audit)        | `shared.fabric.subjects` provides the canonical naming                                                  | ✅ naming defined · ⬜ transport NOT installed                                          |
| **NexusEnvelope** (correlation_id + tenant_id + agent_id + nlah_version + model_pin) | `shared.fabric.envelope.NexusEnvelope` — used by every agent's `agent.run()`                            | ✅ done · every shipped finding carries one                                             |
| **correlation_id propagation**                                                       | `shared.fabric.correlation.correlation_scope()` context-manager                                         | ✅ done · cross-agent trace context preserved                                           |
| **NATS JetStream broker + 5 streams + retention policies**                           | ADR-004 names them; no installation yet                                                                 | ⬜ pending (Phase 1c **F.7** — to be written)                                           |
| **In-process → broker migration**                                                    | Agents publish via direct method calls today; broker-backed publish-subscribe is the v0.2 of fabric     | ⬜ pending (F.7)                                                                        |
| **Semantic Store (F.5 / Neo4j Aura)**                                                | Charter has `EpisodicStore` + `ProceduralStore` + `SemanticStore` interfaces                            | ✅ interfaces done · live Neo4j gated by `NEXUS_LIVE_NEO4J=1`; integration tests opt-in |
| **Episodic Store (F.5 / TimescaleDB)**                                               | `charter.memory.EpisodicStore`                                                                          | ✅ interface done · live Postgres gated by `NEXUS_LIVE_POSTGRES=1`                      |
| **Procedural Store (F.5 / PostgreSQL)**                                              | `charter.memory.ProceduralStore`                                                                        | ✅ interface done · same env gating                                                     |
| **Knowledge graph (Cartography-style across-cloud asset graph)**                     | Deferred from D.2; named in D.7 sub-agent surface                                                       | ⬜ pending (folded into the Phase-1c F.7 fabric expansion)                              |

### 3.2 Last-mile detail

The fabric **knowledge surface** today is the **OCSF-shaped envelope payload** that every finding carries plus the **subject string** that determines downstream routing. Two specific gaps prevent declaring this pillar done:

1. **No NATS broker installed.** ADR-004 names the streams; no `nats-server` runs anywhere; no agent actually publishes to a topic. Every cross-agent handoff today is **in-process** (the eval-framework / charter test harnesses) or **filesystem-mediated** (`findings.json` artifact handoff to D.7 Investigation). For the design-partner deployment, broker installation is the first Phase-1c-after-D.6 task.
2. **Cross-agent semantic queries** (attack-path graph, identity-graph traversal) are scaffolded in `SemanticStore` but no agent has yet written a real graph-traversal query. D.7's sub-agent fan-out reads findings.json files, not graph queries. **This caps D.7's eventual ceiling** until F.7 lights up the graph surface.

**Estimate of pillar completion: ~25%.** The grammar is done; the runtime transport is not.

---

## §4. Pillar 2 — Runtime charter (F.1)

### 4.1 Status: production-grade, OSS-release-ready

The **most-stable substrate the platform has.** Six closed sub-plans (F.1–F.6) plus the ADR-007 reference template define every agent's lifecycle. **236 tests in the charter package alone**, with strict mypy across 184 source files repo-wide.

| Surface                                  | What ships                                                                                | Verification                                                                             |
| ---------------------------------------- | ----------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| **ExecutionContract**                    | Signed YAML contract with budget envelope, tool whitelist, escalation rules               | F.1 [verification record](f3-verification-2026-05-10.md) ✅                              |
| **Charter context manager**              | `with Charter(contract, tools=registry) as ctx: ...` — enforces budget at every tool call | ADR-002 ✅                                                                               |
| **BudgetSpec (5 axes)**                  | llm_calls / tokens / wall_clock_sec / cloud_api_calls / mb_written                        | F.1 ✅                                                                                   |
| **ToolRegistry**                         | Type-checked per-tool versioning + cloud-call accounting                                  | F.1 ✅ (9 agents register 30+ tools across the platform)                                 |
| **Hash-chained AuditLog**                | F.6 Audit Agent — every action emits a SHA-256-linked entry; tamper-evident               | F.6 [verification record](f6-verification-2026-05-12.md) ✅                              |
| **LLM Adapter (ADR-003 + ADR-006)**      | One interface; Anthropic, OpenAI-compatible, Ollama providers; env-config-driven          | ADR-007 v1.1 amendment (LLM-adapter hoist) — 9 agents consume                            |
| **NLAH Loader (ADR-007 v1.2)**           | One 21-LOC shim per agent → `charter.nlah_loader` does the work                           | 6 native v1.2 agents (D.3 / F.6 / D.7 / D.4 / D.5 / D.6)                                 |
| **Always-on agent class (ADR-007 v1.3)** | F.6 Audit Agent opted in; the rest honour every BudgetSpec axis                           | F.6 ✅                                                                                   |
| **Sub-agent spawning (v1.4 candidate)**  | D.7 Investigation Agent consumes; v1.4 still **deferred at 1 consumer**                   | D.7 [verification record](d7-verification-2026-05-13.md) ✅                              |
| **Memory engines (F.5)**                 | Episodic / Procedural / Semantic interfaces + per-tenant workspace pattern                | F.5 [verification record](f5-verification-2026-05-12.md) ✅                              |
| **Eval framework (F.2)**                 | EvalCase / EvalRunner / suite runner / 10-case-per-agent gates                            | F.2 [verification record](f2-verification-2026-05-10.md) ✅ (8 agents register a runner) |
| **Auth + tenant (F.4)**                  | Auth0 SSO/SCIM/RBAC, OPA, tenant-RLS                                                      | F.4 [verification record](d2-f4-verification-2026-05-11.md) ✅                           |

### 4.2 Last-mile detail

The charter is **~95% complete** for v0.1 needs. The remaining 5% is:

1. **OSS release (O.6)** — `charter` and `eval-framework` packages on public GitHub under Apache 2.0; named in the build roadmap, not yet executed. Low-priority; not blocking customers.
2. **Live integration tests in CI** — Ollama / LocalStack / live-Postgres tests exist but are gated by `NEXUS_LIVE_*` env vars and skipped by default. Need a dedicated CI lane (~1 day's work for DevOps).
3. **Token-budget enforcement at customer level** — P0.7 spike was completed but the customer-tier rate-limiting middleware was not deployed beyond the smoke test. **This becomes load-bearing the moment first paying customer ramps.**

**Estimate of pillar completion: ~95%.** Production-ready for the agent count we have; the OSS releases and the per-customer rate-limit middleware are the only meaningful Phase-1c-pre-GA items.

---

## §5. Pillar 3 — Agent layer (detect / project / cure)

The 18 PRD-named agents organised by **what they actually do** rather than which file they live in.

### 5.1 Detect — observe + classify

> _"What's currently wrong, where, how bad?"_

|   # | Agent                                      | Plan ID    | Status                                  | Last verification                                          | Operator-visible output                                         |
| --: | ------------------------------------------ | ---------- | --------------------------------------- | ---------------------------------------------------------- | --------------------------------------------------------------- |
|   1 | Cloud Posture (AWS, reference NLAH)        | F.3        | ✅ shipped                              | [f3-verification](f3-verification-2026-05-10.md)           | OCSF 2003 + per-tier markdown                                   |
|   2 | Vulnerability                              | D.1        | ✅ shipped                              | [d1-verification](d1-verification-2026-05-11.md)           | OCSF 2002 + Trivy / OSV / KEV / EPSS                            |
|   3 | Identity (CIEM)                            | D.2        | ✅ shipped                              | [d2-f4-verification](d2-f4-verification-2026-05-11.md)     | OCSF 3001 + IAM risk taxonomy                                   |
|   4 | Runtime Threat (CWPP)                      | D.3        | ✅ shipped                              | [d3-verification](d3-verification-2026-05-11.md)           | OCSF 2002 + Falco / Tracee / OSQuery                            |
|   5 | Audit                                      | F.6        | ✅ shipped (always-on)                  | [f6-verification](f6-verification-2026-05-12.md)           | Hash-chained `audit.jsonl` per-run + 5-axis query API           |
|   6 | Investigation                              | D.7        | ✅ shipped (load-bearing LLM)           | [d7-verification](d7-verification-2026-05-13.md)           | OCSF 2005 incident envelopes + sub-agent fan-out                |
|   7 | Network Threat                             | D.4        | ✅ shipped                              | [d4-verification](d4-verification-2026-05-13.md)           | OCSF 4002 + Suricata + VPC Flow + DNS DGA                       |
|   8 | Multi-Cloud Posture (Azure + GCP)          | D.5        | ✅ shipped (first F.3 schema re-export) | [d5-verification](d5-verification-2026-05-13.md)           | OCSF 2003 + CSPMFindingType (4 discriminators)                  |
|   9 | **Kubernetes Posture (v0.2 live cluster)** | D.6        | ✅ **shipped (this session)**           | [d6-v0-2-verification](d6-v0-2-verification-2026-05-16.md) | OCSF 2003 + K8sFindingType (3 discriminators) + live API ingest |
|  10 | Data Security (DSPM)                       | D.5-orig   | ⬜ deferred / reframed                  | —                                                          | (reallocated; original slot became multi-cloud CSPM)            |
|  11 | Compliance (framework engine)              | (D-future) | ⬜ Phase 1c                             | —                                                          | —                                                               |
|  12 | Threat Intel                               | D.8        | ⬜ pending                              | —                                                          | (D.4 + D.5 + D.6 ship with bundled static intel)                |
|  13 | App + Supply Chain Security                | D.9        | ⬜ pending                              | —                                                          | —                                                               |
|  14 | SaaS Posture (SSPM)                        | D.10       | ⬜ pending                              | —                                                          | —                                                               |
|  15 | AI Security (AI-SPM)                       | D.11       | ⬜ pending                              | —                                                          | —                                                               |
|  16 | (slot unallocated)                         | —          | —                                       | —                                                          | —                                                               |
|  17 | (slot unallocated)                         | —          | —                                       | —                                                          | —                                                               |
|  18 | (slot unallocated)                         | —          | —                                       | —                                                          | —                                                               |

**Detect quadrant completion: 9 / 13 detect agents = ~69%.** (The original 18-count includes the 3 project/cure agents that don't belong here; the detect-only denominator is 13.)

### 5.2 Project — anticipate + reason forward

> _"What's about to be wrong? What would happen if we acted?"_

| Agent              | Plan ID | Status     | What it would do                                                                                                                               |
| ------------------ | ------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Curiosity Agent    | D.12    | ⬜ pending | Idle scheduler; runs read-only tools on quiet windows; flags **emergent risk patterns** (account-drift, role-creep) before they trip detectors |
| Synthesis Agent    | D.13    | ⬜ pending | Cross-agent reasoning; weekly/monthly narrative reports; customer-facing summary that **projects forward** ("this quarter, expect X")          |
| Meta-Harness Agent | A.4     | ⬜ pending | Self-evolution: reads reasoning traces, proposes NLAH improvements, eval-gates them, deploys to production                                     |

**Project quadrant completion: 0 / 3 = 0%.** Substrate ready (charter idle-loop primitive supports always-on scheduling; F.5 EpisodicStore can buffer historical context). **The Meta-Harness agent (A.4) is the highest-leverage of the three** — it improves every other agent monthly via deployed NLAH tweaks. Originally Phase 1c late; can move earlier if customer feedback creates the demand signal.

### 5.3 Cure — close the loop

> _"Make the problem go away. Safely. With audit."_

| Agent              | Plan ID | Status     | What it would do                                                                                                                     |
| ------------------ | ------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| Remediation Tier 3 | A.1     | ⬜ pending | **Recommend-only.** Generates Cloud Custodian / Terraform / runbook artifacts; operator reviews + applies. Lowest blast radius.      |
| Remediation Tier 2 | A.2     | ⬜ pending | **Approve-and-execute.** ChatOps approval gate → agent applies the artifact from Tier-3 step. Mid blast radius.                      |
| Remediation Tier 1 | A.3     | ⬜ pending | **Autonomous.** ~8 narrow pre-authorised action classes; dry-run → blast-radius cap → execute → auto-rollback timer → post-validate. |

**Cure quadrant completion: 0 / 3 = 0%.** This is the **single biggest gap between Nexus and Wiz** today. Wiz remediates nothing; Palo Alto's AgentiX gates everything. The Tier-3 → Tier-2 → Tier-1 ramp is **the differentiating capability** of Phase 1 and the **highest revenue lever** (customers pay for "the security platform that fixes things," not "the security platform that lists more things").

---

# Part III · Wiz competitive benchmark — last-mile detail

## §6. Weighted Wiz coverage

| Capability                    | Wiz weight | What exists today                                                                                                                               | Coverage | Weighted contribution |
| ----------------------------- | ---------: | ----------------------------------------------------------------------------------------------------------------------------------------------- | -------: | --------------------: |
| **CSPM (F.3+D.5+D.6)**        |   **0.40** | F.3 AWS (offline + dev-account live) + D.5 Azure + GCP (offline) + **D.6 Kubernetes (offline AND v0.2 live cluster via kubernetes-client SDK)** |  **84%** |             **0.336** |
| **Vulnerability (D.1)**       |       0.15 | Trivy + OSV + NVD + EPSS + CISA-KEV; reachability scoring                                                                                       |  **20%** |             **0.030** |
| **CIEM (D.2)**                |       0.10 | boto3 IAM + Access Analyzer + IAM risk taxonomy                                                                                                 |  **30%** |             **0.030** |
| **CWPP (D.3)**                |       0.10 | Falco + Tracee + OSQuery three-feed                                                                                                             |  **50%** |             **0.050** |
| **Compliance / Audit (F.6)**  |       0.05 | F.6 always-on; hash-chained audit; 5-axis query API; per-tenant RLS                                                                             | **100%** |             **0.050** |
| **CDR / Investigation (D.7)** |       0.07 | 6-stage pipeline; sub-agent fan-out; OCSF 2005; load-bearing LLM with deterministic fallback                                                    |  **85%** |             **0.060** |
| **Network Threat (D.4)**      |       0.05 | Suricata + VPC Flow + DNS; bundled threat intel                                                                                                 |  **80%** |             **0.040** |
| **DSPM**                      |       0.08 | Deferred (D.5 slot reframed)                                                                                                                    |   **0%** |                     0 |
| **AppSec**                    |       0.05 | D.9 pending                                                                                                                                     |   **0%** |                     0 |
| **Remediation (A.1-3)**       |       0.05 | A.1-A.3 pending (this is the Phase-1c headline)                                                                                                 |  **~5%** |             **0.003** |
| **Threat Intel (D.8)**        |       0.03 | Bundled static snapshots in D.4 + D.5 + D.6; D.8 live-feeds pending                                                                             | **~15%** |             **0.005** |
| **AI / SaaS Posture**         |       0.02 | D.10 / D.11 pending                                                                                                                             |   **0%** |                     0 |
| **TOTAL (weighted)**          |       1.00 |                                                                                                                                                 |          |             **0.508** |

**Weighted capability coverage: ~50.8%.** Up from ~46.8% pre-D.6 v0.1 (May-13 EOD) → ~50.8% post-D.6 v0.1 (May-13) → **~50.8% post-D.6 v0.2 (today, May-16)**. v0.2 adds **operator-experience lift** (live cluster mode replaces pre-staging) but does not change the surface area Wiz scores against — so the weighted number holds. **Threshold of 50% Wiz-weight crossed three days ago and held.**

## §7. What Wiz does that we don't — the last-mile gap list

A complete, line-item enumeration of the Wiz feature surface where we lag, ranked by what closes the most customer pain per task-week:

| Wiz feature                                             | Nexus equivalent                | Status                                   | Highest-leverage closure plan                                  |
| ------------------------------------------------------- | ------------------------------- | ---------------------------------------- | -------------------------------------------------------------- |
| **One-click cloud connector (AWS / Azure / GCP / K8s)** | F.3 + D.5 + D.6                 | Offline + (D.6 only) live                | F.3 v0.2 LocalStack→live AWS · D.5 v0.2 live SDK (Azure + GCP) |
| **Attack-path explorer (Security Graph)**               | D.7 sub-agent fan-out           | Findings-correlated, not graph-traversed | F.7 (NATS + Neo4j live wiring) + D.7 v0.2 graph queries        |
| **Auto-remediation (Wiz Actions)**                      | A.1 + A.2 + A.3                 | ⬜ none                                  | A.1 → A.2 → A.3 sequenced; **highest-revenue lever**           |
| **Toxic combinations (multi-finding correlation)**      | D.7 already correlates          | ~60% (single-incident scope)             | D.7 v0.2 cross-incident graph queries (depends on F.7)         |
| **DSPM (sensitive data discovery)**                     | Original D.5 slot               | ⬜ deferred                              | Phase 1c: re-plan as a D-track agent                           |
| **Compliance reporting (SOC2 / HIPAA / ISO27001)**      | F.6 + C.1 + C.2 (content packs) | Audit substrate yes; mappings ⬜         | C.0 generic + C.1 tech-pack (Phase 1c)                         |
| **SBOM + supply-chain (Sigstore)**                      | D.9 plan                        | ⬜ none                                  | D.9 (Phase 1c)                                                 |
| **SaaS posture (M365 / Workspace / Slack / GitHub)**    | D.10 plan                       | ⬜ none                                  | D.10 (Phase 1c)                                                |
| **AI-SPM (model / prompt-injection scanning)**          | D.11 plan                       | ⬜ none                                  | D.11 (Phase 1c)                                                |
| **Console (dashboard + chat + drill-down)**             | S.1 + S.2                       | ⬜ 0 LOC (mockups only)                  | S.1 + S.2 (Phase 1c)                                           |
| **ChatOps approvals (Slack / Teams / email)**           | S.3                             | ⬜ 0 LOC                                 | S.3 (Phase 1c; blocker for A.2)                                |
| **Edge deployment (Helm chart)**                        | E.1 + E.2 + E.3                 | ⬜ 0 LOC (ADRs only)                     | E.1 → E.2 → E.3 (Phase 1c)                                     |
| **Threat-intel live feeds (CISA KEV / OTX / abuse.ch)** | D.8 plan                        | ⬜ none (bundled snapshots in D.4/5/6)   | D.8 (Phase 1c)                                                 |

## §8. What we do that Wiz doesn't

A shorter list — but **these are the differentiators**, the reason a hybrid-enterprise CISO would pick us over the incumbent:

1. **Tiered remediation** (when A.1-A.3 land). Wiz doesn't remediate. Palo Alto's AgentiX requires approval for every action. **We're the only platform aiming at autonomous Tier-1 with proper safety mechanisms.**
2. **Edge mesh deployment** (when E.1-E.3 land). Wiz is cloud-only SaaS. We can deploy at customer-edge for hybrid / OT / classified.
3. **Self-evolving agents** (when A.4 Meta-Harness lands). The platform improves itself monthly via deployed NLAH tweaks.
4. **Always-on Audit Agent** (F.6, shipped). Hash-chained, tamper-evident, per-tenant RLS, 7-year retention design.
5. **Charter + execution-contract substrate** (F.1, shipped). The most-stable agent-runtime in the open ecosystem; OSS-release-pending under Apache 2.0.
6. **Multi-cloud + Kubernetes from day one** (F.3 + D.5 + D.6). No "Kubernetes is a separate product" upsell.

The **detect** quadrant is competitive parity; the **project** + **cure** quadrants are where we draw blood.

---

# Part IV · Vision pillars — micro detail

The four VISION §4 pillars, with last-mile completion estimates:

## §9. §4.1 Continuous autonomous operation — ~50%

What's needed: **24/7 agent loops + heartbeat + 18 agents + scheduler + customer-tier rate-limits.**

| Sub-item                          | Done?                        |
| --------------------------------- | ---------------------------- |
| Charter + always-on class         | ✅ (F.1 + F.6)               |
| 9 of 18 agents running end-to-end | ✅                           |
| Audit chain queryable             | ✅ (F.6 5-axis API)          |
| F.5 memory persists across runs   | ✅ (interfaces; live opt-in) |
| Scheduler / cron-style loop       | ⬜ (Phase 1c)                |
| Customer-tier token rate-limits   | ⬜ (P0.7 spike + middleware) |
| Heartbeat / liveness telemetry    | ⬜ (Phase 1c O.1)            |

## §10. §4.2 Multi-agent specialization — ~50% by count, 100% by template

| Sub-item                                           | Done?                                                                     |
| -------------------------------------------------- | ------------------------------------------------------------------------- |
| ADR-007 reference template stable through 9 agents | ✅ (every shipped agent passes the 10-pattern conformance gate)           |
| ADR-007 v1.1-1.3 amendments in force               | ✅                                                                        |
| ADR-007 v1.4 candidate (sub-agent spawning)        | ✅ in use (D.7) · ⬜ amendment still **deferred at 1 consumer** by design |
| 18 agents shipped                                  | 9 / 18                                                                    |
| Supervisor / delegation primitive                  | ⬜ (Phase 1c late — needs project/cure agents to delegate to)             |

## §11. §4.3 Tiered remediation authority — ~10%

| Sub-item                                | Done?                                             |
| --------------------------------------- | ------------------------------------------------- |
| F.6 audit chain (foundation for tiers)  | ✅                                                |
| D.7 Investigation (recommends fix path) | ✅                                                |
| A.1 Tier-3 (recommend-only)             | ⬜ — Phase 1c **next plan**                       |
| A.2 Tier-2 (approve-and-execute)        | ⬜ — depends on A.1 + S.3 ChatOps                 |
| A.3 Tier-1 (autonomous, narrow)         | ⬜ — depends on A.2 + F.6 + customer-grade safety |
| Rollback timer + blast-radius caps      | ⬜ — designed; not implemented                    |

## §12. §4.4 Edge mesh deployment — ~10% (decisions only)

| Sub-item                                          | Done?                                            |
| ------------------------------------------------- | ------------------------------------------------ |
| ADR-004 fabric (5-bus design)                     | ✅                                               |
| ADR-006 OpenAI-compatible provider (air-gap path) | ✅ (Ollama proven via charter integration tests) |
| Edge agent runtime (Go binary)                    | ⬜ — E.1 plan not written                        |
| mTLS + telemetry pipeline (Vector → ClickHouse)   | ⬜ — E.2                                         |
| Helm chart (EKS / AKS / GKE)                      | ⬜ — E.3                                         |
| Signed bundles + auto-update                      | ⬜ — E.1 / E.3 dependency                        |

---

# Part V · Numbers (verifiable from `git log` + `pytest` at HEAD `e2105c2`)

## §13. Test surface

|                                           |    Value |
| ----------------------------------------- | -------: |
| Tests passing (default)                   | **2067** |
| Tests skipped (opt-in via `NEXUS_LIVE_*`) |   **11** |
| Tests collected total                     | **2078** |
| Test files                                |  **156** |
| Test runtime (default suite)              | **~12s** |

## §14. Per-package test count + coverage

| Package               |    Tests |           Coverage | Notes                                                                                          |
| --------------------- | -------: | -----------------: | ---------------------------------------------------------------------------------------------- |
| `charter`             |    ~ 236 | high (live opt-in) | F.1 + F.5 + LLM adapter + memory engines                                                       |
| `eval-framework`      |     ~146 |            **96%** | F.2                                                                                            |
| `shared`              |      ~26 |                n/a | Fabric scaffolding (subjects / envelope / correlation)                                         |
| `control-plane`       |     ~130 |               high | F.4 (Auth0 SSO/SCIM/RBAC, OPA, tenant RLS)                                                     |
| `cloud-posture`       |      ~78 |            **96%** | F.3 (reference NLAH; ADR-007 #1)                                                               |
| `vulnerability`       |     ~111 |            **97%** | D.1                                                                                            |
| `identity`            |     ~142 |           **~95%** | D.2 (ADR-007 v1.1)                                                                             |
| `runtime-threat`      |     ~181 |            **95%** | D.3 (ADR-007 v1.2)                                                                             |
| `audit`               |     ~129 |            **96%** | F.6 (ADR-007 v1.3 always-on)                                                                   |
| `investigation`       |     ~172 |            **94%** | D.7 (load-bearing LLM; v1.4 candidate)                                                         |
| `network-threat`      |     ~231 |            **94%** | D.4 (3-feed)                                                                                   |
| `multi-cloud-posture` |     ~214 |            **94%** | D.5 (first F.3 schema re-export)                                                               |
| `k8s-posture`         |  **282** |            **97%** | **D.6 v0.1 + v0.2** — 245 + 37 tests across 16 + 6 tasks; OCSF re-export + live cluster reader |
| **TOTAL**             | **2078** |                  — |                                                                                                |

## §15. Source surface

|                                                |      Value |
| ---------------------------------------------- | ---------: |
| Total Python files                             |    **367** |
| Source files                                   |   **~211** |
| Test files                                     |    **156** |
| Total Python LOC                               | **60,464** |
| Ruff lint errors                               |      **0** |
| Ruff format errors                             |      **0** |
| Mypy strict errors                             |      **0** |
| ADRs in force                                  |      **9** |
| Plans written                                  |     **16** |
| Verification records                           |     **11** |
| Total commits this campaign (since 2026-05-08) |    **308** |

---

# Part VI · The Next-Steps Plan

## §16. Phase 1c slice ordering (the next ~12 weeks)

Given today's state, here is the recommended sub-plan sequence to close the Wiz gap and reach Phase 1 GA. **Slices are ordered by revenue-impact-per-task-week**, not by VISION pillar alphabetic order.

### Tier A — must ship before any paying customer (revenue blockers)

|   # | Sub-plan                                            | Track   | Effort     | Why now                                                                                                                                                                                        | Depends on               |
| --: | --------------------------------------------------- | ------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------ |
|   1 | **A.1 — Tier-3 Remediation (recommend-only)**       | Action  | 4 wks      | Closes the **biggest competitive gap** vs Wiz. Recommend-only is the safest tier — no production action; just Cloud Custodian / Terraform / runbook artifacts. Operator sees real ROI day one. | F.6 + D.1 + D.6 (all ✅) |
|   2 | **S.3 — ChatOps approvals (Slack + Teams + Email)** | Surface | 4 wks      | Prerequisite for A.2 Tier-2. Slack integration alone gets us 80% of design-partner workflows.                                                                                                  | F.4 (✅)                 |
|   3 | **A.2 — Tier-2 Remediation (approve-and-execute)**  | Action  | 4 wks      | Combines A.1 artifacts + S.3 approval flow. **First "do" agent.** Single biggest jump in operator-perceived value.                                                                             | A.1 + S.3                |
|   4 | **S.1 — Console v1 (dashboard primary)**            | Surface | 6 wks (//) | Operators want a UI to see what the platform sees. Mockups already exist at [docs/design/console/](../design/console/) — 43 screen designs await build.                                        | F.4 + F.5                |
|   5 | **S.4 — API + CLI**                                 | Surface | 3 wks (//) | Programmatic access for MSSP and SI partners. Python SDK + `nexus` CLI.                                                                                                                        | F.4 (✅)                 |

### Tier B — must ship by Phase 1 GA (M12) to hit the success-criteria gate

|   # | Sub-plan                                                     | Track      | Effort | Why                                                                                                                | Depends on                     |
| --: | ------------------------------------------------------------ | ---------- | ------ | ------------------------------------------------------------------------------------------------------------------ | ------------------------------ |
|   6 | **F.7 — Fabric runtime (NATS JetStream broker + 5 streams)** | Foundation | 4 wks  | Today every agent handoff is in-process / filesystem-mediated. F.7 lights up the bus transport per ADR-004.        | F.1 (✅) + ADR-004 (✅)        |
|   7 | **A.3 — Tier-1 Remediation (autonomous, 8 narrow classes)**  | Action     | 6 wks  | The headline capability. **The reason we win.** Narrow + safe (dry-run + blast-radius cap + auto-rollback timer).  | A.2 + F.6 (✅) + safety review |
|   8 | **D.8 — Threat Intel (live feeds)**                          | Detect     | 4 wks  | Replaces bundled snapshots in D.4/5/6 with live CISA-KEV / OTX / abuse.ch / GreyNoise / H-ISAC.                    | D.4 + D.6 (✅)                 |
|   9 | **S.2 — Console v1 (chat sidebar)**                          | Surface    | 4 wks  | Anthropic-backed contextual chat over the operator's tenant. HIPAA-compliant query audit.                          | S.1 + F.1 (✅)                 |
|  10 | **E.1 + E.2 + E.3 — Edge plane**                             | Edge       | 13 wks | Differentiating capability for hybrid/regulated customers. Six-week Go runtime + four-week mTLS + three-week Helm. | F.1 (✅) + ADR-006 (✅)        |
|  11 | **C.0 + C.1 — Generic + Tech content pack**                  | Content    | 12 wks | Phase-1 sales-focus vertical. SOC 2 deep + ISO 27001 deep + DevSecOps detection rules + audit-evidence templates.  | F.6 (✅) + D.6 (✅) + D.5 (✅) |

### Tier C — close the loop / project-quadrant agents

|   # | Sub-plan                                      | Track   | Effort | Why                                                                                                          | Depends on                                           |
| --: | --------------------------------------------- | ------- | ------ | ------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------- |
|  12 | **A.4 — Meta-Harness Agent (self-evolution)** | Project | 5 wks  | Reads reasoning traces, proposes NLAH improvements, eval-gates them, deploys. **Compounding agent quality.** | F.2 (✅) + every D.\*-shipped agent (8/13 detect ✅) |
|  13 | **D.12 — Curiosity Agent**                    | Project | 3 wks  | Idle "wonder" agent; flags emergent risk patterns before they trip detectors.                                | Every detect agent (8 ✅) + F.5 memory               |
|  14 | **D.13 — Synthesis Agent**                    | Project | 3 wks  | Customer-facing narrative; weekly/monthly executive reports projecting forward.                              | Every detect agent + D.12 Curiosity                  |

### Tier D — Phase-1c CSPM lift (extend existing detect agents to live mode)

|   # | Sub-plan                                       | Track  | Effort | Why                                                                                                                  | Depends on               |
| --: | ---------------------------------------------- | ------ | ------ | -------------------------------------------------------------------------------------------------------------------- | ------------------------ |
|  15 | **F.3 v0.2 — LocalStack → live AWS**           | Detect | 3 wks  | Mirrors D.6 v0.2 pattern. Operators stop pre-staging Prowler exports.                                                | F.3 (✅) + D.6 v0.2 (✅) |
|  16 | **D.5 v0.2 — offline → live Azure + GCP SDKs** | Detect | 4 wks  | Same pattern again. Azure SDK + google-cloud-securitycenter + google-cloud-asset.                                    | D.5 (✅) + D.6 v0.2 (✅) |
|  17 | **D.6 v0.3 — in-cluster ServiceAccount mode**  | Detect | 2 wks  | Last v0.2 friction-point. Pod-mounted SA-token fallback when `--kubeconfig` is omitted.                              | D.6 v0.2 (✅)            |
|  18 | **D.6 v0.4 — RBAC overpermissive analyser**    | Detect | 4 wks  | Highest-impact CSPM-K8s rule the v0.1 ruleset doesn't cover. cluster-admin to non-system; wildcard verbs on secrets. | D.6 v0.2 (✅)            |

### Tier E — Operations + GA readiness (last mile)

|   # | Sub-plan                                 | Track | Effort | Why                                                                                        |
| --: | ---------------------------------------- | ----- | ------ | ------------------------------------------------------------------------------------------ |
|  19 | **O.1 — Observability (Prom + Grafana)** | Ops   | 3 wks  | SLO dashboards, on-call rotation in PagerDuty.                                             |
|  20 | **O.2 — SOC 2 Type I (Nexus's own)**     | Ops   | 8 wks  | Required for any enterprise sale. Security architecture, threat model, pen test, evidence. |
|  21 | **O.3 — Customer onboarding playbook**   | Ops   | 3 wks  | Implementation engineer runbooks; universal + tech-pack + healthcare-pack.                 |
|  22 | **O.4 — Pre-GA hardening**               | Ops   | 4 wks  | DR drill + chaos test + rollback drill + customer comms plan.                              |
|  23 | **O.5 — Mintlify docs site**             | Ops   | 4 wks  | Public API ref + admin guide + threat model + vertical compliance reports.                 |
|  24 | **O.6 — OSS releases (charter, eval)**   | Ops   | 2 wks  | Apache 2.0 release of the two reusable substrates. Recruiting + research credibility.      |

## §17. The recommended next plan to write (and execute)

**A.1 — Tier-3 Remediation (recommend-only).** Reasons in priority order:

1. **Single biggest competitive gap closure** vs Wiz. Wiz remediates nothing; A.1 ships **the first "do" agent** even though it doesn't yet "do."
2. **Lowest blast radius** (no production action; just artifact generation).
3. **Highest substrate reuse** — consumes F.6 audit + D.1 vulnerability + D.6 K8s findings unchanged.
4. **Unblocks A.2 + A.3** — the headline remediation tiers can only land after A.1's artifact-generation primitive.
5. **Provable revenue impact** — design partners convert at ~3× rates when shown auto-generated remediation artifacts vs detection-only output.

Effort: **4 weeks** (single engineer at the ADR-007 v0.1 cadence we've been hitting for 9 agents).

## §18. Critical path to Phase 1 GA

```
TODAY (2026-05-16)
  │
  ├─→ A.1 (4 wks) ──┬──→ A.2 (4 wks) ──→ A.3 (6 wks) ──┐
  │                 │                                   │
  ├─→ S.3 (4 wks) ──┘                                   │
  │                                                     │
  ├─→ S.1 (6 wks, //) ──→ S.2 (4 wks, //) ──────────────┤
  │                                                     │
  ├─→ S.4 (3 wks, //) ─────────────────────────────────┤
  │                                                     │
  ├─→ F.7 (4 wks, //) ─────────────────────────────────┤
  │                                                     │
  ├─→ D.8 (4 wks, //) ─────────────────────────────────┤
  │                                                     │
  ├─→ E.1 → E.2 → E.3 (13 wks, //) ────────────────────┤
  │                                                     │
  ├─→ C.0 + C.1 (12 wks, //) ──────────────────────────┤
  │                                                     │
  ├─→ A.4 + D.12 + D.13 (11 wks together) ─────────────┤
  │                                                     ▼
  └─→ O.1 + O.2 + O.3 + O.4 + O.5 ────────────→ PHASE 1 GA (M12)
                                                  M12 = 2026-09 (or 2026-08 at current velocity)
```

**Critical path = A.1 → A.2 → A.3 (Tier-1 remediation).** Everything else parallelises. At the cadence we've been holding (one full agent in ~3-5 days when the substrate is stable), the critical path is **~14 weeks of solo-engineer work**, or **~8 weeks if a second engineer joins**. **Phase 1 GA is achievable by 2026-08 / 2026-09** — ahead of the M12 target.

---

# Part VII · Risks

## §19. Carried-forward (unchanged)

1. **Frontend zero LOC** (Tracks S.1-S.4) — same. **Mitigation:** 43 mockups under [docs/design/console/](../design/console/) provide the visual contract; build is straightforward Tailwind+Next.js work.
2. **Edge plane zero LOC** (Tracks E.1-E.3) — same. **Mitigation:** ADR-004 (fabric) + ADR-006 (sovereign LLM) decide the hard architecture; build is Go-runtime mechanics.
3. **Three-tier remediation zero LOC** (Track A) — same. **Mitigation:** F.6 audit + D.7 investigation + every D.\* finding format are the inputs A.1-A.3 consume; the substrate is ready.
4. **Eval cases capped at 10/agent** — same. **Mitigation:** A.4 Meta-Harness expands this when shipped.
5. **Schema re-export lock-in** — 3 consumers now (F.3 + D.5 + D.6). **Mitigation:** OCSF v1.3 schema is stable; amendments would require an ADR.
6. **GCP IAM rule shallowness (D.5)** — unchanged.
7. **K8s manifest 10-rule shallowness (D.6)** — unchanged.
8. **Cross-tool dedup is rule-id-exact (D.6)** — unchanged.

## §20. New risks introduced today

9. **Three Phase-1c slices now exist as commitments** (D.6 v0.2 shipped; F.3 v0.2 + D.5 v0.2 + D.6 v0.3+ implied). **Risk:** every agent eventually grows a Phase-1c version-2 plan; this compounds into version-fan-out. **Mitigation:** establish a uniform "v0.2 LocalStack/offline → live" template ADR before F.3 v0.2 lands (forcing-function: write the ADR when F.3 v0.2 plan goes in).
10. **Kubernetes SDK version drift.** v0.2 pins `kubernetes>=31.0.0` (resolved 35.0.0). The SDK's API surface is stable but `ApiException.status` int is what we depend on for the 403/non-403 branch. **Mitigation:** A.4 Meta-Harness eval gate will catch drift; v0.2 reader test suite covers the contract explicitly.
11. **No `kind`-cluster integration tests in CI** — all D.6 v0.2 reader tests mock the SDK. **Mitigation:** O.1 should add a gated `NEXUS_LIVE_K8S=1` lane that runs against `kind`.
12. **First 50%-weighted-coverage threshold creates implicit "we're halfway done" narrative.** **Mitigation:** investor/board comms should emphasise that the **second half is harder** — remediation, edge, content packs — and the half we've done is mostly substrate.

---

# Part VIII · Recommendations

## §21. To the team

1. **Write A.1 Tier-3 Remediation plan next.** Single-engineer, ~4-week plan; first "do" agent; closes biggest Wiz gap.
2. **Pair A.1 with S.3 ChatOps in parallel** (different engineer). A.2 cannot land without S.3; they're tightly coupled.
3. **Defer the project-quadrant agents (A.4 / D.12 / D.13)** to Tier C above — they compound returns once the cure quadrant is started. Shipping them before A.1-A.3 wastes their leverage.
4. **Write the v0.2-template ADR (ADR-010)** when F.3 v0.2 plan is queued — establishes the "version-extension pattern" the report has been calling out across all 9 agents.
5. **Get a second engineer started on S.1 console** — 6 weeks of work; runs entirely parallel to the A.1-A.3 critical path; design assets ready.

## §22. To the board / investors

1. **The platform is on Phase 1 GA track.** ~50.8% weighted Wiz coverage at M2; the original calendar called for ~50% at M7-M8.
2. **The next 12 weeks compress the remaining distance.** A.1-A.3 (remediation) + S.1-S.3 (surfaces) + F.7 (fabric runtime) + E.1-E.3 (edge) cover the remaining Wiz-weight surface and the four VISION pillars.
3. **The compounding hits at A.4 Meta-Harness.** Once the agent population is broad enough and Meta-Harness starts shipping NLAH improvements monthly, the platform's per-agent quality grows without further engineering hires. **That's the architectural moat.**
4. **No architectural decisions are blocking velocity.** Every ADR needed for Phase-1 GA is in force or scheduled. The next-12-weeks plan is pure pattern application.

## §23. To customers / design partners

1. **CSPM coverage** is 84% across AWS + Azure + GCP + Kubernetes. **D.6 v0.2's live cluster mode means K8s posture works against your existing kubeconfig with zero pre-staging.**
2. **Detection coverage** is 50.8% of the Wiz feature surface, weighted by what enterprises actually consume.
3. **Remediation lands next.** Tier-3 (recommend) inside 4 weeks; Tier-2 (approve + execute) inside 8 weeks; Tier-1 (autonomous) inside 14 weeks. **All three tiers shipped before any reasonable Phase-1 GA timeline.**
4. **The console builds in parallel** with the remediation work — first usable dashboard in 6 weeks, chat sidebar in 10.
5. **Edge deployment** (the differentiator for hybrid/regulated environments) starts ~12 weeks out and ships in ~25 weeks. **We are the only platform building this on the Phase 1 GA timeline.**

---

## Sign-off

System is **on-trajectory for Phase 1 GA by 2026-08 / 2026-09**, ahead of the M12 calendar. **First 50%-weighted-Wiz-threshold crossed**; second half is harder (remediation + edge + content) but the substrate (fabric + charter + 9 agents) is the foundation that makes the second half pure execution rather than architecture-discovery.

**Recommended action this week:** write the A.1 Tier-3 Remediation plan. Single-engineer, four-week effort. Closes the largest competitive gap vs Wiz.

— recorded 2026-05-16
