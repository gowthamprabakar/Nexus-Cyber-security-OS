# Remaining-agents sketch — 7 one-page sketches + build-out sequence proposal (2026-05-20)

**What this is.** Light one-page sketches for the 7 remaining unbuilt agents in the platform spec per the operator's 2026-05-20 directive. **Not full plans.** Not code. Not tests. Not CI. One document; ~one page per agent; plus a sequence proposal at the end. Each sketch follows a strict 8-item template (mission, reads, writes, closest existing pattern, net-new substrate, live-proof shape, dependencies, SET LOCAL touch-point).

**Why now.** The F.5 LTREE substrate-fix plan closed 2026-05-20 (PR #51 pending merge). The KG-loop closure plan closed 2026-05-18. The two operator-flagged carry-forwards (SET LOCAL `$1`, cross-run AFFECTS dedup) are parked with named owners; the §13.3 retro-point is newly-unblocked but not retro-pointed. Next phase per operator directive: agent build-out, NOT more substrate work. This sketch round is the planning artifact for that phase.

**Discipline.** Doc-only LOW-RISK PR per ADR-011. Pause for full review of all 7 sketches + the proposed sequence before any full plan is written.

---

## Important note up-front: agent-ID namespace overlap

The operator's directive names the 7 unbuilt agents as: **Data Security (D.5), Compliance (D.6), Threat Intel (D.8), Curiosity (D.12), Synthesis (D.13), Meta-Harness (A.4), Supervisor (#0)**.

The existing codebase has packages with overlapping numeric IDs:

| Existing package                       | Self-claimed ID (from README) |
| -------------------------------------- | ----------------------------- |
| `packages/agents/multi-cloud-posture/` | "D.5; third Phase-1b agent"   |
| `packages/agents/k8s-posture/`         | "D.6; fourth Phase-1b agent"  |

**This is a real ID-namespace overlap** between the existing packages and the operator's enumeration. The sketches below follow the **operator's IDs** verbatim (D.5 = Data Security, D.6 = Compliance) and **flag the overlap explicitly** here so the operator can resolve the canonical ID mapping before any full plan is written.

Two possible resolutions for the operator to consider:

- **(a)** Renumber the operator-listed agents (e.g., Data Security = D.5a or D.14; Compliance = D.6a or D.15) — keeps the existing package READMEs unchanged.
- **(b)** Renumber the existing packages (e.g., multi-cloud-posture → D.7' or D.5b; k8s-posture → D.6b) — keeps the operator's nomenclature.
- **(c)** The "remaining 7" interpretation is canonical: there's a separate authoritative spec the existing READMEs got wrong, and the README D.5/D.6 references need updating to the operator's mapping.

**No action taken on this overlap in this document.** Sketches use operator IDs; resolution before the first full plan is requested.

---

## §1. Data Security (D.5) — DSPM

**Mission**: Discover and classify sensitive data assets across cloud storage (S3, Azure Blob, GCP Storage); detect data-exposure risk (public buckets, oversharing, unencrypted sensitive data, sensitive data in untrusted locations).

**What it reads**:

- AWS S3 / Azure Blob / GCP Storage object inventories (via boto3 / azure-sdk / gcloud — possibly some reuse of cloud-posture's tools).
- Existing F.3 Cloud Posture findings (cross-correlation on bucket-level permissions).
- Optional: existing classifications cached as entities in the Postgres `SemanticStore` (for incremental scans).

**What it writes**:

- OCSF v1.3 findings wrapped in `NexusEnvelope` (correlation_id, tenant_id, agent_id, model_pin, charter_invocation_id) — matches the F.3 reference NLAH shape.
- `findings.json` + `summary.md` to the charter-managed workspace per ADR-007.
- Asset entities into the Postgres `SemanticStore` via the `kg_writer.py` pattern (entity_type=`"data_asset"`; properties carry the sensitivity classification + exposure flags).
- F.7 fabric events on the `findings.>` bus per ADR-004.

**Closest existing pattern**: [`packages/agents/cloud-posture/`](../../../packages/agents/cloud-posture/) — same shape (cloud SDK scan + OCSF emission + KG-writer + summarizer). Inherits the F.3 reference NLAH template per ADR-007 v1.2.

**Net-new substrate work**: minimal. The agent itself replicates the F.3 pattern. The only candidate new substrate is a **sensitive-data classifier** primitive — could be a regex-based PII matcher in `packages/agents/data-security/src/.../classifiers/` (agent-local, not substrate) or, if shared across agents, a `charter.data_classification` module (substrate-level). Recommendation: **agent-local for v0.1; promote to charter substrate only if D.6 Compliance or D.12 Curiosity end up needing the same classifier**. HONEST: probably no charter-level new substrate needed.

**Live-proof shape**:

- Replicates F.3's eval-case discipline (10 YAML cases). Fixture cloud-storage state (public bucket containing PII, oversharing IAM, etc.) → expected OCSF findings with correct severity + classification labels.
- Live-lane variant (post-LTREE-fix): `NEXUS_LIVE_POSTGRES=1` + `pgvector/pgvector:pg16` CI service + agent-side dedup + D.7 walker → real entities materialize. Same shape as the KG-loop keystone proof.

**Dependencies on other agents in the 7**: **NONE.** Reads from existing F.3 (built) only. Does not depend on Compliance / Threat Intel / Curiosity / Synthesis / Meta-Harness.

**SET LOCAL bug touch-point**: The agent writes entities into `SemanticStore` (post-LTREE-fix path). `SemanticStore.upsert_entity` itself does NOT issue `SET LOCAL` directly — that's the `MemoryService.session(tenant_id=...)` wrapper at a higher layer. **Decision**: v0.1 builds with `semantic_store=None` opt-in (same default as F.3) OR with a single-tenant in-memory aiosqlite `SemanticStore` (same as KG-loop Task 5's pattern). **NOT BLOCKED** for single-tenant agent development. Multi-tenant production enablement waits for the SET LOCAL fix (§11.1 of the F.5 LTREE plan-closer).

---

## §2. Compliance (D.6)

**Mission**: Map findings emitted by other detect agents to compliance-framework controls (CIS AWS Foundations, SOC2, PCI-DSS, HIPAA, NIST 800-53); emit framework-level compliance findings + periodic posture reports.

**What it reads**:

- All detect-agent findings across the F.6 audit chain (D.1 Vulnerability, D.2 Identity, D.3 Runtime Threat, D.4 Network Threat, F.3 Cloud Posture, and after-build D.5 Data Security).
- Compliance framework definitions (bundled YAML / TOML in `packages/agents/compliance/control_libraries/`).
- F.7 fabric events on `findings.>` to react in near-real-time when new findings land.

**What it writes**:

- OCSF v1.3 "Compliance Finding" with framework + control mapping (e.g., `compliance.control = "CIS-AWS-1.1"`).
- Periodic posture-summary reports to the charter workspace.
- F.7 fabric events on `findings.>` for newly-failed controls.

**Closest existing pattern**: [`packages/agents/k8s-posture/`](../../../packages/agents/k8s-posture/) — also rule-based detection, but D.6 is **cross-source** (consumes other agents' findings) whereas k8s-posture is single-source (Kubernetes API). The aggregation shape may also borrow from [`packages/agents/investigation/`](../../../packages/agents/investigation/) (D.7) which already does cross-source reads via F.6 audit query.

**Net-new substrate work**: HONEST — **none charter-level required.** The compliance-framework definitions library is config (YAML), not substrate. Aggregation over F.6 audit-chain reads uses the existing `AuditLog.query` 5-axis API (per the A.1 safety record's reference). The OCSF "Compliance Finding" class is already used by F.3.

**Live-proof shape**:

- Eval-case discipline: fixture set of detect-agent findings + fixture framework controls → expected compliance findings.
- A live-lane test that reads from real F.6 audit chain (post-LTREE-fix substrate) and produces a posture report — same pattern as F.5's `test_alembic_upgrade_head` proof but applied to the compliance-aggregation path.

**Dependencies on other agents in the 7**: depends on **D.5 Data Security** being built IF Compliance covers data-security framework controls (which CIS, SOC2, PCI all do). Optionally depends on **D.8 Threat Intel** if framework controls reference TTP coverage. **NO dep** on Curiosity / Synthesis / Meta-Harness.

**SET LOCAL bug touch-point**: cross-agent finding aggregation is **inherently multi-tenant-sensitive**. If Compliance queries F.6 audit chain by tenant (it must — controls are per-customer), it will issue tenant-scoped queries. The F.6 audit chain itself is file-backed today, so the SET LOCAL hit depends on whether Compliance also touches `SemanticStore` for finding entities. **Decision**: v0.1 single-tenant build NOT BLOCKED; multi-tenant production-readiness blocks on SET LOCAL fix (§11.1).

---

## §3. Threat Intel (D.8)

**Mission**: Consume external threat-intelligence feeds (CVE / NVD, MISP, MITRE ATT&CK / STIX, VirusTotal IOCs) and correlate IOCs/TTPs with platform findings to elevate risk + add context.

**What it reads**:

- External feeds (HTTP APIs, STIX/TAXII servers, JSON/CSV imports).
- Existing detect-agent findings (D.1 Vulnerability for CVE correlation, D.4 Network Threat for IOC correlation, D.3 Runtime Threat for TTP correlation).
- Cached threat-intel state — likely as entities in `SemanticStore` (entity_type=`"ioc"`, `"ttp"`, `"cve"`).

**What it writes**:

- Augmented findings (existing finding + threat-intel context as a sidecar field on the OCSF envelope), OR new "Threat Indicator" OCSF findings that reference the original finding via `correlation_id`.
- IOC / CVE entities into `SemanticStore` for cross-agent reuse.
- F.7 fabric events for high-severity correlations.

**Closest existing pattern**: [`packages/agents/network-threat/`](../../../packages/agents/network-threat/) — also consumes external feeds (Suricata/Zeek IDS) and emits OCSF findings; same `asyncio.TaskGroup` + async tool wrappers per ADR-005. The CVE-correlation specifics may also borrow from [`packages/agents/vulnerability/`](../../../packages/agents/vulnerability/) (D.1).

**Net-new substrate work**: HONEST — **none charter-level**. The external-feed client wrappers (`tools/cve_feed.py`, `tools/mitre_stix.py`, etc.) are agent-local tools, same shape as cloud-posture's `tools/prowler.py` and `tools/aws_iam.py`. No new charter API needed.

**Live-proof shape**:

- Mocked-feed eval-cases: fixture IOC dump + fixture findings → expected correlation events.
- Live-lane variant: hit a real public CVE feed (NVD JSON dump is freely accessible) in CI as a snapshot-test — same risk-control discipline as F.3's Prowler integration tests.

**Dependencies on other agents in the 7**: **NONE.** Correlates with existing D-track findings (already built). No dep on the other 6 new agents.

**SET LOCAL bug touch-point**: writes IOC/TTP entities to `SemanticStore` (tenant-scoped). Same shape as D.5 Data Security. v0.1 single-tenant NOT BLOCKED.

---

## §4. Curiosity (D.12)

**Mission**: Proactive exploration agent — generates hypotheses about what the platform may not have checked yet ("hypothesis: this customer has unmanaged IAM roles in a non-default region we haven't scanned"; "hypothesis: this asset class has higher-than-baseline risk based on recent threat-intel trends"). Drives "what might we be missing" investigations rather than reacting to existing findings.

**What it reads**:

- Aggregate state across detect-agent findings (D.1-D.8); coverage gaps (e.g. regions / asset-types / time-windows with low finding counts despite high inventory).
- F.6 audit chain for historical patterns of detection.
- D.8 Threat Intel for "rising risks" context.
- F.5 Episodic memory (`EpisodicStore`) for agent-run history.

**What it writes**:

- "Hypothesis" claims — a new entity type `entity_type="hypothesis"` in `SemanticStore`, OR (alternative) a new OCSF class for exploratory claims.
- Probe directives that D.7 Investigation, D.5 Data Security, or D.8 Threat Intel can consume as scanning prompts.
- F.7 fabric events on a hypothesis-track subject (subject: `claims.>` or similar — may need a new ADR-004 stream).

**Closest existing pattern**: [`packages/agents/investigation/`](../../../packages/agents/investigation/) (D.7) — also multi-step + LLM-driven + reads broad state via `memory_neighbors_walk`. **Curiosity is generative; Investigation is responsive** — same substrate, opposite direction.

**Net-new substrate work**: **POSSIBLY YES**. Two flags to call out honestly:

- A new entity_type value (`"hypothesis"`) in `SemanticStore` is just data, not substrate.
- A potentially new F.7 fabric subject (`claims.>` or similar) per ADR-004 — if Curiosity-hypotheses need their own bus separate from `findings.>`. **This is a real substrate decision** that the full plan must call out explicitly; could go either way (re-use `findings.>` with a class_uid distinction, vs. new subject).
- Optionally, a new OCSF class for exploratory claims — not substrate, but a new schema-layer convention.

**Live-proof shape**:

- Eval-case: fixture coverage-gap (e.g. zero findings in `eu-west-3` despite asset inventory > 10) + fixture context → expected hypothesis emission ("scan `eu-west-3`").
- Live-lane: against a real `SemanticStore` post-LTREE-fix, validate that hypothesis entities materialize with the correct cross-reference to the finding-gap that triggered them.

**Dependencies on other agents in the 7**: depends on **D.5 Data Security, D.6 Compliance, D.8 Threat Intel, D.13 Synthesis** all having findings/claims to reason over. Also depends on D.13's claim format if Synthesis is the downstream consumer of Curiosity hypotheses. **This is the most-dependent of the 6 D-track agents** — must come late in the sequence.

**SET LOCAL bug touch-point**: reads broad `SemanticStore` state across multiple tenants potentially (cross-tenant analysis would be a privacy violation, so likely single-tenant operation per customer). **Decision**: v0.1 single-tenant NOT BLOCKED. Multi-tenant production-readiness blocks on §11.1. Plus: if Curiosity introduces a new F.7 subject, the F.7 substrate may need a new stream — flag this in the full plan's eligibility test.

---

## §5. Synthesis (D.13)

**Mission**: Customer-facing narration. Synthesizes findings + investigations + compliance reports into human-readable summaries / narratives / "what happened, what we did, what's at risk" explanations. **The LLM-narration agent**.

**What it reads**:

- Detect-agent findings (all D-track).
- D.7 Investigation conclusions (via the `memory_neighbors_walk` substrate primitive).
- D.6 Compliance reports (for compliance-narrative output).
- D.12 Curiosity hypotheses, if extant — Synthesis weaves them in as "areas we're proactively watching".

**What it writes**:

- Markdown / HTML reports to the charter workspace.
- F.7 fabric events on a synthesis-output subject (could reuse `findings.>` with a `class_uid` distinction, or could be a new subject — same ADR-004 question as Curiosity's claims track).
- Optionally, "report" entities in `SemanticStore` for long-term retrieval.

**Closest existing pattern**: [`packages/agents/cloud-posture/src/cloud_posture/summarizer.py`](../../../packages/agents/cloud-posture/src/cloud_posture/summarizer.py) — same idea but deterministic (no LLM, per F.3's NLAH-out-of-scope clause: _"customer-facing narration belongs to the Synthesis Agent"_). Synthesis is cross-source + LLM-driven; summarizer.py is single-source + deterministic. **Synthesis is the agent that consumes the role F.3's summarizer leaves open.**

**Net-new substrate work**: HONEST — **none charter-level**. Uses `charter.llm.LLMProvider` (existing per ADR-006); writes markdown via `ctx.write_output` (existing); emits fabric events via the F.7 client (existing). LLM-prompt-template work is the bulk of the engineering, not substrate.

**Live-proof shape**:

- Eval-case: fixture findings + fixture investigation + fixture compliance report → expected synthesis report (structure-equality on sections; semantic-equivalence asserted via separate LLM-judge, NOT byte-equality — narratives vary stylistically).
- The fabric-emission path can be live-proven via the F.7 v0.2 live-lane pattern (subject + envelope shape).

**Dependencies on other agents in the 7**: depends on **D.7 Investigation** (existing) for conclusions to synthesize; depends on **D.6 Compliance** for compliance-report shape (if Synthesis covers compliance reports). **Optionally** depends on **D.12 Curiosity** if Curiosity hypotheses are part of Synthesis output (could be deferred to v0.2 — Synthesis v0.1 can omit hypothesis narration). **NO dep** on D.5 Data Security or D.8 Threat Intel directly (those land as findings; Synthesis consumes findings).

**SET LOCAL bug touch-point**: reads `SemanticStore` by tenant_id for investigation entities + finding entities. Same shape as D.5 / D.6 / D.8. v0.1 single-tenant NOT BLOCKED.

---

## §6. Meta-Harness (A.4)

**Mission**: Self-evolution. Runs the eval framework over all agents periodically, scores them, identifies regressions / improvement opportunities, drives A/B comparisons of NLAH-prompt variants, and (in later versions) proposes / applies NLAH changes back to the agent NLAH directories. **The agent that makes the agents better.**

**What it reads**:

- All agents' eval-case directories (`packages/agents/*/eval/cases/*.yaml`).
- All agents' NLAH directories (`packages/agents/*/src/*/nlah/`).
- F.6 audit chains for historical eval performance.
- The eval-framework state (per ADR-008).

**What it writes**:

- Eval scorecards (per-agent, per-case, with delta tracking over time).
- NLAH-change proposals — as PR drafts? As markdown reports? As "playbook" entities in `SemanticStore`? **A real design question for the full plan.**
- A/B comparison results.
- F.7 fabric events for "meta-harness completed pass" / "regression detected" / etc.

**Closest existing pattern**: [`packages/eval-framework/`](../../../packages/eval-framework/) — the substrate Meta-Harness sits ON. Not an agent shape itself. Closest _agent_ pattern is [`packages/agents/investigation/`](../../../packages/agents/investigation/) (D.7) — multi-step, LLM-driven, reads broad state. **Meta-Harness's specific shape is unique in the platform** because it's the only agent that operates on agents themselves.

**Net-new substrate work**: **YES — MORE THAN THE OTHERS**. Honest list:

- **Agent-introspection primitives**: reading NLAH directories programmatically, parsing the NLAH manifest format (if any), scoring rubric for cross-agent comparison.
- **Eval-framework extensions for batch evaluation across agents**: today, eval-framework runs ONE agent's eval suite (per ADR-008); Meta-Harness needs the cross-agent batch shape.
- **A/B comparison runner**: this is fundamentally new — current eval-framework is single-pass; A/B is dual-pass with deterministic comparison.
- **Optional**: NLAH-change-proposal application machinery (PR-open via API?), which raises significant ADR-011 + safety questions.

**This is the only one of the 6 D/A-track agents that genuinely requires non-trivial substrate work.** The full plan needs to explicitly call out the substrate-additions surface and may need its own substrate-extension ADR.

**Live-proof shape**:

- Eval-case: fixture multi-agent state (2-3 fake agent eval suites, deterministic outputs) + fixture NLAH variants → expected A/B comparison output + expected scorecard delta.
- Live-lane: A.4 runs against the real `packages/eval-framework/` + the real existing 10 agents' eval suites + the new 6 D-track agents' eval suites → produces a single coherent scorecard.

**Dependencies on other agents in the 7**: depends on **ALL 6 OTHER NEW AGENTS** existing (it evaluates them all, plus the existing 10). Specifically depends on D.5, D.6, D.8, D.12, D.13 being in the codebase with eval-case suites. **Must come second-to-last in the sequence** (only Supervisor comes after).

**SET LOCAL bug touch-point**: probably **less SET LOCAL exposure than the D-track agents**. Meta-Harness operates primarily on file-based eval-framework state (YAML cases, NLAH directories) + F.6 audit chain (file-backed) — neither hits `SemanticStore`'s tenant-RLS path. Optional: if scorecards are persisted to `SemanticStore` for long-term tracking, that becomes tenant-scoped — but per-customer eval is unusual; eval is typically platform-level. **NOT BLOCKED.** Possibly the agent least affected by SET LOCAL.

---

## §7. Supervisor (#0) — LAST

**Mission**: Orchestrate the 17 worker agents. Receive high-level requests ("scan this customer's AWS account end-to-end"), decompose into per-agent ExecutionContracts, dispatch via F.7 fabric, monitor progress, aggregate results, enforce escalation rules per the charter contract format.

**What it reads**:

- All agents' capabilities (presumably via an agent-registry — a new substrate concept).
- F.7 fabric events on `events.>` for in-flight work tracking.
- F.4 tenant context for authorization (which agents this customer has enabled).
- F.6 audit chain for orchestration provenance.
- Agent eval scorecards from A.4 Meta-Harness for routing decisions ("which agent to use" if multiple agents can handle a task).

**What it writes**:

- ExecutionContracts to subordinate agents (per the existing charter `ExecutionContract` schema).
- F.7 fabric events for "work dispatched" / "work aggregated" / "escalation triggered".
- F.6 audit chain entries for every orchestration decision.
- High-level result aggregation to the charter workspace for the requesting party.

**Closest existing pattern**: **NONE EXACTLY.** Closest is [`packages/agents/investigation/`](../../../packages/agents/investigation/) (D.7) which is multi-step and delegates to TOOLS via `ctx.call_tool`. Supervisor delegates to AGENTS via ExecutionContract — a different shape. Supervisor's orchestration role is unique.

**Net-new substrate work**: **YES — THE BIGGEST OF THE 7**. Honest list:

- **Agent registry**: discovery mechanism for "which agents exist, what they accept, what they emit." Likely a charter-level primitive (`charter.agent_registry`).
- **Contract dispatch machinery**: a substrate primitive for sending an `ExecutionContract` to a subordinate agent (today, contracts are loaded from YAML by individual agents; Supervisor needs to _issue_ them).
- **Fabric-event routing for orchestration**: the F.7 fabric currently carries `events.>` / `findings.>` / `commands.>` / `approvals.>` / `audit.>` per ADR-004. Supervisor may need a new subject for orchestration meta-events (`orchestration.>`?) — a substrate-level F.7 stream addition.
- **Escalation handler**: charter contracts already have an `escalation_rules` field, but Supervisor is the agent that ACTS on them. The "act on escalation_rules" machinery is new substrate-level work.

**This is the substrate-heaviest agent of the 7. Its full plan will read more like a substrate plan than an agent plan.** Probably needs its own ADR.

**Live-proof shape**:

- End-to-end demo: a single high-level request ("scan customer X's AWS environment") → Supervisor decomposes → dispatches ExecutionContracts to F.3 Cloud Posture + D.1 Vulnerability + D.5 Data Security in parallel → aggregates results → returns a coherent summary via D.13 Synthesis.
- Live-lane: against real F.7 fabric (live NATS), real F.5 substrate, real subordinate agents. **Higher integration surface than any prior agent's live proof.**

**Dependencies on other agents in the 7**: depends on **ALL 6 PRIOR NEW AGENTS** plus the existing 10. Sequenced LAST by operator directive (and by structural necessity).

**SET LOCAL bug touch-point**: orchestrates per-tenant. Supervisor sets the tenant context for every subordinate call — DEFINITELY uses `MemoryService.session(tenant_id=...)` or its equivalent. **Will hit SET LOCAL when multi-tenant.** Single-tenant v0.1 NOT BLOCKED.

**By Supervisor's build time, the SET LOCAL fix may have already landed in its own plan** (sequenced after this 7-agent push per operator directive). If so, Supervisor builds against a fixed substrate; if not, v0.1 single-tenant + multi-tenant deferred.

---

## §8. Proposed build-out sequence

Sequence proposal, justified by **item-7 dependencies** and **item-5 substrate touch-points**:

```
1. D.5 Data Security         ─┐
2. D.8 Threat Intel          ─┼─ orthogonal pair: no dep on other 6 new agents; replicate F.3 / D.4 patterns
                              │   D.5 first (most orthogonal); D.8 second (also orthogonal)
                              │
3. D.6 Compliance            ── depends on existing D-track + new D.5; no dep on Curiosity / Synthesis / Meta
                              │
4. D.13 Synthesis            ── depends on D.7 (existing); cleanly buildable here; LLM-template work is the
                              │   bulk; no substrate; provides customer-facing output pipeline before
                              │   the speculative Curiosity layer
                              │
5. D.12 Curiosity            ── depends on D.5 + D.6 + D.8 + D.13 having findings/claims to reason over;
                              │   possibly needs a new F.7 subject ("claims.>") — substrate flag; build after
                              │   the four feed-in agents
                              │
6. A.4 Meta-Harness          ── depends on ALL 6 D-track agents (existing + new) being in the codebase with
                              │   eval-case suites; substrate-heavy (agent introspection, A/B runner, eval-
                              │   framework extensions); must come after the agents it evaluates
                              │
7. Supervisor (#0)           ── LAST per operator directive; depends on ALL prior agents (existing + 6 new)
                                 + A.4 Meta-Harness for routing decisions; substrate-HEAVIEST (agent
                                 registry, contract dispatch, escalation handler, possibly new F.7 subject)
```

### Justification per agent

| Step | Agent             | Why here                                                                                                                                                                                                                                                                                     |
| ---- | ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | D.5 Data Security | Orthogonal (no dep on the other 6); closest existing pattern is F.3 Cloud Posture (extensively built + reference NLAH); zero substrate work; lowest-risk to start with. Building this first proves the operator's "easiest first" heuristic + provides finding inputs to D.6 and D.12 later. |
| 2    | D.8 Threat Intel  | Also orthogonal (correlates with existing D-track only). Closest existing pattern is D.4 Network Threat. Zero substrate work. Can land in parallel with D.5 if execution capacity allows, but the operator's "do not bundle" discipline suggests sequential.                                 |
| 3    | D.6 Compliance    | Depends on existing D-track findings + the now-built D.5; ready to build after step 1. Closest existing pattern is k8s-posture (rule-based detection). Zero substrate work.                                                                                                                  |
| 4    | D.13 Synthesis    | Depends on D.7 (existing); cleanly buildable now. Provides the customer-facing-narration role that F.3's NLAH-out-of-scope clause has been pointing at since the reference NLAH was written. Zero substrate work (uses LLMProvider).                                                         |
| 5    | D.12 Curiosity    | Depends on D.5 / D.6 / D.8 / D.13 all having findings/claims to reason over. **Flag**: may need a new F.7 fabric subject — a substrate decision worth surfacing in its full plan.                                                                                                            |
| 6    | A.4 Meta-Harness  | Must come after all 6 D-track agents exist (it evaluates them). **Substrate-heavy** — agent introspection, batch evaluation, A/B comparison; non-trivial.                                                                                                                                    |
| 7    | Supervisor (#0)   | LAST per operator directive AND by structural necessity (depends on all 17 prior agents + Meta-Harness). **Substrate-HEAVIEST** — agent registry, contract dispatch, escalation handler. Probably needs its own ADR.                                                                         |

### Alternative orderings considered + rejected

- **D.13 Synthesis before D.6 Compliance**: Synthesis depends on D.7 only; Compliance depends on D.5 plus existing. Either order works structurally. **Rejected** because Compliance produces report-shaped outputs that Synthesis can then narrate — building Compliance before Synthesis gives Synthesis more material to work with at first-build time.
- **D.12 Curiosity before D.13 Synthesis**: Curiosity is more dependent (D.5 + D.6 + D.8 + D.13) and substrate-flagging (possible new F.7 subject); Synthesis is more concrete. **Build the concrete one first** so we have a customer-facing pipeline before adding the speculative agent.
- **A.4 Meta-Harness before D.12 Curiosity**: Meta-Harness must come after the agents it evaluates; building it before Curiosity means Curiosity isn't evaluable by the harness. **Rejected** — Meta-Harness evaluates SIX D-track agents (existing + new); all six must exist first.

### Sequence-wide invariants (carry forward into every full plan)

1. **Hard scope boundary per agent**: each agent's full plan operates under the same "ONE agent, the minimal surface required" discipline as the F.5 LTREE plan. No bundling across agents.
2. **SET LOCAL fix is NOT a blocker for v0.1 single-tenant builds.** Every agent v0.1 ships single-tenant + opt-in `semantic_store` arg pattern (matches F.3's `neo4j_driver`→`semantic_store` rename pattern from KG-loop Task 3). Multi-tenant production-readiness blocks on §11.1 (tenant-RLS substrate fix) — owned by a separate future plan, NOT auto-started.
3. **Cross-run AFFECTS-edge dedup (KG-loop §13.1) is NOT a blocker.** Same parking as the F.5 LTREE plan close.
4. **KG-loop §13.3 retro-point is NOT in scope for any of these 7 agents.** Separate future plan. Newly-unblocked by the LTREE fix but sequencing-blocks on §11.1.
5. **Permanent CI workflow per agent IF the agent has a live-lane invariant** (D.5 / D.6 / D.13 likely yes; D.8 / D.12 / A.4 likely no; Supervisor definitely yes). Follow the `charter-f5-live.yml` + `kg-loop-live.yml` pattern.
6. **Every agent ships an ADR-007-compliant NLAH directory** matching the F.3 reference template (v1.2 post-NLAH-loader-hoist).
7. **Every agent's full plan includes the 8-section ADR-010 conformance test honestly classified.**

---

## §9. What's NOT in this document

- **No full plan for any agent.** This is a sketch round.
- **No code, no tests, no CI.**
- **No SET LOCAL fix.** Parked per operator directive 2026-05-20.
- **No cross-run AFFECTS-edge dedup work.** Parked per KG-loop closure §13.1.
- **No KG-loop §13.3 retro-point.** Parked per F.5 LTREE plan-closer §11.3.
- **No resolution of the agent-ID-namespace overlap.** Flagged at the top of this doc; deferred to operator.
- **No commitment to any specific Synthesis-Curiosity integration shape, F.7-subject extension for claims/orchestration, or Meta-Harness scorecard format.** All deferred to the per-agent full plans.

---

## §10. Cross-references

- F.5 LTREE substrate-fix plan-closer (recently closed): [`f5-ltree-substrate-fix-verification-2026-05-19.md`](../../_meta/f5-ltree-substrate-fix-verification-2026-05-19.md) — §11 carries the three current tracked debts.
- KG-loop closure verification record: [`kg-loop-closure-verification-2026-05-18.md`](../../_meta/kg-loop-closure-verification-2026-05-18.md) — §13 carries the original three carry-forwards (one now resolved by the F.5 LTREE plan).
- System readiness report: [`system-readiness-2026-05-19.md`](../../_meta/system-readiness-2026-05-19.md) — the platform state from which this sketch round picks up.
- ADR-007 Cloud Posture as reference NLAH: [`decisions/ADR-007-cloud-posture-as-reference-agent.md`](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) — every agent in this sketch round inherits the F.3 template.
- ADR-004 Fabric: [`decisions/ADR-004-fabric-nats-jetstream-5-buses.md`](../../_meta/decisions/ADR-004-fabric-nats-jetstream-5-buses.md) — D.12 Curiosity and Supervisor may want new subjects under this.
- ADR-008 Eval Framework: [`decisions/ADR-008-eval-framework-architecture.md`](../../_meta/decisions/ADR-008-eval-framework-architecture.md) — A.4 Meta-Harness extends this.
- ADR-011 PR-flow discipline: [`decisions/ADR-011-pr-flow-discipline.md`](../../_meta/decisions/ADR-011-pr-flow-discipline.md) — every agent's full plan follows this.
- F.3 reference agent (existing — closest pattern for D.5): [`packages/agents/cloud-posture/`](../../../packages/agents/cloud-posture/)
- D.4 Network Threat (existing — closest pattern for D.8): [`packages/agents/network-threat/`](../../../packages/agents/network-threat/)
- D.6/k8s-posture (existing — closest pattern for D.6 Compliance, **ID overlap flagged**): [`packages/agents/k8s-posture/`](../../../packages/agents/k8s-posture/)
- D.7 Investigation (existing — closest pattern for D.12, D.13, Supervisor): [`packages/agents/investigation/`](../../../packages/agents/investigation/)
- Eval Framework (substrate for A.4): [`packages/eval-framework/`](../../../packages/eval-framework/)

---

**This is a SKETCH round + sequence proposal ONLY.** No full plan written; no code touched; no agent build started. Pausing for full review of all 7 sketches + the proposed sequence before any full plan begins. Per operator directive 2026-05-20: do NOT auto-start the SET LOCAL fix or any other substrate work; wait for direction on which full agent plan to write first after sketch approval.
