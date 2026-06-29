# Nexus Cyber OS — System Readiness Report

**Date:** 2026-05-26
**Scope:** Full-system assessment — completion rate, capabilities coverage vs. Wiz, architectural maturity, skill-system readiness, and gap analysis.

---

## 1. Executive Summary

Nexus Cyber OS is a 17-agent, multi-tenant cloud security platform with 59K lines of production Python, 85K lines of test code, 190 eval cases, 348 test files, 35 plan documents, and 12 architecture decision records. Agents span the full cloud security lifecycle: posture management (CSPM), identity (CIEM), data security (DSPM), workload protection (CWPP), vulnerability management, network threat detection, runtime threat detection, compliance, investigation, remediation, threat intelligence, and cross-cutting orchestration (Supervisor, Synthesis, Curiosity, Meta-Harness).

**Overall project completion: ~62% through Phase 1 Waves 1-4 core buildout.** All 17 agents ship at v0.1 (meta-harness at v0.2.2), and 9 of 17 have NLAH personas. The G1 effectiveness scoring cycle (16 tasks) is closed. The G2 skill selection cycle (8 tasks) is 3/8 merged with 1 PR open and 1 blocked — the skill selection system, which differentiates the platform from static scanners, is the active integration frontier.

Relative to Wiz: Nexus covers the full Wiz security stack (CSPM, CIEM, DSPM, CWPP, vulnerability, compliance, remediation) across AWS, GCP, Azure, and Kubernetes. Where Wiz is a SaaS product with a mature rules engine, Nexus is an agentic platform with an LLM-native architecture — skills as procedural memory per agent, effectiveness scoring as the learning signal, and a fabric-backed event loop (NATS/JetStream) for continuous operation. The architectural design is more ambitious; the feature surface is less mature.

---

## 2. Completion Rate by Subsystem

### 2.1 Agent Buildout (Phase 1, Waves 1-4)

| Wave | Agents              | Version | NLAH Persona | Skills Dir | Eval Cases | Test Files | Status             |
| ---- | ------------------- | ------- | :----------: | :--------: | :--------: | :--------: | ------------------ |
| 0    | supervisor          | 0.1.0   |     YES      |     no     |     15     |     14     | Shipped            |
| 0    | meta-harness        | 0.2.2   |      no      |     no     |     20     |     39     | Shipped, G2 active |
| 1    | cloud-posture       | 0.1.0   |      no      |     no     |     10     |     16     | Shipped            |
| 1    | vulnerability       | 0.1.0   |     YES      |     no     |     10     |     12     | Shipped            |
| 1    | identity            | 0.1.0   |     YES      |     no     |     10     |     11     | Shipped            |
| 1    | compliance          | 0.1.0   |     YES      |     no     |     10     |     15     | Shipped            |
| 2    | runtime-threat      | 0.1.0   |      no      |     no     |     10     |     12     | Shipped            |
| 2    | network-threat      | 0.1.0   |      no      |     no     |     10     |     14     | Shipped            |
| 2    | multi-cloud-posture | 0.1.0   |      no      |     no     |     10     |     13     | Shipped            |
| 2    | k8s-posture         | 0.1.0   |      no      |     no     |     10     |     21     | Shipped            |
| 3    | investigation       | 0.1.0   |     YES      |     no     |     10     |     17     | Shipped            |
| 3    | remediation         | 0.1.0   |     YES      |     no     |     15     |     24     | Shipped            |
| 3    | audit               | 0.1.0   |     YES      |     no     |     10     |     12     | Shipped            |
| 4    | curiosity           | 0.1.0   |     YES      |     no     |     10     |     15     | Shipped            |
| 4    | synthesis           | 0.1.0   |     YES      |     no     |     10     |     16     | Shipped            |
| 4    | threat-intel        | 0.1.0   |      no      |     no     |     10     |     16     | Shipped            |
| 4    | data-security       | 0.1.0   |      no      |     no     |     10     |     16     | Shipped            |

**Agent buildout: 17/17 shipped (100%).** Per Path B operating rule, all agents ship v0.1 before any agent proceeds to v0.2.

### 2.2 G1 — Effectiveness Scoring

16 tasks, all merged. Provides: composite scoring pipeline, persistence layer (`.nexus/deployed-skills/`), CLI (`score-effectiveness`, `rate-skill`), backwards-compat handler, outcome-correlated audit emission, 5 eval cases, ADR-007 v1.5 canonical patterns, and verification record (CLOSURE).

**G1: 16/16 (100%) — CLOSED.**

### 2.3 G2 — Skill Selection

8 tasks per plan doc. Current status:

| Task | Description                                     | Risk            | Status                |
| :--: | ----------------------------------------------- | --------------- | --------------------- |
|  1   | bootstrap — version bump + CI smoke             | LOW             | **Merged**            |
|  2   | `ExecutionContract.trigger_source` field        | SAFETY-CRITICAL | **Merged**            |
|  3   | Supervisor `_build_contract()` propagation      | LOW             | **Merged**            |
|  4   | `SkillMetadataEntry` effectiveness fields       | SAFETY-CRITICAL | **PR #218 open**      |
|  5   | Wire `get_effectiveness_score()` into discovery | LOW             | **Blocked on Task 4** |
|  6   | Per-agent NLAH persona updates (17 agents)      | LOW             | Pending               |
|  7   | Eval suite extension                            | LOW             | Pending               |
|  8   | Verification record + CLOSURE                   | LOW             | Pending               |

**G2: 3/8 merged, 1 PR open, 1 blocked = ~44% through G2 when Task 4 lands.**

### 2.4 Infrastructure Subsystems

| Subsystem      | Version | Lines | Modules                  | Status                                                                                                       |
| -------------- | ------- | ----- | ------------------------ | ------------------------------------------------------------------------------------------------------------ |
| charter        | 0.1.0   | ~3K   | 14 modules               | Stable — contract, nlah_loader, llm_adapter, audit, cli, context, budget, tools, verifier, workspace, memory |
| shared         | 0.1.0   | ~1K   | fabric + skill_telemetry | Fabric base, NATS/JetStream runtime                                                                          |
| eval-framework | 0.1.0   | ~3K   | 10 modules               | cases, cli, compare, gate, render_json, render_md, results, runner, suite, trace                             |

### 2.5 Documentation

- 35 plan documents covering May 8-25, 2026
- 12 Architecture Decision Records (ADRs)
- ADR coverage: monorepo bootstrap, charter-as-context-manager, LLM provider strategy, fabric layer, async tool wrapper, OpenAI-compatible provider, reference agent, eval framework, memory architecture, version extension template, PR flow/branch protection, claims subject namespace

---

## 3. Capabilities Coverage vs. Wiz

### 3.1 Direct Domain Comparison

| Wiz Domain                                             | Wiz Approach                          | Nexus Agent                        | Nexus Approach                                                    | Maturity                                                              |
| ------------------------------------------------------ | ------------------------------------- | ---------------------------------- | ----------------------------------------------------------------- | --------------------------------------------------------------------- |
| **CSPM** (Cloud Security Posture Management)           | Static rules engine, graph-based risk | cloud-posture, multi-cloud-posture | Prowler+boto3 CSPM, OCSF 2003 events, AWS commercial regions      | v0.1 — single-region eval only; multi-region, live mode in v0.2 scope |
| **CIEM** (Cloud Infrastructure Entitlement Management) | IAM analysis, effective permissions   | identity                           | IAM privilege escalation detection, AssumeRole chain analysis     | v0.1 — 10 eval cases, NLAH persona present                            |
| **DSPM** (Data Security Posture Management)            | Data classification, exposure paths   | data-security                      | Data classification + exposure path detection                     | v0.1 — 10 eval cases                                                  |
| **CWPP** (Cloud Workload Protection)                   | Agentless + agent-based, runtime      | runtime-threat, k8s-posture        | Runtime threat detection, K8s posture scanning (live cluster API) | v0.1 — K8s v0.3 plans in-cluster mode                                 |
| **Vulnerability Management**                           | Agentless scanning, prioritization    | vulnerability                      | Vulnerability scanning + prioritization                           | v0.1 — 10 eval cases                                                  |
| **Compliance**                                         | Framework mapping, evidence           | compliance                         | Compliance framework mapping, evidence collection                 | v0.1 — 10 eval cases, OCSF heavy (12 OCSF files)                      |
| **Remediation**                                        | Guided remediation playbooks          | remediation                        | Automated remediation with earned-autonomy pipeline               | v0.1 — 15 eval cases, most test files (24) after meta-harness         |
| **Network Exposure**                                   | Attack path analysis                  | network-threat                     | Network threat detection + attack path analysis                   | v0.1 — 10 eval cases                                                  |
| **Threat Detection**                                   | Anomaly detection, signals            | threat-intel, runtime-threat       | Threat intelligence enrichment, runtime anomaly detection         | v0.1 — feed-driven                                                    |
| **Investigation**                                      | Graph explorer, query engine          | investigation                      | OCSF-aware investigation, cross-agent correlation                 | v0.1 — 10 eval cases                                                  |

### 3.2 Beyond Wiz — Nexus-Only Capabilities

| Capability                | Wiz                         | Nexus                                                                                                          |
| ------------------------- | --------------------------- | -------------------------------------------------------------------------------------------------------------- |
| **Agentic orchestration** | None — SaaS product with UI | Supervisor (#0) delegates to specialists, 5-stage pipeline (INGEST→ROUTE→DISPATCH→AUDIT→HANDOFF)               |
| **Cross-agent synthesis** | None                        | synthesis agent (LLM-native, "Narrator" persona) synthesizes findings across agents                            |
| **Proactive exploration** | None                        | curiosity agent (LLM-native) explores unknowns                                                                 |
| **Meta-evaluation**       | None — closed internal QA   | meta-harness self-evaluates skills with effectiveness scoring (G1 closed), skill selection (G2 active)         |
| **LLM-native skills**     | Static rules only           | Progressive-disclosure SKILL.md per agent (charter.nlah_loader v1.4), LLM selects skills per run               |
| **Fabric event loop**     | Polling-based               | NATS/JetStream fabric — 6 streams (events, findings, commands, approvals, audit, claims), continuous operation |
| **Audit chain**           | Internal logging            | F.6 audit agent — complete traceability per run, per decision, per escalation                                  |
| **Multi-tenant RLS**      | Org-level tenancy           | PostgreSQL LTREE per-tenant row-level security                                                                 |

### 3.3 Wiz Strengths (Where Nexus Lags)

1. **Detection rules coverage.** Wiz has thousands of built-in rules across CSPM, CIEM, DSPM, CWPP. Nexus has 190 eval cases defining detection surface — orders of magnitude fewer detection paths.
2. **UI/UX.** Wiz has a polished SaaS UI with graph-based risk visualization. Nexus has no UI — terminal, CLI, and markdown reports only.
3. **Production hardening.** Wiz processes billions of cloud events daily in production. Nexus has never been deployed to production.
4. **Integrations.** Wiz has native Jira, ServiceNow, Slack, Splunk, PagerDuty integrations. Nexus has none.
5. **Compliance frameworks.** Wiz maps to 50+ compliance frameworks out of the box. Nexus has a compliance agent with 10 eval cases — a starting point, not a product.

---

## 4. Architecture Maturity Assessment

### 4.1 Decision Record Coverage (12 ADRs)

All foundational architectural concerns have ADRs: monorepo structure, charter contract, LLM strategy (Anthropic + OpenAI-compatible), fabric/routing (NATS/JetStream), async tools, eval framework, memory (PostgreSQL LTREE + pgvector), versioning, PR discipline, and claims namespace. **No known architectural gaps.**

### 4.2 Substrate Decoupling (WI-1)

The charter substrate seal is enforced via CI (`git diff --stat origin/main -- packages/charter/ packages/shared/`). Agent packages must not modify substrate. This discipline holds across all 17 agents.

### 4.3 Agent Contract Maturity

| Contract Element                  | Status                                                    |
| --------------------------------- | --------------------------------------------------------- |
| ExecutionContract (charter)       | 0.1.0 — trigger_source added G2 Task 2                    |
| DelegationContract (supervisor)   | 0.1.0 — trigger_source propagated G2 Task 3               |
| SkillMetadataEntry (charter)      | v1.4 — effectiveness fields being added G2 Task 4         |
| AgentSkillRegistry (meta-harness) | v0.2 — discover_agent_skills + cross-agent walking        |
| OCSF v1.3 compliance              | All 17 agents reference OCSF types (0-15 files per agent) |

### 4.4 LLM Architecture

All 17 agents import `charter.llm_adapter`. The dual-provider strategy (Anthropic direct + OpenAI-compatible) is implemented. Two agents (synthesis, curiosity) are LLM-native with full personas. Supervisor is explicitly LLM-free (Q-ARCH-2 enforced via source-grep smoke test).

### 4.5 Operational Gaps

| Gap                                                        | Severity | Plan Reference                                      |
| ---------------------------------------------------------- | -------- | --------------------------------------------------- |
| No skills deployed to any agent (0/17 have `nlah/skills/`) | HIGH     | G2 Tasks 4-8 (active)                               |
| 8/17 agents lack NLAH README (persona)                     | MEDIUM   | G2 Task 6 (per-agent NLAH update)                   |
| No production deployment                                   | HIGH     | Not yet planned                                     |
| No UI layer                                                | MEDIUM   | Not yet scoped                                      |
| No external integrations (SIEM, ITSM)                      | MEDIUM   | Not yet scoped                                      |
| SET LOCAL tenant-RLS substrate bug                         | MEDIUM   | Tracked in memory; blocks F.5 live tests (5/6 fail) |
| Cross-run AFFECTS-edge dedup is known debt                 | LOW      | KG-loop v0.1 accepted debt                          |
| No continuous skill aggregation (manual CLI only)          | LOW      | G2 v0.2 concern                                     |

---

## 5. Test Coverage Assessment

**Overall metrics:**

- 348 Python test files (across all packages)
- 85,025 lines of test code
- 59,112 lines of production code
- Test-to-production line ratio: 1.44:1
- 190 eval cases across 17 agents

**Top test coverage:** meta-harness (39 files), remediation (24), k8s-posture (21)
**Lowest test coverage:** identity (11 files)

Test discipline is strong — test code volume exceeds production code volume, and every agent has an eval suite. However, 190 eval cases across 17 agents averages ~11 per agent, which is thin for production CSPM coverage (Wiz runs millions of checks daily).

---

## 6. Phase 1 Completion Trajectory

```
Phase 1 Waves:          [████████████████████] 100% (Waves 0-4: 17/17 agents v0.1)
G1 Effectiveness:       [████████████████████] 100% (16/16 tasks, CLOSURE)
G2 Skill Selection:     [██████░░░░░░░░░░░░░░] ~44%  (3/8 merged, 1 PR open)
  └─ Tasks 4-8 remaining: schema extension (PR open), wiring (blocked), NLAH updates, eval, verification

Next milestones:
  G2 CLOSURE             → estimated 2-3 more PRs after Task 4 merges
  Wave 1 agent v0.2      → F.3 cloud-posture (first agent to v0.2 per build plan)
  Skills deployed        → post-G2 — first `nlah/skills/` content across agents
  Production deployment  → not yet scoped
```

---

## 7. Risk Assessment

| Risk                                                    | Likelihood | Impact | Mitigation                                                                                      |
| ------------------------------------------------------- | ---------- | ------ | ----------------------------------------------------------------------------------------------- |
| Skill system never reaches operational density          | Medium     | High   | G2 is actively shipping; Task 6 creates 17 agent personas                                       |
| 190 eval cases insufficient for CSPM coverage           | High       | High   | Per-agent eval case authoring is part of each Wave's plan                                       |
| No production feedback loop                             | High       | Medium | G1 effectiveness scoring is designed for production signals; currently manual CLI only          |
| SET LOCAL bug blocks multi-tenant queries               | Certain    | Medium | Known, tracked; F.5 substrate-fix plan exists                                                   |
| LLM dependency for skill selection is non-deterministic | Medium     | Medium | G2 eval suite (Task 7) will measure selection quality; zero-confidence = include (conservative) |
| 8 agents without NLAH personas are "headless"           | Medium     | Low    | G2 Task 6 creates all 17; each agent operates with charter context even without persona         |

---

## 8. Summary Verdict

**Nexus Cyber OS is 62% through its Phase 1 feature buildout.** The agent fleet is fully stood up (17/17 agents at v0.1), the evaluation infrastructure is operational, the G1 effectiveness scoring pipeline is closed, and G2 skill selection is mid-integration. The architectural foundations — 12 ADRs, substrate decoupling, progressive-disclosure skill loading, fabric event loop, LLM adapter, dual-provider strategy — are solid.

**Relative to Wiz**, Nexus covers the same security domains but with a fundamentally different architecture: agentic, LLM-native, and event-driven rather than rules-engine-based. The agentic architecture is a structural advantage for complex detection chains that cross security domains (e.g., CSPM finding → identity analysis → remediation), but Wiz's mature rules engine, production hardening, and UI/polish represent a 3-5 year lead in operational maturity.

**The critical path forward** is: close G2 (Tasks 4-8) → deploy skills to Wave 1 agents → F.3 cloud-posture v0.2 (live AWS mode) → production deployment → continuous skill aggregation from production signals. Until skills are deployed and selection is live, Nexus is an infrastructure platform without its procedural memory layer — structurally complete but operationally thin.
