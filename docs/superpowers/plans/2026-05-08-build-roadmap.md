# Nexus Cyber OS — Build Roadmap (Master Plan-of-Plans)

> **For agentic workers:** This is a *roadmap*, not an executable plan. Each entry below points to a sub-plan saved as `docs/superpowers/plans/YYYY-MM-DD-<slug>.md`. Sub-plans use TDD checkbox steps and are executed via `superpowers:subagent-driven-development` or `superpowers:executing-plans`. spec-kit's `/specify` consumes each sub-plan as input.

**Goal:** Ship Phase 1 of Nexus Cyber OS — a horizontal autonomous cloud security platform with 18 agents, edge plane, three-tier remediation, console (chat + dashboard), and two vertical content packs (mid-market tech as sales focus, healthcare as pipeline) — in 9–12 months with an 8-engineer team plus compliance + threat-intel + ops + CSM.

**The Path (anchor):** Build horizontally with deep vertical content packs. Sell with vertical sequencing (Phase 1 = mid-market tech, Phase 2 = healthcare, Phase 3 = financial, Phase 3-4 = manufacturing, Phase 4-5 = defense). The 18 agents are domain-agnostic. Vertical content packs layer on top. Self-evolution compounds learning across verticals.

**Architecture summary:** Python agents on Anthropic Claude (Sonnet 4.5 / Haiku 4 / Opus 4.5), file-backed state, charter-validated execution contracts, hash-chained audit. SaaS control plane on AWS (us-east-1 + us-west-2 DR). Single-tenant edge agent (Helm chart, EKS/AKS/GKE) connected via outbound mTLS. Three memory engines: TimescaleDB (episodic) + PostgreSQL (procedural) + Neo4j Aura (semantic/KG). Console: Next.js + TypeScript. Edge runtime: Go (perf) + Python (agent reasoning). Monorepo with Turborepo. CI: GitHub Actions + self-hosted runners.

**Tech Stack:** Python 3.12 / TypeScript 5 / Go 1.22 · Anthropic SDK · Auth0 (SSO) · TimescaleDB · PostgreSQL 16 · Neo4j Aura · ClickHouse · NATS / Redis Streams · Prowler · Trivy · Falco · Cartography · Cloud Custodian · Checkov · Trufflehog · Kubescape · Vector · Helm · Turborepo · Next.js · GitHub Actions · Mintlify · Auth0

---

## Phase boundaries (calendar)

| Phase | Months | Theme | Exit gate |
|---|---|---|---|
| **Phase 0** | M0 (4–6 weeks) | Bootstrap — repo, decisions, spikes, hires | All 7 spikes resolved with ADRs; canonical doc set; 3 of 8 engineers hired; first design-partner LOI signed |
| **Phase 1a** | M1–M3 | Foundation — charter, eval framework, first agent (Cloud Posture), auth, memory engines | One end-to-end agent invocation with audit trail; SOC 2 Type I scoping started |
| **Phase 1b** | M4–M7 | Detection breadth — 12 more agents, control plane, edge plane, ChatOps approvals | All 18 agents in alpha; edge deployed at 1 design partner; Tier 3 remediation working |
| **Phase 1c** | M8–M10 | Productization — Tier 2 + Tier 1 remediation, console v1, vertical content packs (tech complete, healthcare 80%) | First paying customer in production; SOC 2 Type I achieved |
| **Phase 1 GA** | M11–M12 | Hardening — observability, on-call, DR drills, security review | $400K–$1M ARR signed; 5–8 customers in production; NPS ≥ 30 |

---

## Plan inventory (~25 sub-plans)

Plans grouped by track. Dependencies noted as `↳ requires: [PlanID]`. Where `[Parallel-with: ...]` is shown, plans can be worked simultaneously by different engineers.

### Track 0 — Bootstrap (Phase 0)

| ID | Sub-plan | Owner | Effort | Notes |
|---|---|---|---|---|
| **P0.1** | Repo bootstrap + monorepo skeleton + CI/CD baseline | DevOps Eng | 1 wk | Turborepo, GitHub Actions, self-hosted runners, branch protection, conventional commits, pre-commit hooks |
| **P0.2** | Doc canonicalization — `_meta/glossary.md`, ADR template, version-history.md, README.md, archive PART1/PART3, declare harness doc canonical pending PART4-5 | Tech Writer | 1 wk | Resolves the 3-overlapping-specs problem from review |
| **P0.3** | Spike — Cloud Custodian vs. Terraform for Tier 1 remediation | Detection Eng + Backend Eng | 2 wks | Decision ADR; recommend hybrid in pre-spike intuition |
| **P0.4** | Spike — NLAH writability test (can a non-engineer author production NLAH?) | Detection Eng + Tech Writer | 2 wks | Non-engineer participates; output = NLAH authoring guide |
| **P0.5** | Spike — Charter contract validator PoC (YAML schema + budget enforcer + tool whitelist) | AI/Agent Eng | 1 wk | Foundation for F.1 |
| **P0.6** | Spike — Neo4j Aura graph queries at healthcare scale (50K identities, 100K assets, simulated load) | Backend Eng | 1 wk | Validates W3 decision |
| **P0.7** | Spike — Anthropic API budget enforcement at customer level (rate-limit middleware) | AI/Agent Eng | 1 wk | Validates per-tenant token caps |
| **P0.8** | Spike — Edge agent install + update flow (Helm + signed bundles) | Platform Eng | 2 wks | Validates W1 / W7 edge architecture |
| **P0.9** | Spike — Vertical content pack workflow (compliance eng + threat intel develop tech + healthcare packs in parallel) | Compliance Eng + Threat Intel | 1 wk | Validates J3 team composition assumption |

**Phase 0 deliverables:** P0.1 repo skeleton committed · 7 ADRs committed (one per spike) · canonical doc set in place · 3 hires onboarded (Detection Eng, AI/Agent Eng, Backend Eng) · first design-partner LOI signed.

---

### Track F — Foundation (Phase 1a)

| ID | Sub-plan | Owner | Effort | Depends on |
|---|---|---|---|---|
| **F.1** | Runtime charter v0.1 — execution contract schema + validator + budget envelope + tool registry + audit hash chain | AI/Agent Eng | 4 wks | P0.5, P0.7 |
| **F.2** | Eval framework v0.1 — case format, runner, gates, traces, comparison reports | AI/Agent Eng | 3 wks | F.1 (parallel-with) |
| **F.3** | **Cloud Posture Agent reference NLAH** (Prowler-backed; AWS only) — first end-to-end working agent with charter + eval + audit | Detection Eng + AI/Agent Eng | 5 wks | F.1, F.2 |
| **F.4** | Auth + tenant manager — Auth0 SSO (SAML + OIDC), SCIM provisioning, RBAC, MFA enforcement | Backend Eng | 3 wks | P0.1 (parallel-with all of F) |
| **F.5** | Memory engines integration — TimescaleDB (episodic) + PostgreSQL (procedural) + Neo4j Aura (semantic). Per-tenant workspace pattern enforced | Backend Eng | 3 wks | P0.6, F.1 (parallel-with F.3) |
| **F.6** | Audit Agent (#14) — append-only hash-chained log writer, tamper detection, 7-year retention design | Backend Eng | 2 wks | F.1 |

**Phase 1a deliverables:** Cloud Posture Agent runs end-to-end against a real AWS dev account, produces findings.json + summary.md, every action audited, reproducible from disk. Eval suite ≥ 50 cases passing. SSO working in dev environment. Memory writes flowing to all three engines.

---

### Track D — Detection breadth (Phase 1b)

Each agent is its own sub-plan that follows the **Cloud Posture Agent template** (F.3). Pattern: NLAH authoring → charter wiring → tool integration → eval suite → integration tests. Most are 3-4 weeks each; complex ones are 5-6 weeks.

| ID | Sub-plan | Backend tools | Owner | Effort |
|---|---|---|---|---|
| **D.1** | Vulnerability Agent (#2) | Trivy, Grype, OSV, NVD, EPSS | Detection Eng | 4 wks |
| **D.2** | Identity Agent (#3) — CIEM | Cartography, AWS IAM Access Analyzer, custom permission simulator | Detection Eng | 5 wks |
| **D.3** | Runtime Threat Agent (#4) — CWPP | Falco (eBPF), Tracee, OSQuery | Detection Eng | 5 wks |
| **D.4** | Network Threat Agent (#6) | VPC Flow Logs parser, Suricata rules, DGA classifier | Detection Eng | 4 wks |
| **D.5** | Data Security Agent (#5) — DSPM | Macie API, custom classifiers, Apache Tika for unstructured | Detection Eng | 5 wks |
| **D.6** | Compliance Agent (#7) + framework engine (~110 framework definitions, deep mapping for SOC 2, ISO 27001, HIPAA, HITRUST in Phase 1) | Custom framework DSL | Compliance Eng + Detection Eng | 6 wks |
| **D.7** | Investigation Agent (#8) + sub-agent orchestration (Orchestrator-Workers pattern; depth ≤ 3, parallel ≤ 5) | MITRE ATT&CK mappings, custom timeline builder | Detection Eng + AI/Agent Eng | 6 wks |
| **D.8** | Threat Intel Agent (#9) — feed integration | MITRE ATT&CK, CISA KEV, OTX, abuse.ch, GreyNoise, OSV, GitHub Advisory, H-ISAC | Threat Intel Analyst | 4 wks |
| **D.9** | Application & Supply Chain Security Agent (#16) — SAST + DAST + supply chain | Semgrep, ZAP baseline, Sigstore/cosign verifier | Detection Eng | 5 wks |
| **D.10** | SaaS Posture Agent (#17) — SSPM | M365, Google Workspace, Salesforce, ServiceNow, GitHub, Slack, Zoom APIs | Detection Eng | 5 wks |
| **D.11** | AI Security Agent (#18) — AI-SPM | Garak, ProtectAI ModelScan, PyRIT, LLM Guard | Detection Eng + AI/Agent Eng | 4 wks |
| **D.12** | Curiosity Agent (#11) — background "wonder" agent with idle scheduler | Custom; uses all read-only tools from other agents | AI/Agent Eng | 3 wks |
| **D.13** | Synthesis Agent (#12) — cross-agent reasoning, customer-facing narrative | Claude Opus 4.5 | AI/Agent Eng | 3 wks |

---

### Track A — Action / remediation (Phase 1b → Phase 1c)

| ID | Sub-plan | Owner | Effort | Depends on |
|---|---|---|---|---|
| **A.1** | Remediation Agent (#10) — Tier 3 (recommend) — generates Cloud Custodian / Terraform / runbook artifacts | Detection Eng + Backend Eng | 4 wks | D.1, D.6, P0.3 |
| **A.2** | Remediation Agent — Tier 2 (approve & execute) — gated by ChatOps | Backend Eng + Detection Eng | 4 wks | A.1, S.3 |
| **A.3** | Remediation Agent — Tier 1 (autonomous) — 8 narrow action classes, dry-run + blast-radius cap + auto-rollback timer + post-validation | Backend Eng + Security Eng + Detection Eng | 6 wks | A.2, F.6 |
| **A.4** | Meta-Harness Agent (#13) — self-evolution loop, NLAH proposal, eval gating, deploy pipeline | AI/Agent Eng | 5 wks | F.2, all D.* (reads traces) |

---

### Track S — Surfaces (Phase 1b → Phase 1c)

| ID | Sub-plan | Owner | Effort | Depends on |
|---|---|---|---|---|
| **S.1** | Console v1 — dashboard primary (findings list, filter, drill-down, IA shell, navigation, theming with dark mode) | Frontend Eng | 6 wks | F.4, F.5 |
| **S.2** | Console v1 — chat sidebar (Anthropic-backed, customer context aware, HIPAA-compliant audit log of every query) | Frontend Eng + AI/Agent Eng | 4 wks | S.1, F.1 |
| **S.3** | ChatOps approval flows — Slack app + Teams Bot Framework + Email (HMAC-signed URLs, expiry, mobile-friendly) | Backend Eng | 4 wks | F.4 |
| **S.4** | API + CLI — REST API per OpenAPI spec, Python SDK, `nexus` CLI | Backend Eng | 3 wks | F.4 |

---

### Track E — Edge plane (Phase 1b)

| ID | Sub-plan | Owner | Effort | Depends on |
|---|---|---|---|---|
| **E.1** | Edge agent runtime — Go binary, charter subset, local scanners (Prowler/Trivy/Falco), workspace storage, telemetry buffer | Platform Eng | 6 wks | P0.8, F.1 |
| **E.2** | Edge ↔ control plane mTLS + telemetry pipeline (Vector → ClickHouse), reconnect/replay logic, signed updates | Platform Eng + Backend Eng | 4 wks | E.1, F.5 |
| **E.3** | Edge Helm chart for EKS / AKS / GKE — installer, upgrader, observability sidecar | Platform Eng | 3 wks | E.1 |

---

### Track C — Vertical content packs (Phase 1b → Phase 1c)

| ID | Sub-plan | Owner | Effort |
|---|---|---|---|
| **C.0** | Generic content baseline — universal NLAH tunings + universal compliance mappings (~110 frameworks at engine level, basic mappings) | Compliance Eng + Threat Intel | 4 wks |
| **C.1** | Tech content pack (Phase 1 sales focus) — SOC 2 Type II deep, ISO 27001:2022 deep, GDPR/CCPA deep, DevSecOps detection rules, GitHub/GitLab/Slack integration depth, tech threat intel, tech-friendly NLAH tunings, audit-ready evidence templates | Compliance Eng + Threat Intel + Detection Eng | 8 wks |
| **C.2** | Healthcare content pack (Phase 2 sales focus, target 80% by Phase 1 GA) — HIPAA Security Rule deep, HITRUST CSF v11, 42 CFR Part 2, 18 PHI classifiers, H-ISAC, Teams + ServiceNow integration depth, healthcare NLAH tunings | Compliance Eng + Threat Intel + Detection Eng | 10 wks |

---

### Track O — Operations + GA readiness (Phase 1c → GA)

| ID | Sub-plan | Owner | Effort |
|---|---|---|---|
| **O.1** | Observability — Prometheus + Grafana + OpenTelemetry traces, SLO dashboards, on-call rotation in PagerDuty | DevOps Eng | 3 wks |
| **O.2** | Nexus's own SOC 2 Type I — security architecture, threat model, pen test, evidence collection | Security Eng | 8 wks (parallel) |
| **O.3** | Customer onboarding playbook + implementation engineer runbooks (universal flow + tech addendum + healthcare addendum) | CSM + Tech Writer | 3 wks |
| **O.4** | Pre-GA hardening — DR drill, chaos test, security review, rollback drill, customer comms plan | All | 4 wks |
| **O.5** | Mintlify docs site (api ref, admin guide, runbooks, threat model, vertical compliance reports) | Tech Writer | 4 wks |
| **O.6** | OSS releases — `charter` package + `eval-framework` package on public GitHub under Apache 2.0 with tagged versions, contribution guide, code of conduct | AI/Agent Eng + Tech Writer | 2 wks |

---

## Plan dependencies (critical path)

```
                                    ┌─── F.4 (auth) ──────────┐
                                    │                         │
P0.1 → P0.2 → P0.3..P0.9 → F.1 ─┬→ F.2 → F.3 (Cloud Posture)──┼→ D.1..D.13 (parallel batches)
                                ↓                              │
                                F.5 (memory) ──────────────────┤
                                ↓                              ↓
                                F.6 (audit) ─────→ A.1 → A.2 → A.3 → Meta-Harness (A.4)
                                                                        │
                                                  S.1 → S.2 (console) ──┤
                                                  S.3 (chatops) ────────┤
                                                  E.1 → E.2 → E.3 ──────┤
                                                                        ↓
                                                                  C.1 (tech pack) ──→ Phase 1 GA
                                                                  C.2 (healthcare) → Phase 2 ramp
```

**Critical path = P0 → F.1 → F.3 → A.3 (Tier 1).** Everything else parallelizes.

---

## BMAD ↔ spec-kit integration points

| Roadmap stage | BMAD persona owns | spec-kit step | Output |
|---|---|---|---|
| Roadmap (this doc) | John (PM) + Mary (analyst) | — | `BUILD_ROADMAP.md` |
| Sub-plan brief (per plan) | John + Winston | — | `_bmad-output/planning-artifacts/<plan-id>-brief.md` |
| Sub-plan architecture | Winston (architect) | — | `_bmad-output/planning-artifacts/<plan-id>-arch.md` |
| Sub-plan stories | Amelia (dev) + Sally (UX) | `/specify` | `spec.md` |
| Sub-plan technical plan | Winston (architect) | `/plan` | `plan.md` |
| Atomic tasks | Amelia (dev) | `/tasks` | `tasks.md` |
| Code | Claude Code | `/implement` | code + tests + commits |
| Review gates | John (PM) + Winston (architect) | `/analyze` | review notes |

**Each sub-plan goes through this pipeline once.** ~25 pipelines over 12 months, with several running in parallel.

---

## Phase 1 success criteria (recap from J4)

- Five to eight customers in production using the platform daily ≥ 30 days (4–6 mid-market tech + 1–2 healthcare design partners).
- $400K–$1M ARR signed.
- Mean time to remediation reduced ≥ 50% from customer baseline.
- False positive rate < 15%.
- Tier 2 approval queue P95 < 5 days.
- No platform-caused production incidents.
- Customer NPS > 30.
- All 18 agents in production.
- SOC 2 Type I achieved.
- Tech content pack 100% complete; healthcare content pack ≥ 80% complete.
- Self-evolution operational; ≥ 3 NLAH improvements deployed per month via Meta-Harness.
- Eval suites ≥ 100 cases per agent.
- Critical-finding detection latency < 60s.

---

## What's NOT in Phase 1 (de-scoped, deferred to Phase 2+)

- **GCP and OCI cloud coverage** (AWS + Azure only in Phase 1; GCP added Phase 2)
- **Air-gap deployment** (Phase 4)
- **Mobile native app** (Phase 3 — workaround: Slack mobile + email approvals)
- **Full Tier 1 expansion to 25+ action classes** (Phase 3; Phase 1 = 8 classes)
- **MSSP white-label** (Phase 3)
- **Financial / Manufacturing / Defense vertical content packs** (Phases 3–5)
- **OpenAI in production traffic** (canary only Phase 1; active Phase 2 for cost optimization)
- **Mobile native SOC analyst console** (Phase 3)
- **Auto-deploy of major NLAH rewrites without human review** (Phase 2-3)

---

## Open items (unblocked by working assumptions; revisit when known)

- M4 design-partner scenario — assumed multi-vertical (A); affects which customer-development tasks live in Phase 0 vs. Phase 1.
- J5 budget runway — assumed $5M/18 months; affects parallel hiring aggressiveness.
- A3/P2 PART3 disposition — accept structural depth; PART4-5 produced alongside Phase 1 build (Tech Writer track).

---

## Recommended write order for sub-plans

1. **P0.1** (repo bootstrap) — needed before any code lands
2. **P0.2** (doc canonicalization) — unblocks everyone else
3. **P0.3 / P0.5 / P0.7** (the three highest-risk spikes) — written together, run in parallel
4. **F.1** (charter v0.1) — the foundation everything else stacks on
5. **F.3** (Cloud Posture reference) — first end-to-end agent; pattern that scales to 17 more
6. Everything else opportunistically as engineers free up

---

## Self-review against this roadmap

✓ Spec coverage — every PRD section has a Track or Plan ID.
✓ Phase 1 scope (J1) is reflected in plan sizing.
✓ Three "must-haves" (J2) map to F.3/F.6 (autonomous loop), C.1 (vertical depth), E.1-E.3 (edge).
✓ 18 agents (J1) — all listed in Track D + the Action/Synthesis tracks.
✓ Three memory engines (W3) covered in F.5.
✓ Charter as universal foundation (W1, M5 moat #1) covered in F.1.
✓ Open-source split (J6) covered in O.6.
✓ Vertical content packs (path decision) carved into Track C with clear Phase 1 vs. Phase 2 split.
✓ Phase 0 spikes (A4) all listed individually.

**Gap noted:** I haven't yet sized hiring sequencing on a calendar — that lives in a separate operations doc, not this engineering roadmap. **Recommend:** John writes a hiring & runway plan as a sister doc.

---

## Next actions

1. **You confirm or revise the three working assumptions above.**
2. **You pick the first sub-plan to write in TDD detail.** Recommended: **P0.1 (repo bootstrap)** — fastest unblock, lets all engineers start working.
3. I write that sub-plan to `docs/superpowers/plans/2026-05-08-<plan-slug>.md` with full TDD steps.
4. We run it through BMAD review (Winston + John) → spec-kit `/specify` → execute.
