# Phase 1 Wave Build Plan — v0.2 for all 17 agents (2026-05-23)

**Status:** Draft — pending operator review and approval.
**Prerequisite:** A.4 Meta-Harness v0.2 closed (Wave 0, 16/16 tasks, 392 tests, 2026-05-23).
**References:** [Hermes-pattern absorption](../../_meta/hermes-pattern-absorption-2026-05-22.md), [A.4 v0.2 plan](2026-05-22-a-4-meta-harness-v0-2.md), [A.4 v0.2 verification](../../_meta/a-4-meta-harness-v0-2-verification-2026-05-23.md), [remaining-agents sketch](../sketches/2026-05-20-remaining-agents-sketch.md).

## §0. Executive summary

**Wave 0 closed.** A.4 Meta-Harness v0.2 installed the compounding learning loop — progressive-disclosure NLAH loader (N1), autonomous skill creation (N2), and agentskills.io format (N5). Every agent from Wave 1 forward inherits:

1. A `nlah/skills/` directory that A.4 can write to
2. A skill-discovery registry that lists deployed skills per agent
3. An eval-gate that gates every auto-deployed skill
4. A first-of-class operator approval gate via `meta-harness approve-skill`

**This plan covers Waves 1-6** — v0.2 for all 15 remaining agents, organized into 6 waves of 2-3 agents each. Per-wave plan docs will be written before each wave starts; this document is the roadmap.

## §1. What "v0.2" means — the generic upgrade template

Every agent v0.1 → v0.2 inherits these **platform-level** upgrades (zero per-agent work — A.4 v0.2 already shipped them):

| Capability                  | Mechanism                                                                                              | Agent work required                                                 |
| --------------------------- | ------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------- |
| Progressive-disclosure NLAH | `charter.nlah_loader` v1.4 — `load_skill_metadata_index()` / `load_skill()` / `load_skill_reference()` | Ship a `nlah/skills/` directory (can be empty)                      |
| Skill loading at runtime    | `skills_overlay` parameter on the NLAH loader                                                          | Call `load_skill_metadata_index(nlah_dir)` in agent startup         |
| A.4 observes complex runs   | F.6 audit chain + workspace artefacts                                                                  | Emit F.6 audit entries for tool calls (already done for all agents) |
| A.4 eval-gates candidates   | `skill_eval_gate.py` — Option-B two-run baseline                                                       | Eval suite must be deterministic (already true for all 17 agents)   |

Beyond the platform baseline, each agent's v0.2 has **agent-specific** scope — the capability it was missing in v0.1. These fall into 3 categories:

1. **Live-mode activation** — v0.1 shipped with stub/synthetic eval; v0.2 connects to real cloud APIs (applies to CSPM, Data, Threat agents).
2. **Hermes nectar absorption** — N3 (Curator, A.4 v0.3), N4 (per-customer baseline, D.12 v0.2), N6 (cross-session search, D.13 v0.2).
3. **Domain depth** — capabilities the v0.1 plan explicitly deferred (multi-region, cross-tenant, additional frameworks, additional cloud providers).

## §2. Fleet inventory — all 17 agents at v0.1, mapped to v0.2 scope

| Wave         | Agent               | Code | v0.1 shipped | v0.2 scope                                                                                  |
| ------------ | ------------------- | ---- | ------------ | ------------------------------------------------------------------------------------------- |
| **0**        | meta-harness        | A.4  | 2026-05-21   | **CLOSED** — N1+N2+N5, auto-deploy, subscriber-ACL                                          |
| **1**        | cloud-posture       | F.3  | 2026-05-10   | Live AWS mode, skills library, multi-region, A.4 integration                                |
| **1**        | multi-cloud-posture | D.5a | 2026-05-13   | Live Azure/GCP mode, skills library, A.4 integration                                        |
| **1**        | k8s-posture         | D.6a | 2026-05-13   | Already at v0.2/v0.3 (live cluster + in-cluster); v0.2.5 = A.4 integration + skills library |
| **2**        | data-security       | D.5  | 2026-05-20   | Live S3 DSPM, PII classifier, A.4 integration                                               |
| **2**        | compliance          | D.6  | 2026-05-21   | Live cross-source aggregation, additional frameworks (SOC2, HIPAA), A.4 integration         |
| **3**        | runtime-threat      | D.3  | 2026-05-11   | Live CWPP (Falco/Tracee), A.4 integration                                                   |
| **3**        | network-threat      | D.4  | 2026-05-13   | Live Suricata/VPC flow, A.4 integration                                                     |
| **3**        | threat-intel        | D.8  | 2026-05-21   | Live CVE/MITRE feeds, A.4 integration                                                       |
| **4**        | identity            | D.2  | 2026-05-11   | Live CIEM (AWS IAM, Access Analyzer), A.4 integration                                       |
| **4**        | vulnerability       | D.1  | 2026-05-11   | Live CVE (Trivy/OSV/NVD), A.4 integration                                                   |
| **5**        | investigation       | D.7  | 2026-05-13   | Cross-agent correlation v0.2, A.4 skill consumer (first agent to LOAD A.4-created skills)   |
| **5**        | curiosity           | D.12 | 2026-05-21   | **N4** — per-customer behavioral baseline, hypothesis refinement                            |
| **5**        | synthesis           | D.13 | 2026-05-21   | **N6** — cross-session search + LLM summary (gated on Surface track)                        |
| **6**        | meta-harness        | A.4  | v0.2 closed  | v0.3 — **N3** Curator (stale/duplicate/failing pruning)                                     |
| **6**        | audit               | F.6  | 2026-05-12   | Compliance reporting v0.2                                                                   |
| **excluded** | remediation         | A.1  | 2026-05-16   | Phase 3 territory — no v0.2 in Phase 1                                                      |
| **excluded** | supervisor          | #0   | 2026-05-21   | Downstream of A.4 v0.2 introspection — no v0.2 in Phase 1                                   |

**Note on ID namespace:** The remaining-agents sketch flagged D.5/D.6 overlap between multi-cloud-posture (self-claims D.5) / k8s-posture (self-claims D.6) and data-security (operator D.5) / compliance (operator D.6). Resolution: use operator IDs. multi-cloud-posture = D.5a, k8s-posture = D.6a, data-security = D.5, compliance = D.6. The existing package READMEs need updating — included as a Task 1 item in the relevant wave plans.

## §3. Wave dependency graph

```
Wave 0: A.4 v0.2  ─────────────────────────────────────────────┐
  (learning loop installed)                                      │
                                                                 │
Wave 1: F.3 v0.2 ──→ multi-cloud v0.2 ──→ k8s v0.2.5            │
  (CSPM family — no cross-wave deps)                             │
       ┌─────────────────────────────────────────────────────────┘
       ▼
Wave 2: D.5 data-security v0.2 ──→ D.6 compliance v0.2
  (Compliance reads D.5 findings)
       │
       ├──→ Wave 3: D.3 runtime v0.2 → D.4 network v0.2 → D.8 threat-intel v0.2
       │     (Threat family — orthogonal to each other; D.8 correlates with D.3/D.4)
       │
       ├──→ Wave 4: D.2 identity v0.2 → D.1 vuln v0.2
       │     (Identity/Vuln — orthogonal pair)
       │
       └──→ Wave 5: D.7 investigation v0.2 → D.12 curiosity v0.2 → D.13 synthesis v0.2
             (Smart layer — D.12 depends on D.5/D.6/D.8/D.13 findings; D.13 gated on Surface)
                   │
                   ▼
            Wave 6: A.4 v0.3 (Curator N3) + F.6 v0.2 (compliance reporting)
```

**Waves 1-4 are parallelizable** — they have no cross-wave dependencies. Waves 5-6 depend on Waves 1-4 completing (they need findings from all detect agents to reason over).

## §4. Wave 1 — CSPM family (F.3, multi-cloud-posture, k8s-posture)

**Why first.** CSPM agents are the reference NLAH pattern (per ADR-007). F.3 cloud-posture was the first agent ever built. They have the cleanest v0.1 → v0.2 path: activate live mode, integrate A.4 skills, done. Building CSPM v0.2 first proves the "A.4 integration" pattern that every subsequent wave inherits.

### §4.1 F.3 cloud-posture v0.2

**Current v0.1 state:** AWS CSPM via Prowler + boto3. 10 eval cases (stub AWS responses). OCSF 2003 findings. Single-region (`us-east-1` default). No live AWS integration in CI.

**v0.2 scope (5 capabilities):**

1. **Live AWS mode.** Wire real boto3 calls against a sandbox AWS account. CI service container with LocalStack or real AWS sandbox. Same pattern as the F.5 LTREE live-CI proof — `charter-f3-live.yml` workflow. Deterministic eval cases with canned AWS responses stay in place for fast-feedback; live lane is additive.

2. **A.4 skill integration.** Add `nlah/skills/` directory. Load skills at agent startup via `charter.nlah_loader.load_skill_metadata_index()`. Register as a skill consumer — F.3 is the first non-A.4 agent to load A.4-created skills. Ship 2-3 operator-curated bundled skills (e.g., `cloud-posture/s3-public-bucket-remediation/SKILL.md`, `cloud-posture/iam-overprivileged-role/SKILL.md`).

3. **Multi-region scanning.** v0.1 hardcoded `us-east-1`. v0.2 scans all 23 AWS regions (configurable via `--regions` CLI flag; defaults to all commercial regions, excludes GovCloud/China unless opted in).

4. **Skills as procedural memory.** When A.4 deploys a skill to F.3's NLAH, F.3 picks it up on next run. The skill augments the system prompt with domain-specific procedural knowledge. This is the Hermes N1 pattern in production — the progressive-disclosure loader keeps the system prompt lean (Level 0 metadata index) and loads full SKILL.md content (Level 1) only when the task matches.

5. **Eval suite extension.** 5 new cases: (a) live-AWS smoketest (b) multi-region scan coverage (c) skill-loaded changes agent behavior (d) empty skills dir → backwards-compat (e) A.4-deployed skill → F.3 loads and uses it.

**Estimated tasks:** 12-14 (following the A.4 v0.2 16-task template, minus substrate/CDRI touches).

**Substrate work:** None. Agent-local only. `charter.nlah_loader` v1.4 already shipped.

**Dependencies:** A.4 v0.2 (closed). No other agents.

### §4.2 multi-cloud-posture v0.2

**Current v0.1 state:** Azure + GCP CSPM. 10 eval cases (stub cloud responses). Parallel to F.3's AWS pattern. Self-claims D.5 in README (ID overlap — resolve in v0.2 Task 1).

**v0.2 scope:**

1. **Live Azure/GCP mode.** Wire real Azure SDK + GCloud SDK against sandbox accounts. Same live-CI pattern as F.3 v0.2.
2. **A.4 skill integration.** Same pattern as F.3 v0.2 — `nlah/skills/`, progressive-disclosure loading, bundled skills.
3. **ID namespace resolution.** Rename self-claimed ID from D.5 to D.5a (or whatever the operator resolves). Update README, pyproject metadata.
4. **Cross-provider correlation.** v0.1 treats Azure and GCP as separate scans. v0.2 correlates: "this Azure VM's network security group and this GCP instance's firewall rule both expose port 22 to 0.0.0.0/0" — cross-cloud posture finding.
5. **Eval suite extension.** 5 new cases (live-Azure, live-GCP, cross-provider correlation, skill-loaded, backwards-compat).

**Estimated tasks:** 12-14.

### §4.3 k8s-posture v0.2.5

**Current state:** Already at v0.2 (live cluster API) and v0.3 (in-cluster mode). Has 21 test files — most tested agent in the fleet. Self-claims D.6 in README (ID overlap).

**v0.2.5 scope (minor version bump — already past v0.2):**

1. **A.4 skill integration.** Add `nlah/skills/`, progressive-disclosure loading. This is the ONLY missing piece from the v0.2 platform baseline.
2. **ID namespace resolution.** Rename self-claimed ID from D.6 to D.6a.
3. **Eval suite extension.** 2-3 new cases (skill-loaded, backwards-compat).

**Estimated tasks:** 5-7 (smallest wave entry — k8s-posture already did the heavy lifting).

### §4.4 Wave 1 sequence and timing

**Sequence within Wave 1:** F.3 v0.2 first (reference pattern) → multi-cloud-posture v0.2 second (inherits F.3's live-mode pattern) → k8s-posture v0.2.5 third (smallest, inherits both).

**Parallel opportunity:** F.3 v0.2 and multi-cloud-posture v0.2 are structurally independent (different cloud providers). Could be built in parallel if execution capacity allows, but ADR-011 discipline says sequential. F.3 first because it's the reference NLAH agent and the pattern-setter.

**Wave 1 completion criteria:**

- All 3 CSPM agents load skills via the v1.4 progressive-disclosure loader
- All 3 agents have `nlah/skills/` directories with 2-3 operator-curated bundled skills
- F.3 + multi-cloud-posture have live-CI workflows (k8s-posture already has them)
- A.4 can observe their complex runs and create candidate skills
- ID namespace resolved for multi-cloud-posture (D.5→D.5a) and k8s-posture (D.6→D.6a)

## §5. Wave 2 — Data + Compliance (D.5 data-security, D.6 compliance)

**Why second.** Data Security and Compliance are the next-most-orthogonal family. D.5 data-security reads from cloud storage APIs (S3, Azure Blob, GCP); D.6 compliance reads from D.5 + other detect agents. Building D.5 first gives D.6 material to work with.

### §5.1 D.5 data-security v0.2

**Current v0.1 state:** AWS S3 DSPM only (single-cloud). PII detection via agent-local regex. 10 eval cases (stub S3 inventory).

**v0.2 scope:**

1. **Live S3 scanning.** Wire real boto3 S3 calls against a sandbox AWS account with seeded test buckets (public bucket, encrypted bucket, bucket with PII, cross-account shared bucket).
2. **A.4 skill integration.** `nlah/skills/`, progressive-disclosure loading. Bundled skills for common DSPM patterns (e.g., `data-security/s3-public-bucket-remediation/SKILL.md`).
3. **Multi-cloud DSPM.** Extend beyond S3 to Azure Blob + GCP Storage (v0.1 was single-cloud per the sketch). Follows multi-cloud-posture v0.2's cross-provider pattern.
4. **PII/sensitive-data classifier upgrade.** v0.1 used agent-local regex. v0.2 adds ML-based classification (presidio or similar) as an agent-local tool — still not substrate (per the sketch's recommendation). Promote to `charter.data_classification` only if D.6 Compliance ends up needing the same classifier.
5. **Eval suite extension.** 5 new cases (live-S3, Azure Blob, GCP Storage, PII classifier accuracy, skill-loaded).

**Estimated tasks:** 12-14.

### §5.2 D.6 compliance v0.2

**Current v0.1 state:** Maps findings to CIS AWS Foundations v3 controls. 10 eval cases. Single-framework.

**v0.2 scope:**

1. **Live cross-source aggregation.** Read from real F.6 audit chain (findings from D.5, F.3, D.1, D.2). Produce a real compliance posture report. This is the first agent to consume cross-agent findings at runtime.
2. **Additional framework support.** Add SOC2, PCI-DSS, HIPAA control libraries. v0.1 was CIS-only; v0.2 covers the compliance frameworks enterprise buyers ask for.
3. **A.4 skill integration.** `nlah/skills/`, progressive-disclosure loading. Bundled skills for framework-specific mapping rules.
4. **Periodic posture reports.** A.4 Meta-Harness `run` can trigger D.6 to produce a compliance posture report as part of the cross-agent eval pipeline. This is the first cross-agent orchestration pattern — Supervisor isn't doing it; A.4 is.
5. **Eval suite extension.** 5 new cases (live-aggregation, SOC2 mapping, PCI-DSS mapping, HIPAA mapping, skill-loaded).

**Estimated tasks:** 12-14.

## §6. Wave 3 — Threat layer (D.3 runtime-threat, D.4 network-threat, D.8 threat-intel)

**Why third.** Threat agents are detection-heavy. They benefit from the CSPM live-mode patterns proven in Waves 1-2, and D.8 threat-intel correlates with D.3/D.4 findings.

### §6.1 D.3 runtime-threat v0.2

**v0.2 scope:** Live CWPP mode (Falco/Tracee/OSQuery against a kind cluster). A.4 skill integration. Eval suite extension.

**Estimated tasks:** 10-12.

### §6.2 D.4 network-threat v0.2

**v0.2 scope:** Live Suricata + VPC Flow Logs + DNS analysis against a sandbox VPC. A.4 skill integration. Eval suite extension.

**Estimated tasks:** 10-12.

### §6.3 D.8 threat-intel v0.2

**v0.2 scope:** Live CVE (NVD JSON feed) + MITRE ATT&CK (STIX) + CISA KEV correlation. A.4 skill integration. Eval suite extension.

**Estimated tasks:** 10-12.

**Wave 3 completion criteria:** All 3 threat agents in live mode + A.4 skill integration. D.8 correlates with live D.3/D.4 findings.

## §7. Wave 4 — Identity + Vulnerability (D.2 identity, D.1 vulnerability)

### §7.1 D.2 identity v0.2

**v0.2 scope:** Live CIEM mode (AWS IAM Access Analyzer + IAM policy simulation). A.4 skill integration.

**Estimated tasks:** 10-12.

### §7.2 D.1 vulnerability v0.2

**v0.2 scope:** Live CVE scanning (Trivy + OSV + NVD). A.4 skill integration.

**Estimated tasks:** 10-12.

## §8. Wave 5 — Smart layer (D.7 investigation, D.12 curiosity, D.13 synthesis)

**Why fifth.** Smart agents reason over findings from ALL detect agents. They need Waves 1-4 findings material to work with. This wave also delivers the remaining Hermes nectar items (N4, N6).

### §8.1 D.7 investigation v0.2

**v0.2 scope:**

1. **A.4 skill consumer (first-class).** D.7 is the agent that benefits MOST from A.4-created skills — investigation patterns are procedural, complex, and repeatable. D.7 v0.2 loads skills at startup and uses them during cross-agent correlation.
2. **Skill-driven investigation.** When D.7 loads an A.4-created skill like `investigation/iam-privesc-via-assume-role/SKILL.md`, it follows the procedural steps encoded in the skill. This is the Hermes N2 value proposition in production — institutional memory accumulating per-customer.
3. **Enhanced correlation.** Feed from all live detect agents (Waves 1-4). Cross-source correlation with skill-augmented reasoning.
4. **Eval suite extension.** 5 new cases (skill-loaded investigation, cross-source correlation with live findings, backwards-compat without skills).

**Estimated tasks:** 10-12.

### §8.2 D.12 curiosity v0.2

**v0.2 scope (N4 — per-customer behavioral baseline):**

1. **Per-customer baseline modeling.** Model normal behavior per customer organization (spending patterns, asset counts, finding frequencies, region coverage). Detect anomalies against baseline.
2. **Hypothesis refinement.** v0.1 emitted hypotheses over coverage gaps. v0.2 refines them with baseline context: "customer X normally has 200-300 S3 buckets but currently has 450 — investigate provisioning anomaly."
3. **A.4 skill integration.** Skills for common anomaly patterns.
4. **F.7 `claims.>` subject.** May require a new fabric subject for hypothesis claims — flagged in the remaining-agents sketch as a substrate decision. Resolve in the full plan.

**Estimated tasks:** 12-14.

### §8.3 D.13 synthesis v0.2

**v0.2 scope (N6 — cross-session search + LLM summary):**

1. **Cross-session search.** Query F.5 EpisodicStore for historical patterns: "have we seen this attack pattern before in this customer's last 90 days?"
2. **LLM summarization of search results.** Hermes N6 pattern — FTS5 search + LLM summarizes.
3. **A.4 skill integration.** Skills for common synthesis patterns.
4. **Surface track gate.** N6 is gated on S.1 Console OR S.3 ChatOps existing. If no surface exists at Wave 5 start, N6 defers to Wave 6 or later and D.13 v0.2 ships with A.4 integration + live mode only.

**Estimated tasks:** 10-14 (depending on N6 gate).

## §9. Wave 6 — Curator + Compliance reporting (A.4 v0.3, F.6 v0.2)

### §9.1 A.4 meta-harness v0.3 (Curator — N3)

**v0.3 scope:**

1. **N3 Autonomous Curator.** Stale/duplicate/failing skill pruning. Per Hermes: stale = not loaded in 90d, duplicate = >85% similarity, failing = <50% success rate. Operator-pinning for critical skills.
2. **Per-skill telemetry.** load_count, last_used, success_rate — net new work. A.4 v0.2 doesn't emit this.
3. **Curator reports.** Weekly janitor output — archive/consolidate/review candidates. Operator approves bulk actions.

**Estimated tasks:** 14-16. Requires its own full plan doc.

### §9.2 F.6 audit v0.2

**v0.2 scope:** Compliance reporting — produce audit-ready reports from the hash-chained audit log. Periodic compliance posture summaries. Integrate with D.6 compliance framework mappings.

**Estimated tasks:** 10-12.

## §10. Excluded agents — A.1 remediation, Supervisor #0

**A.1 Remediation** (v0.1 shipped 2026-05-16) is Phase 3 territory. It's the most safety-critical agent in the fleet — 9 primitives, Tier 1/2/3 authorization, promotion pipeline. v0.2 for A.1 means autonomous remediation (Tier 1 auto-approve), which requires:

- At least one wave of A.4 skill creation proving the eval-gate + operator-approval pattern works at scale
- Cross-agent trust model validation (can A.4's auto-deploy safety rails apply to A.1's execution safety rails?)
- Customer design-partner sign-off

**Do NOT start A.1 v0.2 in Phase 1.** Parked per the A.4 v0.2 plan's explicit exclusion.

**Supervisor #0** (v0.1 shipped 2026-05-21) is downstream of A.4 v0.2 introspection. v0.2 for Supervisor means:

- Routing decisions informed by A.4 scorecards ("which agent to use" when multiple can handle a task)
- Dynamic agent capability registry (today's routing table is static)
- Work decomposition improvements

But Supervisor's v0.1 AGENT_SPEC explicitly forbids analysis + NLAH evolution. v0.2 changes that contract — needs its own safety review. **Deferred to Phase 2.**

## §11. Cross-cutting invariants (every wave, every agent)

1. **One agent per plan.** Per ADR-011 — each agent's v0.2 gets its own full plan doc. No bundling across agents.
2. **Substrate sealed.** No `packages/charter/` or `packages/shared/` changes in Waves 1-6 unless explicitly flagged in the per-wave plan. The two SAFETY-CRITICAL substrate touches (Tasks 4 + 11 of A.4 v0.2) are it for Phase 1.
3. **A.4 integration is additive.** Every agent adds `nlah/skills/` + calls the v1.4 loader. Existing NLAH structure unchanged. Backwards-compatible — agent with empty skills dir behaves identically to v0.1.
4. **Live mode is additive.** Stub/synthetic eval cases stay in place for fast CI feedback. Live-CI workflows are additive lanes (same pattern as `charter-f5-live.yml`).
5. **WI-3 determinism holds.** Every agent's eval suite stays deterministic under stub responses. Live-lane tests are separate from the byte-equal probe.
6. **Single-tenant default.** `semantic_store=None` throughout. Multi-tenant production blocks on SET LOCAL `$1` fix.
7. **No `--force` anywhere.** Eval-gate mandatory. Operator approval mandatory for first-of-class skills. Same discipline as A.4 v0.2.
8. **Path-B breadth-first is retired.** Phase 1 (Maturity-First) operating rule is in effect. Each agent goes deep (v0.1 → v0.2) within its wave; the wave sequence ensures breadth across families.

## §12. What to build first

**Wave 1, F.3 cloud-posture v0.2.** The reference NLAH agent. Cleanest v0.1 → v0.2 path. Proves the "A.4 integration" pattern that every subsequent wave inherits. Establishes the live-CI workflow template.

After F.3 v0.2 closes → multi-cloud-posture v0.2 inherits the live-mode pattern. K8s-posture v0.2.5 inherits the A.4 integration pattern. By Wave 1 close, the CSPM family is fully integrated with the compounding learning loop.

**Write the F.3 v0.2 full plan doc next.** Start with the [brainstorming workflow](../../../.claude/plugins/cache/claude-plugins-official/superpowers/5.1.0/skills/brainstorming/) to collapse the scope, then the writing-plans skill for the implementation plan.

---

## Appendix A — Agent ID namespace resolution

Per the remaining-agents sketch §"Important note up-front":

| Existing package      | Current README claim         | Resolution                       |
| --------------------- | ---------------------------- | -------------------------------- |
| `multi-cloud-posture` | "D.5; third Phase-1b agent"  | → D.5a (or operator-assigned ID) |
| `k8s-posture`         | "D.6; fourth Phase-1b agent" | → D.6a (or operator-assigned ID) |
| `data-security`       | D.5 (operator)               | Stays D.5                        |
| `compliance`          | D.6 (operator)               | Stays D.6                        |

Resolution applied in Wave 1 Task 1 for multi-cloud-posture and k8s-posture. The existing README D.5/D.6 references need updating.

## Appendix B — Hermes nectar status

| Nectar | Description                      | Lands in           | Status                 |
| ------ | -------------------------------- | ------------------ | ---------------------- |
| N1     | Progressive-disclosure NLAH      | A.4 v0.2           | **SHIPPED**            |
| N2     | Autonomous skill creation        | A.4 v0.2           | **SHIPPED**            |
| N5     | agentskills.io format            | A.4 v0.2           | **SHIPPED**            |
| N4     | Per-customer behavioral baseline | D.12 v0.2 (Wave 5) | Not started            |
| N6     | Cross-session search + LLM       | D.13 v0.2 (Wave 5) | Gated on Surface track |
| N3     | Autonomous Curator               | A.4 v0.3 (Wave 6)  | Not started            |

## Appendix C — References

- [A.4 Meta-Harness v0.2 plan](2026-05-22-a-4-meta-harness-v0-2.md)
- [A.4 Meta-Harness v0.2 verification](../../_meta/a-4-meta-harness-v0-2-verification-2026-05-23.md)
- [Hermes-pattern absorption](../../_meta/hermes-pattern-absorption-2026-05-22.md)
- [Remaining-agents sketch](../sketches/2026-05-20-remaining-agents-sketch.md)
- [Agent version roadmaps](../sketches/2026-05-20-agent-version-roadmaps.md)
- [ADR-007 Cloud Posture as reference agent](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)
- [ADR-011 PR-flow discipline](../../_meta/decisions/ADR-011-pr-flow-and-branch-protection-discipline.md)
