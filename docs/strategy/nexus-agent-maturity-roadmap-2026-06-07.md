# Nexus Agent Maturity Roadmap — Macro Strategic Plan (2026-06-07)

> **Role:** the single strategic source of truth that anchors every subsequent per-agent maturity cycle. Where Nexus is, where it's going, in what order, and honestly how far it is.

- **Status:** strategic anchor — **sequencing is proposed and operator-amendable**; calendars are **sustainable-cadence estimates, not deadlines**.
- **Grounded in:** [readiness report](../_meta/nexus-platform-readiness-2026-06-07.md) (PR #241) · [capability-vs-Wiz](../_meta/agent-capability-vs-wiz-2026-06-07.md) (PR #242) · [detection-maturity v0.1→v0.3](../_meta/agent-detection-maturity-v0-1-to-v0-3-2026-06-07.md) (PR #243) · [agent-version-roadmaps sketch](../superpowers/sketches/2026-05-20-agent-version-roadmaps.md) · per-agent verification records · the v0.2.5 cycle pattern (PR #240).
- **Operator-locked:** strict serial agent maturity (one agent at a time, no parallel cycles); v0.2.5 cadence discipline (per-task PRs, eval-gates, drift surfacing) applies to every cycle.

---

## Section 1 — Executive summary

**Today.** All 17 Wave-1 agents are shipped at **Level 1** (architecture proven, minimum scope, **offline-fixture** mode). Estimated **~56–60% weighted Wiz coverage** (corrected baseline was ~27%). Suites green; 17/17 eval-runners; OCSF v1.3 uniform.

**Target.** Every agent at **Level 3** (analyst-grade, live, deep) = **Platform v1.0**; then **Platform v2.0** (attack-path / probability / blast-radius layer); then **Platform v3.0** (cure breadth across detection domains); plus **2 net-new agents** (AppSec, AI-SPM/SaaS) required for full Wiz/CNAPP parity.

**Honest scope.** This is **multi-year serial work** (~2–3 years to full Platform v3.0 at sustainable side-project cadence). Detection maturity alone (v0.1→v0.3) reaches **~75–80%** Wiz coverage — _necessary but not sufficient_; the last ~20–25 points are the 2 net-new agents + the v2.0 graph, **not** detector tuning (per PR #243).

**This document is the per-cycle anchor:** each future agent cycle refines its own Level 2/3 scope in a dedicated brainstorm, but sequences and frames against this plan.

---

## Section 2 — Strategic framework (operator-locked)

### Per-agent maturity levels

- **Level 1 — architecture proven + minimum scope.** Current state of all 17. Offline/fixture, deterministic, narrow native rules, single-cloud-mostly.
- **Level 2 — live + breadth + multi-cloud.** Offline→live feeds; breadth expansion; multi-cloud where applicable. The single most demo-credible jump.
- **Level 3 — analyst-grade.** Agents reason like analysts; production-mature; deep (effective-permissions, reachability, cross-signal correlation, multi-store).

### Platform tiers

- **Platform v1.0 — all 17 agents at Level 3.** Mature detection across the roster.
- **Platform v2.0 — probability / attack-path / blast-radius layer.** Emerges on top of analyst-grade agents; needs security-graph substrate decisions (it is _not_ produced by per-agent maturity — PR #243 §3).
- **Platform v3.0 — cure breadth.** A.1 Remediation expanded beyond its 5 K8s classes to per-detection-domain actions (S3 fix, IAM patch, WAF block, JIT revoke, …) + the documented per-agent Tier-1 surfaces.

### Two net-new agents (no maturity ladder — they don't exist yet)

- **AppSec / IaC / secrets-in-code / SBOM-supply-chain** — Wiz weight **0.04**, currently 0%.
- **AI-SPM / SaaS posture (SSPM)** — Wiz weight **0.02**, currently 0%.

### Sequencing rule (locked)

**Strict serial.** One agent matures at a time, start to finish, before the next begins. No parallel cycles. (Substrate prerequisites — §4 — may be standalone cycles between agents.)

---

## Section 3 — Per-agent maturity roadmaps

Coverage %s per category trace the PR #243 trajectory (Level 1 = measured/cited; Level 2/3 = estimates). "Effort ~3 weeks" = a sustainable-cadence estimate per version step, **not** a commitment.

### Detection agents (11) — in recommended maturity sequence

#### F.3 Cloud Posture (Wiz weight: CSPM 0.35)

- **Level 1 today:** Prowler 5.x (AWS breadth) + 3 native boto3 checks (users-without-MFA, customer-managed `*:*` admin policy, S3 enrichment); LocalStack/offline; deterministic. 11 src / 87 tests / runbook ✅. CSPM category **84%** (shared row). Limits: AWS-only, no live continuous, no graph.
- **Level 2 plan:** live boto3 + AWS account autodiscovery. CSPM → ~90%. ~3 wks. Dep: **live-cloud credential/sandbox substrate (F.3 pioneers it)**.
- **Level 3 plan:** pattern breadth 700→1,200+; cross-account; Organizations/Control Tower. CSPM → ~95%. ~3 wks.
- **Wiz in category:** continuous agentless multi-cloud CSPM + config-graph. **Residual at L3:** the security-graph (v2.0); agentless scale.
- **Trajectory (CSPM):** 84% → ~90% → ~95%.

#### D.5 Multi-Cloud Posture (Wiz weight: shares CSPM 0.35)

- **Level 1 today:** Azure Defender + GCP SCC + Activity-log ingest (severity pass-through) + ~5 native GCP-IAM binding rules; offline JSON. 12 src / 170 tests / runbook ✅. Limits: offline, ~5 authored rules, no AWS (F.3 owns).
- **Level 2 plan:** live `azure-mgmt-security` + `google-cloud-securitycenter` + asset SDK. ~3 wks. Dep: per-cloud credential substrate (extends F.3's).
- **Level 3 plan:** OCI coverage; native-rule breadth. ~3 wks. Dep: OCI SDK.
- **Wiz in category:** full Azure/GCP/OCI/Alibaba CSPM. **Residual at L3:** Alibaba; rule depth.

#### D.6 K8s Posture (Wiz weight: shares CSPM 0.35 / KSPM)

- **Level 1 today + already ahead:** manifest 10-rule analyzer + kube-bench + Polaris; **live kubeconfig (v0.2) + in-cluster (v0.3) already shipped**. 14 src / 257 tests / runbook ✅.
- **Level 2/3 remaining:** rule-library expansion 10→100+ / full CIS-K8s Benchmark (its "v0.4"); admission-controller + RBAC inventory. ~3 wks each.
- **Wiz in category:** KSPM + admission + RBAC + image + runtime-graph. **Residual:** RBAC inventory, admission webhooks. _(Most-mature detection agent already.)_

#### D.1 Vulnerability (Wiz weight: 0.13 — biggest single lever)

- **Level 1 today:** Trivy container-image CVE + KEV/NVD-CVSS/EPSS/OSV enrichment; offline fixtures. 11 src / 103 tests / runbook ✅. Category **20%**.
- **Level 2 plan:** **live registry scanning** + image-pull-policy enforcement. → ~55% (biggest weighted jump on the board). ~3 wks. Dep: registry creds.
- **Level 3 plan:** malicious-package supply-chain detection. → ~65%. ~3 wks.
- **Wiz in category:** agentless vuln across VM/container/serverless/host + validated reachability. **Residual at L3:** host/VM/serverless **agentless** scanning; reachability. **Trajectory:** 20% → ~55% → ~65%.

#### D.2 Identity / CIEM (Wiz weight: 0.09)

- **Level 1 today:** AWS-IAM — overprivilege (attached `AdministratorAccess`), dormant (>90d), external-access (Access Analyzer; public CRITICAL/cross-account HIGH), MFA-gap; group-transitive admin. 10 src / 125 tests / runbook ✅. Category **30%**. Limit: attached-policy admin only (no inline/Condition/SCP/boundary).
- **Level 2 plan:** Azure AD/Entra. → ~50%. ~3 wks. Dep: Azure SDK substrate.
- **Level 3 plan:** GCP IAM + SAML/OIDC federation forensics + effective-permissions (simulator-in-loop). → ~70%. ~3 wks.
- **Wiz in category:** effective-permissions + identity-graph + lateral-movement, all clouds. **Residual at L3:** identity-graph; full effective-perms depth. **Trajectory:** 30% → ~50% → ~70%.

#### D.3 Runtime Threat / CWPP (Wiz weight: 0.09)

- **Level 1 today:** Falco + Tracee + OSQuery + Wazuh-FIM → 5 families (process/file/network/syscall/osquery); Linux/eBPF; JSONL fixtures. 11 src / 135 tests / runbook ✅. Category **50%**.
- **Level 2 plan:** Windows CWPP; live Falco gRPC. → ~65%. ~3 wks. Dep: Windows-eBPF substrate decision.
- **Level 3 plan:** macOS; full ATT&CK; cloud-event correlation. → ~70%. ~3 wks.
- **Wiz in category:** runtime sensor + agentless, Linux+Windows + cloud-event join. **Residual at L3:** agentless workload; cloud-event depth. **Trajectory:** 50% → ~65% → ~70%.

#### D.4 Network Threat (Wiz weight: 0.04)

- **Level 1 today:** 3 native detectors (port-scan, C2-beacon-CoV, DGA-entropy) + Suricata lift + static intel (16 domains / 12 IP-CIDRs / 10 Tor-CIDRs); offline Suricata/VPC-flow/DNS. 13 src / 207 tests / runbook ✅. Category **80%**.
- **Level 2 plan:** live `describe_flow_logs` + S3→Athena; live IOC (needs D.8 live). → ~90%. ~3 wks.
- **Level 3 plan:** Tor detection; cross-window beacon baselines. → ~92%. ~3 wks. Dep: **TimescaleDB substrate**.
- **Wiz in category:** network **exposure-path graph** (different flavor). **Residual at L3:** the exposure graph (v2.0). **Trajectory:** 80% → ~90% → ~92%.

#### D.8 Threat Intel (Wiz weight: 0.03)

- **Level 1 today:** 3 offline feeds (NVD/KEV/MITRE); correlators (CVE×KEV, IOC×network, IOC×runtime); **IOC index CVE-only**. 16 src / 231 tests / runbook ❌. Category **25%**.
- **Level 2 plan:** live HTTP + MISP/STIX-TAXII + abuse.ch/VirusTotal (populates IP/domain/hash IOCs — unblocks D.4/D.3/D.7 correlation). → ~55%. ~3 wks.
- **Level 3 plan:** active-campaign tracking. → ~60%. ~3 wks.
- **Wiz in category:** integrated TI + exploitability across the graph. **Residual at L3:** graph-integrated exploitability. **Trajectory:** 25% → ~55% → ~60%.

#### Data Security / DSPM (Wiz weight: 0.07)

- **Level 1 today:** 4 S3 detectors (public/unencrypted/sensitive-location/oversharing) + 7-label regex/Luhn classifier; AWS-S3, operator-staged samples. 15 src / 262 tests / runbook ✅. Category **25%**.
- **Level 2 plan:** live boto3 + classifier expansion (DOB/address/healthcare) + Macie cross-val. → ~40%. ~3 wks.
- **Level 3 plan:** RDS + DynamoDB + RDS-snapshot scanning; AWS-native classifier API. → ~55%. ~3 wks.
- **Wiz in category:** DSPM across many stores + ML classify + data-flow graph + toxic-combination. **Residual at L3:** multi-store breadth, ML, toxic-combination. **Trajectory:** 25% → ~40% → ~55%.

#### Compliance (Wiz weight: shares Compliance/Audit 0.04)

- **Level 1 today:** CIS-AWS v3, **12 of 43 controls wired**, FAIL-only; correlates F.3 + DSPM findings. 14 src / 207 tests / runbook ❌. Category row **100%** (saturated by the audit substrate; framework breadth is the real gap).
- **Level 2 plan:** SOC2 / PCI-DSS / HIPAA / NIST 800-53 + PASS attestation export + `findings.>` subscribe. ~3 wks.
- **Level 3 plan:** continuous drift detection. ~3 wks. Dep: **TimescaleDB**.
- **Wiz in category:** 100+ frameworks, continuous, multi-cloud. **Residual at L3:** multi-cloud framework mapping. _(Doc nit: README says 45 controls; file has 43, 12 wired.)_

#### F.6 Audit (Wiz weight: shares Compliance/Audit 0.04 — **Nexus-ahead**)

- **Level 1 today:** hash-chain tamper detection + 5-axis forensic query + NL→query. 11 src / 125 tests / runbook ✅. **Ahead of Wiz on integrity.**
- **Level 2/3 plan:** cross-tenant query-attempt alerting (L2); quarterly isolation harness + external-timestamp immutability proof (L3). ~3 wks each.
- **Wiz in category:** activity/audit search. **Residual:** none material.

### Investigation / reasoning agents (3) — Wiz comparison less direct (Nexus differentiator)

#### D.7 Investigation (CDR — Wiz weight: 0.06)

- **L1 today:** timeline reconstruction, IOC extraction (9 types), MITRE ATT&CK attribution (10 techniques), LLM hypotheses with evidence-validation, containment planning; OCSF 2005. **Already at v0.2** (fabric events). Category **85%**.
- **L2/L3:** IOC pivoting via D.8 (needs D.8 live); real-time triage; graph-grounded correlation (depends on v2.0). → ~88% → ~90%.
- **Wiz:** threat-center investigation over the security graph. **Nexus-different:** autonomous hypothesis generation is a differentiator; depth ceiling is graph-grounding (v2.0).

#### D.12 Curiosity (no direct Wiz analog)

- **L1 today:** exactly **1 detector** (region coverage-gap) + LLM hypotheses + probe directives; first `claims.>` publisher. **L2/L3:** more gap detectors (asset-type/time/severity/control) + consumer wire-up + live-LLM. Proactive hypothesis-hunting is **Nexus-unique** (no Wiz equivalent).

#### D.13 Synthesis (reporting — Wiz analog: dashboards/reports)

- **L1 today:** customer-facing narrative + executive summary across sibling workspaces; **no OCSF emit yet**. **L2/L3:** OCSF emit + findings-delta re-narration + fabric event + per-persona styling. **Residual vs Wiz:** no UI/dashboard (markdown only) — a Surface-track concern, not detection.

### Action / meta agents (3)

#### A.1 Remediation (Cure — sequenced into Platform v3.0)

- **L1 today:** 5 K8s patch classes (runAsNonRoot, resource-limits, RO-rootfs, imagePull-Always, disable-privesc); recommend/dry-run/execute modes; **detector-re-run rollback**; earned-autonomy promotion. 22 src / 415 tests. Category **50%**.
- **Maturity = Platform v3.0 breadth:** per-detection-domain actions (S3 fix, IAM patch/JIT-revoke, WAF block, bucket-public-block) + the ~7 documented per-agent Tier-1 surfaces. → ~65%+. Dep: WAF/IAM/Custodian action substrates.
- **Wiz:** guided + some auto-remediation. **Nexus-edge:** rollback rigor (re-run detector, inverse-patch).

#### A.4 Meta-Harness (self-optimization — no Wiz analog)

- **At v0.2.5** (closed PR #240). v0.3 = optimization closure (3 gates: prediction-sensitive reward, trace persistence, flag-flip). Self-optimization is **Nexus-unique**. Not a Wiz category. (Backgrounds to infrastructure after v0.3.)

#### Supervisor #0 (orchestration — no Wiz analog)

- **L1 today:** declarative no-LLM routing to 10 specialists + parallel dispatch + escalation + heartbeat. **L2/L3:** LLM routing, multi-agent planning, retries, scheduled cron. Platform-internal; not a Wiz category.

---

## Section 4 — Cycle execution sequence

**Recommended order (proposed; operator-amendable).** Rationale per agent in §3 + PR #241 §10.

0. **Substrate cycle (prerequisite): live-cloud credential/sandbox.** Pioneered by F.3 but used by every Level-2 agent — establish the pattern first (or fold into F.3's cycle as task 1).
1. **F.3 Cloud Posture** — reference agent (max pattern reuse) + heaviest weight (CSPM 0.35) + pioneers the live-cloud substrate.
2. **D.1 Vulnerability** — biggest single weighted lever (0.13 @ 20% → live registry).
3. **D.2 Identity** — CIEM (0.09); reuses live-cloud substrate; unblocks lateral-movement story.
4. **D.5 Multi-Cloud Posture** — extends CSPM to Azure/GCP live (reuses credential substrate).
5. **D.8 Threat Intel** — live feeds; **unblocks D.4/D.7 correlation** (dependency multiplier).
6. **D.4 Network Threat** — live flow + now-live IOC from D.8.
7. **D.3 Runtime Threat** — Windows CWPP (own substrate decision).
8. **Data Security / DSPM** — live boto3 + classifier expansion.
9. **Compliance** — multi-framework (consumes the now-richer detection findings).
10. **D.6 K8s Posture** — rule-breadth expansion (already live; lower urgency).
11. **F.6 Audit** — cross-tenant alerting (already ahead; lowest urgency).
    12–14. **Investigation / Curiosity / Synthesis** — Level 2/3 (D.7 wants D.8 live first).

**Substrate prerequisites flagged inline:**

- **Live-cloud credential/sandbox** — universal Level-2 unblocker (step 0/1).
- **SET LOCAL tenant-RLS fix** — multi-tenant blocker affecting all; standalone substrate cycle when multi-tenant is needed.
- **TimescaleDB** — D.4 cross-window baselines + Compliance drift (Level 3).
- **Per-cloud credential store** (F.4 extension) — D.5 live SDK.
- Net-new action substrates (WAF/IAM/Custodian) — Platform v3.0.

**Calendar (sustainable-cadence estimates — NOT deadlines):**

- Per agent-version step: **~3 weeks** (extrapolated from v0.2.5 cadence).
- All 11 detection agents to Level 3 (serial): **~9–12 months**.
- Investigation/Action agents to Level 2/3: **+~3–6 months**.
- **Platform v1.0 (all 17 at Level 3): ~12–18 months.**

---

## Section 5 — Platform v2.0 + v3.0 + net-new agents

**Platform v2.0 — probability / attack-path / blast-radius.**

- Starts **after** detection is at Level 3 (analyst-grade findings are the inputs).
- Substrate (per PR #241 §4): a graph-substrate **decision** (reconcile Neo4j vs Postgres SemanticStore), attack-path traversal semantics (the current depth-3 BFS is generic, not attack-aware), a graph-wide exposure/probability model, OCSF finding-chaining. **Greenfield modeling + partly blocked behind the tenant-RLS bug.**
- Needs its own brainstorm/ADR. Estimate: **~2–3 month dedicated cycle**.

**Platform v3.0 — cure breadth.**

- Starts **after** v2.0 (operator may later allow partial overlap).
- A.1 expansion beyond 5 K8s classes → per-detection-domain actions + the ~7 documented per-agent Tier-1 surfaces; ChatOps approval surface. The cure _substrate_ (approval gates, dry-run, detector-re-run rollback, earned-autonomy) **already exists** (PR #241 §5) — this is breadth, not foundation. Estimate: **~3–6 months**.

**Net-new agents (for Wiz/CNAPP parity).**

- **AppSec / IaC / secrets-in-code / SBOM-supply-chain** (0.04) — new v0.1 cycle (~3–4 wks architecture + minimum scope).
- **AI-SPM / SaaS posture (SSPM)** (0.02) — new v0.1 cycle (~3–4 wks).
- **Sequencing TBD** — could precede v2.0/v3.0 (close the two zero-categories) or follow (operator decides nearer the horizon). They're ~6% of Wiz weight but table-stakes for a "full CNAPP" claim.

**Full Platform v3.0 + net-new + parity: ~2–3 years at sustainable cadence (estimate).**

---

## Section 6 — Honest scope realities

**What this plan IS:** an empirically-grounded macro roadmap (PR #241/#242/#243 source data); the operator-locked strategic framework; the per-cycle anchor; decisive sequencing with room for operator amendment.

**What it is NOT:** a deadline commitment (sustainable cadence, not date-driven); parallel work (strict serial preserved); Wiz-replication (Nexus differentiates on **Cure + the analyst/agentic loop + edge architecture**); final (each agent's Level 2/3 scope is refined in its own brainstorm).

**Honest acknowledgments:**

- **Multi-year** (~2–3 years to full Platform v3.0).
- **Side-project capacity** governs cadence; calendars flex.
- **Priorities may shift** — design-partner pressure could reorder the queue (e.g. pull a net-new agent forward).
- **Estimates are estimates** — coverage %s past Level 1 are projections; no post-Level-2 measured snapshot exists.
- **Two structural truths from PR #243:** detection maturity caps near ~75–80% Wiz; the rest is _net-new agents + the v2.0 graph_, not detector tuning.
- **Known blocker:** the SET LOCAL tenant-RLS bug gates multi-tenant + the v2.0 SemanticStore-as-graph path.

---

## Section 7 — References + cross-links

- **PR #241** — [Platform readiness report](../_meta/nexus-platform-readiness-2026-06-07.md) (current-state inventory, Wiz coverage, substrate readiness, first-agent rec).
- **PR #242** — [Agent capability vs Wiz](../_meta/agent-capability-vs-wiz-2026-06-07.md) (per-agent concrete capability vs Wiz).
- **PR #243** — [Detection maturity v0.1→v0.3](../_meta/agent-detection-maturity-v0-1-to-v0-3-2026-06-07.md) (trajectory + the "necessary but not sufficient" verdict).
- **PR #240** — [v0.2.5 verification record](../_meta/a-4-meta-harness-v0-2-5-verification-2026-06-07.md) (the cycle-execution pattern this plan reuses).
- [agent-version-roadmaps sketch](../superpowers/sketches/2026-05-20-agent-version-roadmaps.md) — per-agent v0.1→terminal trajectories.
- [ADRs 001–012](../_meta/decisions/) · per-agent verification records under [`docs/_meta/`](../_meta/).

> **After approval, this is ground truth for every per-agent cycle.** Each cycle: brainstorm (refine that agent's Level 2/3 scope) → plan → serial execution per v0.2.5 discipline → verification record → advance the trajectory number here.
