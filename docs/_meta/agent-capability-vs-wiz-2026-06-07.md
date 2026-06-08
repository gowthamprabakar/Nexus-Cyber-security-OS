# Agent Capability vs Wiz — Concrete Detection Accounting (2026-06-07)

> **Plain question:** can the 17 Nexus agents detect everything Wiz detects today?
> **Plain answer: No.** Evidence below — per agent, what we actually detect vs what Wiz covers in that category, the delta, and the work to close it.

- **Method:** read-only. The Nexus column is grounded in **actual eval cases (what's tested = what's real), detector modules, and READMEs** — not architecture or roadmaps. The Wiz column is industry-known capability. No maturity-level theorizing; concrete capability only.
- **One structural fact up front:** most posture/workload agents are **offline, deterministic, scanner-wrapping** in v0.1 (they ingest Prowler/Defender/SCC/kube-bench/Polaris/Trivy/Falco output and normalize to OCSF). Agent-_native_ detection logic is small and enumerable; _breadth_ is delegated to the wrapped tool and runs only against offline fixtures.

---

## The plain answer + why not

**No — the 17 agents do not match Wiz's detection coverage today.** Five concrete reasons, each evidenced per-agent below:

1. **Everything runs offline / on fixtures.** No agent does live, continuous detection in v0.1. Wiz is continuous + agentless against live cloud. (Every agent README: "offline / operator-staged / LocalStack".)
2. **AWS-mostly.** Deep coverage is AWS; Azure/GCP are thin pass-throughs (D.5) or absent (D.2 identity, DSPM); OCI/Alibaba absent. Wiz is full multi-cloud.
3. **Whole categories are 0.** **AppSec / code / IaC / secrets-in-code / CI** = no agent. **AI-SPM / SaaS posture** = no agent. Wiz covers all of these.
4. **No security graph / attack paths / toxic combinations.** This is Wiz's signature, and Nexus's is unbuilt (v2.0; generic depth-3 BFS exists, no attack-path semantics). Today Nexus emits _individual_ findings; it does not compute exposure paths or toxic combinations.
5. **Native rule breadth is small.** Agent-authored rules total roughly: F.3 ~3 boto3 checks, D.5 ~5 GCP-IAM rules, D.6 10 manifest rules, D.2 4 IAM families, DSPM 4 S3 detectors + 7 PII labels, D.4 3 detectors, compliance 12 wired CIS controls. Prowler/Trivy/etc. supply more breadth, but offline + AWS only.

**Where Nexus is at/near parity or is genuinely different (not behind):**

- **Immutable hash-chained audit + tamper detection (F.6)** — a Nexus-native strength; Wiz does not center this.
- **Remediation with detector-re-run rollback (A.1)** — in its narrow 5-class K8s slice, the _rollback rigor_ (re-run the detector, inverse-patch if it still fires) is strong.
- **The agentic detect→investigate→cure→self-optimize loop** (D.7 hypotheses, D.12 gap-hunting, D.13 narration, A.1 cure, A.4 skill self-optimization) — a different architecture than Wiz's platform; it's Nexus's differentiator, but it is _reasoning/ops_, not detection-coverage.

---

## Per-agent capability vs Wiz

### Posture / CSPM

**F.3 Cloud Posture** — _detects today:_ AWS misconfigs via **Prowler 5.x** (breadth) + 3 native boto3 checks (users-without-MFA, customer-managed admin `*:*` policy, S3 bucket enrichment); eval-pinned: public S3, IAM-no-MFA, unencrypted RDS, SG `0.0.0.0/0:22`, no multi-region CloudTrail, root-no-MFA, KMS no-rotation, admin policy, shared RDS snapshot, unencrypted EBS. _Wiz:_ continuous agentless CSPM, thousands of rules across AWS/Azure/GCP/OCI/Alibaba, config-graph. _Delta:_ live+continuous; multi-cloud; agentless scale; the graph. _Close:_ v0.2 live boto3 + account autodiscovery; pattern breadth 700→1,200+.

**D.5 Multi-Cloud Posture** — _detects today:_ Azure Defender + GCP SCC findings (severity pass-through) + Azure Activity-log classification + **~5 native GCP-IAM binding rules** (allUsers/allAuthenticated impersonation, external owner/editor). Offline JSON snapshots. _Wiz:_ full Azure/GCP/OCI CSPM, native rule libraries, continuous. _Delta:_ live SDK; rule breadth (we pass through scanner output, author ~5 rules); AWS handled separately. _Close:_ live `azure-mgmt-security` / `google-cloud-securitycenter` / asset SDK.

**D.6 K8s Posture** — _detects today:_ kube-bench (CIS-K8s) + Polaris ingest + **10 native manifest rules** (run-as-root, privileged, hostNetwork/PID/IPC, privesc, missing-limits, imagePull, RO-rootfs, SA-token). Live kubeconfig path exists (v0.2/0.3). _Wiz:_ KSPM + admission + image + RBAC + runtime-graph. _Delta:_ RBAC inventory, admission webhooks, Helm, rule breadth to full CIS Benchmark. _Close:_ rule expansion + admission-controller.

**Compliance** — _detects today:_ nothing native — **correlates** sibling findings (F.3 + DSPM) to **12 of 43 wired CIS-AWS-v3 controls**, FAIL-only. _Wiz:_ 100+ frameworks (SOC2/PCI/HIPAA/NIST/ISO/CIS multi-cloud), continuous, PASS+FAIL attestation. _Delta:_ 1 framework, partial wiring, no PASS attestation. _Close:_ SOC2/PCI/HIPAA/NIST + PASS export + more correlators. _(Doc nit: README says "45 controls"; bundled file parses to 43.)_

### Identity / CIEM

**D.2 Identity** — _detects today:_ 4 AWS-IAM families — overprivilege (attached `AdministratorAccess`), dormant (>90d), external-access (Access Analyzer: cross-account HIGH / public CRITICAL), MFA-gap on admins; group-transitive admin. _Wiz:_ full CIEM — effective-permissions across AWS/Azure/GCP, identity graph, lateral-movement, secrets→identity, inline+SCP+boundary eval. _Delta:_ effective-permissions (we do attached-policy admin only — no inline/Condition/SCP/boundary), multi-cloud, identity graph. _Close:_ simulator-in-loop effective perms; Azure AD/Entra; GCP IAM.

### Data / DSPM

**Data Security (DSPM)** — _detects today:_ 4 S3 detectors (public bucket, unencrypted, sensitive-in-untrusted-location, oversharing IAM policy) + a **regex/Luhn classifier with 7 PII labels** (AWS key, JWT, SSN, credit-card, email, US phone, API token), AWS-S3 only, operator-staged samples. _Wiz:_ DSPM across many stores (S3/RDS/Redshift/Azure/GCP/etc.), ML classifiers, data-flow + access graph. _Delta:_ one store, regex-only (no ML), US-only, sample-based. _Close:_ live boto3, classifier expansion, RDS/DynamoDB, Azure/GCP, Macie cross-val.

### Workload / CWPP + Vulnerability

**D.1 Vulnerability** — _detects today:_ **Trivy** container-image CVE scan + enrichment (CISA-KEV flag, NVD CVSS v3.1, FIRST EPSS, OSV OSS lookup), offline fixtures. _Wiz:_ agentless vuln across VMs/containers/serverless/hosts, full registry, validated/reachable exploitability, OS+app+lib. _Delta:_ container-image only, offline, no host/VM/serverless, no agentless reachability. _Close:_ live registry + host/VM scanning + reachability.

**D.3 Runtime Threat** — _detects today:_ normalizes **Falco + Tracee + OSQuery** into 5 families (process/file/network/syscall/osquery) — e.g. container shell-spawn, `/etc/shadow` read, Tor-exit connection, kernel-module load, orphan process. Linux/eBPF, JSONL fixtures. _Wiz:_ runtime sensor + agentless workload, Linux+Windows, cloud-event correlation. _Delta:_ live sensors, Windows, no cross-sensor dedup (→ D.7). _Close:_ live Falco gRPC; Windows Sysmon.

**D.4 Network Threat** — _detects today:_ **3 native detectors** (port-scan ≥50 ports/60s; C2 beacon via inter-arrival CoV; DGA via Shannon-entropy+bigram) + Suricata-alert lift + static-intel severity uplift (16 bad domains / 12 bad-IP CIDRs / 10 Tor CIDRs). Offline Suricata/VPC-flow/DNS. _Wiz:_ network exposure analysis (graph-based reachable-exposure paths) — a different flavor; Wiz is exposure-graph, Nexus is NDR-style forensic. _Delta:_ live capture; live IOC (needs D.8); exposure-path graph. _Close:_ live `describe_flow_logs`+Athena; live IOC; (exposure-path is v2.0).

**D.8 Threat Intel** — _detects today:_ correlation only — CVE×KEV (D.1), IOC×network (D.4), IOC×runtime (D.3); 3 offline feeds (NVD/KEV/MITRE); **IOC index is CVE-heavy, IP/domain/hash buckets ~empty in v0.1**. _Wiz:_ integrated TI + exploitability scoring across the graph. _Delta:_ live feeds (MISP/TAXII/abuse.ch/VT), populated IOC types. _Close:_ live HTTP polling + IOC feeds.

### Cloud Detection & Response / reasoning

**D.7 Investigation** — _does today:_ timeline reconstruction, IOC extraction (9 types), MITRE ATT&CK attribution (10 bundled techniques), LLM hypothesis generation with evidence-validation ("hallucinated refs dropped"), containment planning, parallel sub-agent spawn → OCSF 2005 incident report. _Wiz:_ threat-center investigation over the security graph. _Delta:_ graph-grounded investigation (we read sibling `findings.json`, not a graph); breadth of correlated signals. _Close:_ graph-backed correlation (v2.0).

**F.6 Audit** — _does today:_ **hash-chain tamper detection** (pins first break) + 5-axis forensic query (time/action/agent/correlation_id/tenant) + NL→query translation. _Wiz:_ activity/audit search. _Delta/edge:_ **Nexus-native strength** — immutable hash-chained audit with tamper proofs is stronger than typical CSPM audit search. Near/at parity, arguably ahead on integrity.

### Cure / ops / meta (not detection — included for completeness)

**A.1 Remediation** — _does today:_ **5 K8s patch classes** (runAsNonRoot, resource-limits, RO-rootfs, imagePull-Always, disable-privesc) in 3 modes (recommend/dry-run/execute) with **detector-re-run rollback**, blast-radius caps, earned-autonomy promotion. _Wiz:_ guided remediation + some auto-remediation, multi-domain. _Delta:_ K8s-only 5 classes (Wiz spans cloud/IAM/network); _edge:_ rollback rigor strong in-slice. _Close:_ WAF/IAM/Custodian action domains + the ~7 deferred per-agent Tier-1 actions.

**D.12 Curiosity** — _does today:_ **exactly 1 detector** (region coverage-gap) + LLM hypotheses + probe directives. _Wiz:_ n/a (proactive hypothesis-hunting is a Nexus-unique concept). _Delta:_ more gap detectors (asset-type/time/severity/control). Not a Wiz-comparable category.

**D.13 Synthesis** — _does today:_ customer-facing narrative + executive-summary reports across sibling workspaces (no OCSF emit yet). _Wiz:_ reporting/dashboards. _Delta:_ no UI/dashboard (markdown only).

**A.4 Meta-Harness** — _does today:_ cross-agent eval, scorecard-delta/regression flagging, A/B, **skill lifecycle** (trigger→compose→eval-gate→deploy) + **G1 effectiveness scoring + DSPy/GEPA** (default-OFF). _Wiz:_ n/a — self-optimization is Nexus-unique. Not a Wiz category.

**Supervisor** — _does today:_ declarative (no-LLM) routing to 10 specialists + parallel dispatch + escalation + heartbeat. _Wiz:_ n/a (platform orchestration). Not a Wiz category.

---

## Aggregated: category-by-category

**Parity / Nexus-ahead:**

- **Audit integrity** (F.6) — hash-chained tamper detection: Nexus-ahead.
- **Compliance/Audit substrate** — the _audit_ half is complete; framework _breadth_ is not (CIS-AWS only).
- **Remediation rollback** (A.1) — strong in the narrow K8s slice.

**Gaps (Nexus behind Wiz):**

- **CSPM** — breadth ok via Prowler but **offline + AWS-deep**; multi-cloud + continuous + graph missing.
- **CIEM** — attached-policy admin only; no effective-permissions, no multi-cloud, no identity graph.
- **CWPP/Vuln** — container-image only, offline; no host/VM/serverless/agentless; no Windows runtime.
- **DSPM** — one store, regex-only, US-only, sample-based.
- **Network exposure** — NDR-style forensic, not Wiz's exposure-path graph.
- **Threat intel** — offline feeds; IOC types sparse.

**Categories at 0 (entirely missing):**

- **AppSec / code / IaC / secrets-in-code / CI-CD scanning.**
- **AI-SPM** (AI model/pipeline posture).
- **SaaS posture (SSPM).**
- **Security graph / attack paths / toxic combinations** (Wiz's signature) — v2.0, unbuilt.

**Nexus-unique (no Wiz equivalent):**

- Autonomous **investigation hypotheses** (D.7), **curiosity gap-hunting** (D.12), **skill self-optimization** (A.4), and the **detect→cure with rollback** loop (A.1).

---

## Per-agent maturity standing (factual, from READMEs/roadmaps)

All at **v0.1** except A.4 (v0.2.5). Self-progression status: F.3/D.1/D.2/D.5/DSPM/D.8/compliance = **offline→live is the next step** (v0.2). D.6 k8s = already has a **live-cluster path** (v0.2/0.3). D.7 investigation = at **v0.2** (fabric events). A.1 = v0.1 with v0.1.1 earned-autonomy; Stage-4 unattended-execute globally closed in code. A.4 = **v0.2.5 closed**, default-OFF, three v0.3 optimization gates open. D.12/D.13/Supervisor = v0.1 producer/narrator/router with most behavior deferred to v0.2.

---

## Honest notes (discrepancies found)

- **Compliance control count:** README/runbook say "45 CIS controls"; the bundled `cis_aws_v3.yaml` parses to **43**, of which only **12 are wired** to a source rule. The other 31 can't produce a finding today.
- **Meta-harness README is stale:** it describes v0.1 (read-only, 5 capabilities); the shipped source + eval cases 11–25 + NLAH persona prove v0.2 (skill lifecycle) + v0.2.5 (DSPy/GEPA) are actually built.
- **"Breadth via wrapped tools" caveat:** F.3 (Prowler), D.1 (Trivy), D.6 (kube-bench/Polaris), D.3 (Falco/Tracee) inherit their tool's rule breadth — but only against **offline fixtures** in v0.1, so live breadth is unproven.

---

### Appendix — evidence

Per-agent capability gathered from `packages/agents/*/eval/cases/*.yaml` (tested capability), `*/src/**/detectors|checks|correlators|classifiers/*.py` (detection logic), and `*/README.md` + `*/src/**/nlah/README.md` (scope/deferrals), via 4 parallel read-only investigators. Wiz column = industry-known capability (not a repo source). Companion: [platform readiness report](nexus-platform-readiness-2026-06-07.md) (PR #241).
