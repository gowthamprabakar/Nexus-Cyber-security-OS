# DETAILED AGENT SPECIFICATION — PART 3 OF 4
## Compliance, Investigation, Threat Intel, Remediation Agents

**Continues from Parts 1 and 2.** Foundational concepts and cross-cutting specifications are in Part 1.

This part covers four specialists handling cross-cutting concerns. Compliance Agent maps every other agent's findings to regulatory frameworks. Investigation Agent orchestrates deep-dive incident response with sub-agent spawning (the most architecturally complex specialist). Threat Intel Agent provides external context to all detection agents. Remediation Agent is the action endpoint where every other agent's recommendations become reality through three-tier authority.

---

## 11. AGENT 7 — COMPLIANCE AGENT

### 11.1 Purpose

The Compliance Agent owns compliance framework mapping, audit evidence collection, control coverage reporting, and continuous compliance monitoring. It does not perform detection itself — it consumes findings from detection agents and maps them to applicable compliance controls across 100+ frameworks.

This agent operates differently from detection agents. Where Cloud Posture Agent runs every six hours producing findings, Compliance Agent runs daily for monitoring and on-demand for audit preparation. Its outputs are not findings — they are compliance status reports, evidence packages, gap analyses, and control coverage matrices.

The agent is the platform's connection to the regulatory world. When auditors arrive, this agent produces what they need. When customers face new regulations (NIS2, SEC cyber disclosure, state privacy laws), this agent maps existing platform capabilities to new requirements.

### 11.2 Hire test analog

Senior GRC analyst or compliance officer with seven-plus years of experience across multiple frameworks. Has supported customer audits as evidence provider. Has implemented compliance programs from scratch. Familiar with auditor expectations across SOC 2, HIPAA, PCI-DSS, ISO 27001, FedRAMP, vertical-specific frameworks. Understands the difference between technical controls and administrative controls. Knows when compensating controls are acceptable and when they aren't.

### 11.3 Capability scope

The Compliance Agent does not detect — it maps and reports. Its capability scope is:

#### 11.3.1 Framework coverage

The agent supports approximately 110 compliance frameworks at Phase 1 production launch:

**General security frameworks:**
- CIS Benchmarks (AWS, Azure, GCP, Kubernetes, Linux, Windows)
- NIST 800-53 Rev 5 (all control families)
- NIST Cybersecurity Framework 2.0
- NIST 800-171 (CUI protection)
- NIST 800-207 (Zero Trust Architecture)
- ISO/IEC 27001:2022
- ISO/IEC 27017 (cloud security)
- ISO/IEC 27018 (cloud privacy)
- SOC 2 Type II Trust Services Criteria
- COBIT 2019
- CIS Controls v8

**Privacy regulations:**
- GDPR (EU) — Article 32, 35 mappings
- CCPA/CPRA (California)
- PIPEDA (Canada)
- LGPD (Brazil)
- POPIA (South Africa)
- Privacy Act 1988 (Australia)
- PDPA (Singapore, Thailand)
- APPI (Japan)
- PIPL (China — for customers operating there)

**Financial sector:**
- PCI-DSS 4.0
- FFIEC Cybersecurity Assessment Tool
- NYDFS Part 500
- SOX (IT general controls)
- SWIFT Customer Security Programme (CSP)
- Basel Committee BCBS 239
- MAS Technology Risk Management Guidelines (Singapore)
- HKMA Cybersecurity Framework (Hong Kong)
- RBI Cyber Security Framework (India)
- FINMA (Switzerland)

**Healthcare:**
- HIPAA Security Rule (45 CFR §164.302-318)
- HIPAA Privacy Rule (relevant technical safeguards)
- HITECH
- HITRUST CSF v11
- 42 CFR Part 2 (substance abuse confidentiality)
- DEA Electronic Prescriptions (EPCS) requirements
- NHS Data Security and Protection Toolkit (UK)

**Government and defense:**
- FedRAMP Moderate baseline
- FedRAMP High baseline
- StateRAMP
- CMMC Level 1, 2, 3
- DoD Impact Level 2, 4, 5
- ITAR / EAR (export control adjacent)
- CJIS (criminal justice information)
- IRS Publication 1075 (federal tax information)

**Industry-specific:**
- NERC-CIP (electric utility)
- TSA Pipeline Security Directives
- TSA Surface Transportation Cybersecurity
- IEC 62443 (industrial control systems)
- API 1164 (pipeline SCADA)
- AWWA G430 (water utility)

**Cloud-specific frameworks:**
- AWS Well-Architected Framework (Security pillar)
- AWS Foundational Technical Review (FTR)
- Azure Cloud Adoption Framework
- Azure Well-Architected Framework
- Google Cloud Architecture Framework
- CSA Cloud Controls Matrix (CCM v4)
- CSA STAR

**International:**
- BSI C5 (Germany)
- BSI Grundschutz (Germany)
- IRAP (Australia)
- TISAX (German automotive)
- ENS High (Spain)
- IRAP PROTECTED
- Cyber Essentials Plus (UK)
- Cyber Essentials (UK)

**Emerging frameworks:**
- NIS2 Directive (EU)
- DORA (EU financial)
- SEC Cyber Disclosure Rules
- EU AI Act compliance (where applicable)
- EU Cyber Resilience Act

**Custom and internal:**
- Customer-defined frameworks (their internal policies as compliance frameworks)
- Industry consortium frameworks (ISAC standards)
- Insurance carrier requirements

#### 11.3.2 Detection capabilities

What the agent detects (in compliance terms):

**Compliance posture status:**
- Per-framework current control coverage
- Per-control current implementation status
- Gap identification (controls failing or partially implemented)
- Drift detection (controls degrading from previous baseline)

**Audit readiness:**
- Evidence completeness per control
- Evidence freshness (recently collected vs stale)
- Evidence quality (sufficient detail for auditor)
- Audit-blocking findings

**Compliance-impacting changes:**
- New findings that affect compliance posture
- Changes that improve compliance posture
- Changes that degrade compliance posture
- Predicted impact of pending remediations

**Regulatory change tracking:**
- Framework version updates (CIS 1.5 to 2.0 transitions)
- New requirements (NIS2 implementation deadlines)
- Vertical-specific regulatory changes

#### 11.3.3 Reporting capabilities

**Audit-ready reports:**
- Auditor evidence packages (control-by-control with evidence)
- Executive compliance summaries (board-level, 5-10 pages)
- Detailed compliance status reports (operational, monthly)
- Vertical-specific reports (HIPAA Security Rule report, PCI ROC support, SOC 2 evidence)
- Custom reports per customer requirement

**Continuous monitoring outputs:**
- Daily compliance score per framework
- Weekly compliance trend reports
- Monthly executive briefings
- Real-time alerts for compliance-blocking findings
- Quarterly comprehensive reviews

**Audit support outputs:**
- Auditor question/answer interface support
- Specific evidence retrieval
- Compensating control documentation
- Exception register management

### 11.4 Prevention level

The agent operates in process-focused, not real-time, prevention mode:

**Continuous compliance monitoring:**
Daily comprehensive evaluation of all subscribed frameworks. Drift detection. Trend analysis. Customer alerted when compliance posture degrades.

**Pre-audit preparation:**
Triggered by upcoming audit (customer's audit calendar). Comprehensive evidence collection 30-90 days before audit. Gap remediation prioritization.

**Compliance-as-policy enforcement:**
Recommendations for policy enforcement (admission controllers, IaC scanning rules, etc.) that prevent compliance violations before they reach production. Handoff to Cloud Posture Agent and Vulnerability Agent for implementation.

**Regulatory horizon scanning:**
Track regulatory changes in customer's verticals. Notify customer of upcoming requirements. Begin gap analysis early.

### 11.5 Resolution capability

**For compliance gaps:**
Generate gap analysis reports with specific remediation recommendations. Hand off to Remediation Agent for execution.

**For audit-blocking findings:**
Prioritize remediation based on audit timeline. Coordinate with relevant detection agents for verification after remediation.

**For evidence gaps:**
Request evidence collection from relevant detection agents. Coordinate timing for audit submission.

**For framework transitions:**
Generate migration plan from old framework version to new. Map controls across versions.

### 11.6 Three-layer description

#### 11.6.1 Backend infrastructure

**Knowledge base:**
- Framework definitions in structured YAML (110+ frameworks)
- Control-to-finding mappings (millions of mapping entries)
- Evidence requirement specifications per control
- Framework version transitions

**Reporting infrastructure:**
- PDF generation engine (ReportLab + custom templates)
- HTML report generation
- Excel/CSV export for auditor consumption
- Custom report template engine

**Compliance scanning:**
- Prowler compliance modules
- OpenSCAP for traditional compliance
- InSpec for compliance-as-code
- Custom compliance evaluators

**Evidence management:**
- Evidence locker with cryptographic signing
- Searchable evidence repository
- Evidence retention policies
- Auditor access portal

#### 11.6.2 Charter participation

Standard charter rules with these specifics:

**Privileges:**
- Can request evidence from any other specialist
- Can read findings store across all agents
- Higher budget allowance for comprehensive audit reports
- Can mark findings as "compliance-blocking" with elevated severity

**Restrictions:**
- Cannot implement controls (recommendations only — handoff to Remediation Agent)
- Cannot approve audit findings (advisory)
- Cannot modify framework definitions (compliance team only, signed updates)
- Cannot generate false evidence

#### 11.6.3 NLAH

Compliance Agent NLAH structure (full production approximately 1,400 lines). The structured natural language defining role, expertise, decision heuristics, stages, failure taxonomy, contracts required, and explicit prohibitions. Key sections:

- ROLE: Compliance and audit readiness specialist
- EXPERTISE: Major frameworks, industry-specific frameworks, audit methodology, mapping principles
- DECISION HEURISTICS: H1-H8 covering multi-control mapping, compensating controls, audit-blocking priority, customer calendars, proactive evidence, framework interpretability, version tracking, vertical-specific overrides
- STAGES: 7 stages — Inventory, Map (parallel across frameworks), Coverage, Gap Analysis, Evidence, Report, Handoff
- FAILURE TAXONOMY: F1-F6 covering version mismatches, ambiguous mappings, evidence failures, timeouts, outdated definitions, vertical ambiguity
- CONTRACTS YOU REQUIRE: Customer compliance subscriptions, audit calendar, framework versions, specialist access
- WHAT YOU NEVER DO: Implement controls, approve findings, generate false evidence, claim certifications, skip compensating controls
- PEER COORDINATION: Detailed handoffs to all detection agents, Audit Agent, Remediation Agent, Investigation Agent

### 11.7 Execution contract template

```yaml
contract_version: 1.0
contract_id: <UUID>
identity:
  source_agent: <delegating>
  target_agent: compliance
  customer_id: <UUID>
  trace_id: <UUID>

task:
  type: map_findings | generate_report | gap_analysis | continuous_monitoring | audit_preparation | regulatory_change
  scope:
    frameworks: array of framework_id
    time_range: <for reports>
    target_audit_date: ISO 8601 (for audit prep)
    report_format: pdf | html | json | csv
    report_audience: executive | operational | auditor | custom
    framework_versions: object (per-framework version)
  priority: emergency | urgent | normal | background

required_outputs:
  compliance_status:
    framework_id: string
    framework_version: string
    coverage_percentage: float
    controls_satisfied: array
    controls_partially_satisfied: array
    controls_failed: array
    controls_not_applicable: array
    controls_needs_review: array
    trend: enum [improving, stable, degrading]
    audit_blocking_findings: array
  reports:
    array of {report_id, framework_id, report_type, audience, file_path, signing}
  gap_analysis:
    framework_id: string
    audit_date: ISO 8601
    gaps: array of {control_id, gap_type, severity, remediation_effort, blast_radius, recommended_remediation}
    prioritization: array
  evidence_packages:
    array of {package_id, framework_id, control_id, evidence_items, signature, retention_until}

budget:
  max_llm_calls: 10
  max_tokens: 16000
  max_wall_clock_seconds: 300
  max_workspace_mb: 1000

permitted_tools:
  - map_finding_to_controls
  - generate_compliance_report
  - query_control_coverage
  - identify_control_gaps
  - query_compliance_history
  - request_evidence
  - update_compliance_status
  - load_framework_definition
  - validate_evidence
  - sign_evidence_package
  - generate_pdf_report
  - generate_html_report
  - record_audit

completion_condition: |
  All requested frameworks mapped (or partial with reason)
  AND requested reports generated
  AND gap analysis completed if requested
  AND evidence packages assembled if requested

workspace: /workspaces/<customer_id>/<contract_id>/compliance/
```

### 11.8 File-backed state schema

```
/workspaces/<customer_id>/<contract_id>/compliance/
  task.yaml
  framework_inventory.json
  mappings/
    <framework_id>_mappings.json
  coverage_analysis/
    <framework_id>_coverage.json
  gap_analysis/
    <framework_id>_gaps.json
  evidence/
    <control_id>/
      configuration_evidence.yaml
      log_evidence.json
      policy_evidence.yaml
      attestation_evidence.yaml
      screenshots/
  reports/
    <framework_id>_<audience>_<date>.pdf
    <framework_id>_<audience>_<date>.html
  reasoning_trace.md
  output.yaml

/persistent/<customer_id>/compliance/
  framework_subscriptions.yaml
  framework_versions.yaml
  audit_calendar.yaml
  certification_status.yaml
  exception_register.yaml
  compensating_controls.yaml
  custom_frameworks/
  historical_reports/
  evidence_archive/
  trend_data.jsonl

/persistent/global/compliance/
  framework_definitions/        # 110+ framework files in structured YAML
  framework_mappings.yaml       # cross-framework mapping
  framework_versions/           # historical versions for transitions
```

### 11.9 Self-evolution criteria

Compliance Agent harness rewrite triggered when:
- Auditor disputes findings > 5%
- Evidence collection failures > 10%
- Report generation time exceeds budget
- Customer requests new framework not yet supported

Framework definition updates are NOT self-evolution — they're explicit compliance team work, signed and deployed through normal release process.

### 11.10 Pattern usage declaration

**Primary patterns:** Parallelization (mapping across frameworks concurrently), Prompt chaining (overall flow)
**Secondary patterns:** Evaluator-optimizer (self-evolution)

### 11.11 Tools

13 tools in permitted_tools; full specifications in Tool Specification document.

### 11.12 Memory architecture

**Episodic:** Compliance evaluations history, audit history, evidence collection events
**Procedural:** Mapping effectiveness, customer report preferences, auditor preferences
**Semantic:** Customer's vertical, audit calendar, compensating controls, exception register

### 11.13 Inter-agent coordination

**Calls:** All detection agents (evidence requests), Audit Agent (evidence signing), Remediation Agent (gap remediation), Investigation Agent (compliance breach scenarios)
**Called by:** Supervisor, all detection agents (compliance impact mapping), customer (audit prep)

### 11.14 Wiz capability mapping

Maps to Wiz compliance reporting plus Wiz framework coverage. Wiz supports approximately 100 frameworks; we support 110+ at Phase 1. Coverage parity at Phase 1: approximately 95% of Wiz compliance capability. Stronger in vertical-specific frameworks (HITRUST, NERC-CIP, FFIEC).

### 11.15 Coverage progression

| Phase | Coverage | Notes |
|---|---|---|
| 1 | 95% | Production with 110+ frameworks |
| 2 | 96% | + Refined vertical specializations |
| 3 | 98% | + Newer regulations (DORA, EU AI Act) |
| 4 | 99% | Mature with self-evolution |

---

## 12. AGENT 8 — INVESTIGATION AGENT

### 12.1 Purpose

The Investigation Agent owns deep-dive incident investigation, root cause analysis, and evidence collection. It is the most architecturally complex specialist in the platform — the only specialist that uses orchestrator-workers pattern by spawning sub-investigation agents. It is invoked when other agents detect issues requiring deeper analysis than their domain scope permits.

This agent does not perform initial detection. Detection agents handle that. The Investigation Agent is invoked when:
- A confirmed runtime threat needs full incident response
- Multi-finding correlations suggest active attack
- Customer initiates an investigation
- Critical findings require deeper context
- Patterns appear that no single specialist can fully analyze

The orchestrator-workers complexity is intentional. Real incident investigations require parallel work streams: timeline reconstruction, IOC pivoting, asset enumeration, adversary attribution. These are best done as sub-agents that can work concurrently and feed results back to a parent investigation.

### 12.2 Hire test analog

Senior incident responder or DFIR analyst with ten-plus years of experience leading investigations. Has handled APT investigations under time pressure. Experienced with cross-source correlation across cloud, identity, network, runtime telemetry. Familiar with MITRE ATT&CK technique attribution, IOC pivoting methodology, and forensic preservation. Has written incident reports that withstood regulatory and legal scrutiny.

### 12.3 Capability scope

#### 12.3.1 Triage capabilities (Mode A)

Quick assessment of incoming alerts to determine investigation depth:
- Severity classification beyond initial alert
- Scope assessment (single asset, multiple assets, cross-environment)
- Investigation depth determination (light triage, medium investigation, deep investigation)
- Initial containment recommendation
- Stakeholder notification timing

#### 12.3.2 Deep investigation capabilities (Mode B)

Full DFIR with sub-agent orchestration:

**Timeline reconstruction:**
- Cross-source event correlation (cloud control plane, runtime, network, identity, application)
- Temporal sequencing
- Causality determination
- Branching timeline (different attack paths from same starting point)
- Reverse engineering (working backwards from impact to initial compromise)

**Asset enumeration:**
- All affected resources identification
- Lateral movement tracking
- Data access enumeration
- Identity compromise scope
- Network connection scope
- Process tree expansion

**IOC extraction and pivoting:**
- IOCs from initial detection
- IOC enrichment via threat intel
- IOC pivoting to find related compromised resources
- IOC validation (confirmed malicious vs noise)
- IOC sharing recommendations

**Adversary attribution:**
- TTP mapping to threat actor profiles
- Campaign correlation
- Confidence-based attribution (high/medium/low)
- Industry vertical targeting analysis
- Geopolitical context

**Root cause analysis:**
- Initial compromise vector identification
- Contributing factor identification
- Distinguishing root cause from symptoms
- Counterfactual analysis
- Failure mode classification

**Containment, eradication, recovery planning:**
Generate complete incident response plan with immediate containment, short-term containment, long-term containment, adversary access removal, persistence mechanism removal, credential rotation, configuration restoration, service restoration sequence, data integrity validation, identity recovery, network recovery, operational normalization criteria.

#### 12.3.3 Cross-incident analysis (Mode C)

Pattern detection across multiple incidents:
- Recurring attack patterns
- Repeated targeting of specific assets
- Trend analysis
- Coordinated campaign detection
- Detection rule effectiveness analysis

#### 12.3.4 Sub-agent orchestration

The agent spawns specialized sub-agents for parallel work streams:

**Investigation Timeline sub-agent:**
Specialized in event sequencing across heterogeneous data sources.

**Investigation IOC Pivot sub-agent:**
Specialized in indicator extraction and pivoting.

**Investigation Asset Enumeration sub-agent:**
Specialized in determining the full scope of affected resources.

**Investigation Attribution sub-agent:**
Specialized in adversary technique mapping and threat actor identification.

Each sub-agent has narrower scope, smaller context, focused tools — exactly the multi-agent architecture pattern applied recursively. Sub-agents cannot spawn further sub-agents (depth limit 1).

### 12.4 Prevention level

The Investigation Agent operates reactively but produces preventive value:
- Reactive containment recommendations
- Pattern-based prevention from cross-incident analysis
- Detection rule recommendations based on observed attacks
- Defensive recommendations (architectural, process, training, technology)

### 12.5 Resolution capability

The Investigation Agent generates investigation reports with executive summary, timeline, affected resources, adversary techniques mapped to MITRE ATT&CK, threat actor attribution with confidence, IOCs, root cause, contributing factors, containment plan, eradication steps, recovery validation criteria, lessons learned, defensive recommendations.

Hands off to Remediation Agent for execution, Cloud Posture Agent for architectural recommendations, Identity Agent for credential rotation, Network Threat Agent for network-level containment, Compliance Agent for regulatory reporting.

### 12.6 Three-layer description

#### 12.6.1 Backend infrastructure

**Investigation engines:**
- Timeline reconstruction engine (custom)
- Cross-source query engine (Elasticsearch/OpenSearch on aggregated logs)
- IOC extraction tools
- Forensic snapshot infrastructure integration
- Memory analysis tools (where snapshots available)

**Sub-agent orchestration:**
- Sub-agent spawn coordinator
- Sub-agent budget management
- Sub-agent result aggregation
- Sub-agent failure handling

**External intelligence:**
- VirusTotal API client
- AlienVault OTX client
- MITRE ATT&CK API
- Threat actor knowledge base
- Mandiant intelligence integration (where customer subscribed)

**Evidence preservation:**
- Forensic-grade evidence locker
- Hash chain for evidence integrity
- Auditor-accessible evidence portal
- Chain of custody tracking

#### 12.6.2 Charter participation

**Special privileges (most extensive of any specialist):**
- Can spawn sub-agents (only Investigation Agent and Supervisor have this privilege)
- Extended budget caps for deep investigations
- Forensic capture authority (always permitted, no authorization gate)
- Can request elevated read permissions for forensic purposes (with audit trail)
- Can preempt other agent work for incident response

**Restrictions:**
- Cannot take direct remediation actions (handoff to Remediation Agent)
- Sub-agent depth limit: 1 (sub-agents cannot spawn sub-agents)
- Maximum 4 sub-agents per investigation
- Must preserve evidence before any destructive recommendation
- Cannot conclude investigation without documented chain of evidence

#### 12.6.3 NLAH

Investigation Agent NLAH is the longest of all specialists at approximately 2,000-2,500 lines due to orchestrator-workers complexity. Key sections:

- ROLE: Incident investigator and DFIR lead with sub-agent orchestration
- EXPERTISE: NIST 800-61 IR methodology, SANS PICERL process, Diamond Model, Cyber Kill Chain, MITRE ATT&CK as analytical framework, forensic methodology, cross-source investigation, adversary attribution methodology, sub-agent orchestration
- DECISION HEURISTICS: H1-H8 covering timeline-first hypothesis-second, IOC pivoting, containment-before-investigation, real-time documentation, sub-agent decomposition, root cause vs contributing factors, confidence levels, multiple valid hypotheses
- OPERATING MODES: Mode A (Triage 5-min), Mode B (Deep investigation 10-min with sub-agents), Mode C (Cross-incident analysis 15-min)
- ORCHESTRATOR-WORKERS PATTERN: When to spawn sub-agents, sub-agent types and budgets, coordination pattern (parent determines, provides scope, sub-agents execute concurrently, parent synthesizes)
- STAGES Mode B: 9 stages — Scope, Preserve (forensic preservation immediate), Spawn, Sub-agent execution (parallel), Synthesize, Validate, Plan, Report, Handoff
- FAILURE TAXONOMY: F1-F7 covering sub-investigation budget, evidence preservation failure, contradicting hypotheses, root cause undetermined, sub-agent failures, threat intel unavailable, cascading findings
- CONTRACTS YOU REQUIRE: Forensic infrastructure, log access, threat intel, sub-agent capability, evidence locker
- WHAT YOU NEVER DO: Take remediation actions, skip evidence preservation, conclude without chain of evidence, allow sub-agents to escalate beyond scope, force single hypothesis when evidence supports multiple, overstate attribution confidence, skip Stage 2 (Preserve)
- PEER COORDINATION: Detailed handoffs to Remediation, Audit, Cloud Posture, Identity, Network Threat, Runtime Threat, Threat Intel, Compliance agents

### 12.7 Execution contract template

```yaml
contract_version: 1.0
contract_id: <UUID>
identity:
  source_agent: <delegating>
  target_agent: investigation
  customer_id: <UUID>
  trace_id: <UUID>

task:
  type: triage | deep_investigation | cross_incident_analysis | continued_investigation
  scope:
    incident_id: <UUID>
    initial_evidence: array
    severity: enum
    time_pressure: enum [routine, urgent, emergency]
    investigation_depth: light | medium | deep
    extended_from_investigation_id: <UUID, for continuations>
  priority: emergency | urgent | normal | background

required_outputs:
  investigation_report:
    report_id: UUID
    executive_summary: text (200-500 words)
    timeline: structured array of events
    affected_resources: structured (workloads, identities, data_stores, network_segments)
    adversary_techniques: array of {technique_id, evidence, confidence}
    threat_actor_attribution: {attributed_actor, confidence, alternatives, reasoning}
    iocs: structured (ips, domains, hashes, file_paths)
    root_cause: structured
    contributing_factors: array
  containment_plan:
    immediate_actions: array
    short_term_actions: array
    long_term_actions: array
    side_effects: array
    validation_criteria: array
  eradication_steps: array
  recovery_plan: structured
  lessons_learned: array
  defensive_recommendations: array
  sub_agent_outputs: object (timeline, ioc_pivot, asset_enumeration, attribution)

budget:
  max_llm_calls:
    triage: 5
    deep: 30          # extended for deep investigations
    cross_incident: 15
  max_tokens:
    triage: 8000
    deep: 60000
    cross_incident: 24000
  max_wall_clock_seconds:
    triage: 300
    deep: 600         # 10 minutes for deep
    cross_incident: 900
  max_sub_agents: 4
  sub_agent_budget: <inherited proportionally>
  max_workspace_mb: 1000

permitted_tools:
  - reconstruct_timeline
  - query_cross_source
  - extract_iocs
  - map_to_mitre
  - find_related_findings
  - enumerate_affected_resources
  - request_workload_snapshot
  - query_audit_trail
  - query_memory_dump
  - query_threat_intel
  - query_virustotal
  - query_otx
  - query_mitre_attack
  - request_runtime_action
  - request_network_block
  - request_identity_isolation
  - notify_compliance_agent
  - spawn_sub_agent
  - aggregate_sub_agent_results
  - sign_evidence
  - record_audit

spawnable_sub_agents:
  - investigation_timeline
  - investigation_ioc_pivot
  - investigation_asset_enumeration
  - investigation_attribution

completion_condition: |
  Triage: scope determined, containment recommendation made if applicable
  Deep: full report generated with all required sections
  Cross-incident: pattern analysis complete with recommendations

workspace: /workspaces/<customer_id>/<incident_id>/investigation/
```

### 12.8 File-backed state schema

```
/workspaces/<customer_id>/<incident_id>/investigation/
  task.yaml
  scope.yaml
  evidence_locker/                # immutable evidence preservation
    <evidence_id>_signed.zip
    chain_of_custody.jsonl
  sub_investigations/
    timeline/
      sub_task.yaml
      sub_workspace/
        timeline_data.json
      output.yaml
    ioc_pivot/
      sub_task.yaml
      sub_workspace/
        iocs_extracted.json
        iocs_enriched.json
        related_findings.json
      output.yaml
    asset_enumeration/
      sub_task.yaml
      sub_workspace/
        affected_resources.json
        scope_analysis.json
      output.yaml
    attribution/
      sub_task.yaml
      sub_workspace/
        ttp_mapping.json
        actor_correlation.json
      output.yaml
  synthesis.md                    # how sub-investigations integrate
  hypotheses.md                   # hypothesis tracking with evidence
  validation.md                   # what was confirmed vs uncertain
  containment_plan.yaml
  eradication_steps.yaml
  recovery_plan.yaml
  lessons_learned.md
  reasoning_trace.md
  full_report.md                  # final investigation report
  output.yaml

/persistent/<customer_id>/investigation/
  incident_history/               # past incidents with reports
    <incident_id>/
  attacker_patterns_observed.yaml
  recurring_indicators.yaml
  effective_containment.json
  detection_improvement_log.jsonl
```

### 12.9 Self-evolution criteria

Investigation Agent harness rewrite triggered when:
- Investigation accuracy disputed in postmortem > 10%
- Sub-agent spawning patterns leading to budget overruns
- Time-to-containment exceeding targets
- Hypotheses contradicting evidence (validation failures)
- Single-hypothesis bias in complex investigations

When triggered, Meta-Harness reads investigation traces (which include sub-agent traces — recursive trace structure), identifies orchestration or synthesis issues, proposes refinements (often around when to spawn sub-agents, sub-agent scope definitions, or synthesis logic). Eval suite includes 100+ historical investigation scenarios with known outcomes for validation.

### 12.10 Pattern usage declaration

**Primary patterns:** Orchestrator-workers (primary, spawns specialized sub-agents), Prompt chaining (within each sub-investigation and parent synthesis)
**Secondary patterns:** Evaluator-optimizer (self-evolution), Parallelization (sub-agents execute concurrently)

### 12.11 Tools

20 tools in permitted_tools plus sub-agent spawning capability; full specifications in Tool Specification document.

### 12.12 Memory architecture

**Episodic:** Investigation history with full reports, IOCs collected across investigations, containment effectiveness data
**Procedural:** Customer's incident response runbooks, validated IOCs from past investigations, customer-specific attacker patterns, effective containment strategies
**Semantic:** Customer's typical attack vectors, customer's threat model, customer's normal baseline (used to identify abnormal during investigation)

### 12.13 Inter-agent coordination

**Calls (Investigation coordinates broadly):** Remediation Agent (containment, eradication, recovery), Audit Agent (evidence package signing), all detection agents (evidence requests during investigation), Threat Intel Agent (ongoing intelligence updates), Compliance Agent (regulatory reporting requirements)

**Spawns (only Investigation can spawn):** Investigation Timeline sub-agent, Investigation IOC Pivot sub-agent, Investigation Asset Enumeration sub-agent, Investigation Attribution sub-agent

**Called by:** Supervisor (when complex incidents need investigation), all detection agents (when their findings warrant investigation), customer (manually-initiated investigations), Curiosity Agent (when proactive hypothesis warrants investigation)

### 12.14 Wiz capability mapping

Wiz has investigation capabilities but they're less developed than Wiz's detection. Wiz's investigation surface is primarily UI-driven dashboards rather than agentic investigation. Coverage parity at Phase 1: approximately 90% of Wiz investigation capability with significant differentiation through orchestrator-workers pattern that Wiz does not have.

### 12.15 Coverage progression

| Phase | Coverage | Notes |
|---|---|---|
| 1 | 90% | Production with full sub-agent orchestration |
| 2 | 92% | + Refined attribution capabilities |
| 3 | 95% | + Mature DFIR with extensive playbook library |
| 4 | 97% | Advanced cross-incident pattern detection |

---

(Continued in next file due to size — Threat Intel and Remediation agents follow.)
# DETAILED AGENT SPECIFICATION — PART 3B
## Threat Intel and Remediation Agents

**Continues from Part 3A.** Compliance and Investigation agents are in Part 3A. Read both as a single Part 3.

---

## 13. AGENT 9 — THREAT INTEL AGENT

### 13.1 Purpose

The Threat Intel Agent owns external threat intelligence ingestion, normalization, and correlation. It does not detect threats in customer environments — it provides external context to other detection agents. When Vulnerability Agent finds a CVE, Threat Intel Agent provides exploitation context. When Network Threat Agent sees a suspicious IP, Threat Intel Agent provides reputation. When Investigation Agent investigates an incident, Threat Intel Agent provides adversary attribution.

The agent runs continuously in background mode for feed ingestion (separate from heartbeat), and on-demand for queries from other agents. It maintains the platform's connection to the broader threat landscape.

### 13.2 Hire test analog

Senior cyber threat intelligence (CTI) analyst with eight-plus years of experience tracking threat actors, attribution, and campaign analysis. Has authored threat reports. Has used and contributed to multiple threat intelligence platforms (MISP, OpenCTI). Familiar with intelligence collection methodologies, source evaluation, and confidence assessment. Has mapped TTPs to threat actors with appropriate caveats about attribution confidence.

### 13.3 Capability scope

#### 13.3.1 Source ingestion

**Standards bodies:**
- MITRE ATT&CK (Cloud, Enterprise, ICS matrices)
- MITRE ATLAS (AI/ML-specific)
- MITRE D3FEND (defensive techniques)
- CSA Cloud Controls Matrix

**Government:**
- CISA Known Exploited Vulnerabilities (KEV)
- CISA Alerts feed
- NIST National Vulnerability Database (NVD)
- US-CERT advisories
- UK NCSC advisories
- ANSSI (France) advisories
- BSI (Germany) advisories

**Cloud-specific:**
- Wiz Cloud Threat Landscape (public RSS + STIX)
- AWS Security Bulletins
- Azure Security Bulletins
- GCP Security Bulletins

**Industry intelligence:**
- Unit 42 (Palo Alto) GitHub IOCs and reports
- CrowdStrike Global Threat Reports (public versions)
- Mandiant public reports
- Microsoft Threat Intelligence Center publications
- Cisco Talos publications
- Recorded Future public intelligence

**Community:**
- AlienVault OTX
- abuse.ch (URLhaus, ThreatFox, MalwareBazaar, FeodoTracker)
- VirusTotal Intelligence (subscription)
- GreyNoise (subscription where customer enabled)
- Shodan (where customer subscribed)

**Vertical-specific (ISACs):**
- FS-ISAC (financial services)
- H-ISAC (healthcare)
- E-ISAC (electricity)
- Auto-ISAC (automotive)
- Aviation-ISAC
- Multi-State ISAC (state and local government)
- Retail and Hospitality ISAC

**OSS vulnerability:**
- OSV (Open Source Vulnerabilities)
- GitHub Advisory Database
- npm Advisory Database
- PyPI vulnerability data
- RubyGems advisory database

**Custom customer-specific:**
- Customer-purchased intelligence feeds
- Customer's threat sharing agreements
- Customer's industry-specific intelligence

#### 13.3.2 Correlation capabilities

**Customer-environment correlation:**
- Match customer findings to active campaigns
- Identify which threat actors target customer's industry
- Track emerging techniques relevant to customer's tech stack
- Provide context on CVEs (who's exploiting them, when, against whom)

**IOC enrichment:**
- IP reputation and context
- Domain reputation and registration history
- File hash classification
- URL classification
- Cross-source IOC corroboration

**Campaign tracking:**
- Active campaign identification
- Campaign timeline
- Industry vertical targeting
- Geographic targeting
- TTP evolution within campaigns

**Threat actor profiling:**
- Known threat actor TTPs
- Threat actor motivations and capabilities
- Threat actor tooling
- Industry vertical preferences
- Sophistication assessment

#### 13.3.3 Briefing generation

**Briefing schedule:**
- Daily critical alerts (automated)
- Weekly industry threat summary (semi-automated)
- Monthly comprehensive briefing (with human curation in production team)
- Quarterly executive threat reports (heavily curated)

**Briefing content:**
- Active campaigns relevant to customer
- New threat actor activity
- Vertical-specific threats
- Recommended defensive priorities
- Notable incidents in customer's industry

### 13.4 Prevention level

**Predictive prevention:**
- Proactive notification when customer's industry is being targeted
- Pre-emptive rule deployment when new techniques emerge
- Contextual prioritization that elevates findings matching active campaigns

**Hunting recommendations:**
- Threat hunt suggestions based on emerging intelligence
- Retrospective hunting when new IOCs published
- Coordinated hunting with Curiosity Agent

### 13.5 Resolution capability

The Threat Intel Agent provides context, not action. Hand off to other agents:
- Vulnerability Agent — for active exploitation context on CVEs
- Network Threat Agent — for IP/domain reputation
- Runtime Threat Agent — for malware family information
- Investigation Agent — for adversary attribution support
- Customer (via supervisor) — for threat briefings

### 13.6 Three-layer description

#### 13.6.1 Backend infrastructure

**Ingestion infrastructure:**
- Apache Airflow DAGs for scheduled feed pulls
- STIX 2.1 parser
- TAXII feed clients
- Custom feed parsers per source format
- Feed deduplication and merging
- Feed integrity verification

**Storage:**
- Master knowledge graph in Neo4j (control plane)
- IOC database in PostgreSQL with TTL
- Full-text search via Elasticsearch
- Time-series storage for historical intel

**Correlation engine:**
- Customer environment fingerprinting
- Industry vertical mapping
- Tech stack profiling
- TTP correlation
- Confidence scoring

**Briefing infrastructure:**
- Briefing template engine
- Customer-specific briefing personalization
- Multi-channel delivery (email, ChatOps, dashboard)

#### 13.6.2 Charter participation

**Special privileges:**
- Continuous background ingestion (not heartbeat-driven)
- Ability to trigger urgent rule pack updates when critical CVE published
- Higher rate limits on feed queries during active intel updates

**Restrictions:**
- Cannot modify or delete intel from sources (read-only)
- Cannot generate fictional threat intel
- Cannot share customer-specific data with other customers
- Must maintain source attribution on all intel

#### 13.6.3 NLAH

Threat Intel Agent NLAH structure (full production approximately 1,200 lines). Key sections:

- ROLE: Cyber threat intelligence analyst with continuous ingestion, customer correlation, briefing generation
- EXPERTISE: Intelligence collection methodologies (OSINT, TECHINT, closed source, ISACs, government feeds), source evaluation, threat actor tracking (APT groups, cybercrime groups, hacktivists, nation-state actors), attribution methodology with confidence levels, intelligence lifecycle, cloud-specific threat patterns
- DECISION HEURISTICS: H1-H8 covering recency decay rates, industry-specificity, source confidence weighting, IOC reputation in context, customer tech stack relevance, attribution confidence assessment, urgent campaign distribution, intel overload avoidance
- OPERATING MODES: Mode A (Continuous ingestion always running), Mode B (Query response on-demand), Mode C (Briefing generation scheduled or on-demand), Mode D (Active correlation on detection events)
- STAGES Mode A (Ingestion): Poll (parallel across feeds), Normalize (to STIX 2.1), Dedup, Enrich (cross-feed), Graph (upsert to knowledge graph)
- STAGES Mode B (Query): Parse, Graph_Query, Contextualize (apply customer context), Respond
- STAGES Mode C (Briefing): Gather, Prioritize, Write, Deliver
- FAILURE TAXONOMY: F1-F5 covering feed unavailability, STIX parse errors, conflicting intel, missing customer data, knowledge graph update failures
- CONTRACTS YOU REQUIRE: Feed credentials, customer industry/tech stack, knowledge graph writable, briefing preferences
- WHAT YOU NEVER DO: Modify source intel, generate fictional intel, apply intel out of context, share customer data across customers, claim attribution without confidence, overwhelm with low-relevance intel
- PEER COORDINATION: Detailed handoffs to Vulnerability, Cloud Posture, Identity, Network Threat, Runtime Threat, Investigation, Synthesis agents

### 13.7 Execution contract template

```yaml
contract_version: 1.0
contract_id: <UUID>
identity:
  source_agent: <delegating>
  target_agent: threat_intel
  customer_id: <UUID>
  trace_id: <UUID>

task:
  type: ingest | query | correlate | brief | active_correlation
  scope:
    feeds: array (for ingest)
    query: string (for query)
    observed_techniques: array (for correlate)
    time_range: <for briefings>
    briefing_audience: enum
    briefing_format: enum
  priority: emergency | urgent | normal | background

required_outputs:
  ingest_results:
    records_ingested: int
    records_updated: int
    records_failed: int
    urgent_intel_published: array
  query_results:
    results: array of intel records
    confidence: float
    source_attribution: array
  correlation_results:
    matched_campaigns: array
    matched_threat_actors: array
    relevance_score: float
    attribution_confidence: enum
  briefing:
    report_content: text
    key_threats: array
    recommendations: array
    delivery_channel: array

budget:
  max_llm_calls: 6
  max_tokens: 12000
  max_wall_clock_seconds: 60
  max_external_api_calls: 200
  max_workspace_mb: 200

permitted_tools:
  - query_mitre_attack
  - query_mitre_atlas
  - query_mitre_d3fend
  - query_cisa_kev
  - query_wiz_landscape
  - query_unit42
  - query_abuse_ch
  - query_otx
  - query_virustotal
  - query_industry_feed
  - correlate_to_campaign
  - predict_targeted_industries
  - query_knowledge_graph
  - update_knowledge_graph
  - generate_threat_briefing
  - notify_critical_intel
  - record_audit

completion_condition: |
  Ingest: all configured feeds polled, results recorded
  Query: relevant intel returned with confidence and attribution
  Correlate: matches identified with confidence assessment
  Brief: briefing generated and delivered through preferred channel

workspace: /workspaces/<customer_id>/<contract_id>/threat_intel/
```

### 13.8 File-backed state schema

```
/workspaces/<customer_id>/<contract_id>/threat_intel/
  task.yaml
  query_results.json
  correlation_outputs.json
  briefing.md (if brief task)
  reasoning_trace.md
  output.yaml

/persistent/<customer_id>/threat_intel/
  industry_profile.yaml
  tech_stack_profile.yaml
  subscribed_feeds.yaml
  briefing_preferences.yaml
  correlation_history.jsonl
  briefing_history/
    <date>_<audience>_briefing.md

/persistent/global/threat_intel/    # not customer-specific
  master_graph_sync_status.json
  feed_health.json
  ingestion_log.jsonl
  source_reliability_scores.yaml
```

### 13.9 Self-evolution criteria

Threat Intel Agent harness rewrite triggered when:
- Correlation accuracy disputed > 10%
- Customer feedback that briefings miss relevant threats
- New feeds requested by customers not yet integrated
- Latency on real-time intel queries exceeds budget
- Specific feeds showing high error rates
- Customer downvotes briefings as too generic

### 13.10 Pattern usage declaration

**Primary patterns:** Parallelization (Mode A feed ingestion across many feeds concurrently), Prompt chaining (Mode B query response, Mode C briefing generation)
**Secondary patterns:** Routing (Mode A vs B vs C vs D dispatch), Evaluator-optimizer (self-evolution)

### 13.11 Tools

17 tools in permitted_tools; full specifications in Tool Specification document.

### 13.12 Memory architecture

**Episodic:** Recent intel ingested (last 90 days hot, 1 year warm), customer briefings sent, query history per customer
**Procedural:** Source reliability scores learned over time, customer-specific relevance patterns, briefing format effectiveness
**Semantic:** Customer's industry vertical, tech stack, geographic operations, regulatory environment

### 13.13 Inter-agent coordination

**Calls:** Synthesis Agent (for customer-facing briefings via supervisor)
**Called by (most agents):** Supervisor, all detection agents, Investigation Agent, Curiosity Agent

### 13.14 Wiz capability mapping

Wiz has threat intelligence integration but it's not their primary capability. We have stronger threat intelligence integration through dedicated agent and broader feed coverage. Coverage parity at Phase 1: approximately 95% of Wiz threat intel capability with significant superset in vertical-specific feeds.

### 13.15 Coverage progression

| Phase | Coverage | Notes |
|---|---|---|
| 1 | 95% | Production with 15+ feeds, customer correlation |
| 2 | 96% | + Industry-specific feeds depth |
| 3 | 98% | + Predictive correlation |
| 4 | 99% | Mature with self-evolution |

---

## 14. AGENT 10 — REMEDIATION AGENT

### 14.1 Purpose

The Remediation Agent owns action drafting and execution. It is the action endpoint for the entire platform. Every other agent's recommendations flow through Remediation Agent eventually. It implements the three-tier authority model: autonomous execution for narrow customer-authorized action classes (Tier 1), approval-gated execution for default actions (Tier 2), and recommendation-only output for high-blast-radius actions (Tier 3).

This agent has the highest blast radius of any agent in the platform — it is the only agent that modifies customer infrastructure directly. Every safety mechanism in the platform exists primarily to govern this agent's behavior. Its execution contracts have the strictest validation. Its self-evolution criteria include the strictest thresholds. Its audit logging is the most comprehensive.

### 14.2 Hire test analog

Senior security automation engineer or SOAR specialist with eight-plus years of experience automating security operations at scale. Has built remediation playbooks that operate in production. Has handled incidents where automation failed. Understands rollback strategies, blast radius assessment, and approval workflow design. Knows when to recommend autonomous action and when human judgment is required.

### 14.3 Capability scope

#### 14.3.1 Action drafting

The agent drafts complete remediation artifacts for every supported action type:

**Cloud Custodian policies:** Multi-cloud policy generation with built-in safety mechanisms and dry-run capability.

**Terraform diffs:** Maps production resources to Terraform state. Generates minimal diffs to address findings. Optionally creates pull requests in customer's source control for human review and merge.

**CloudFormation changesets:** Generates change sets with explicit before/after state. Validates against current stack state.

**Kubernetes manifest patches:** kubectl patch operations or kustomize overlays. Validates against admission policies before apply.

**ARM templates / Bicep:** For Azure-managed-via-IaC environments.

**Pulumi diffs:** For Pulumi-based IaC.

**AWS CDK changes:** For CDK-based deployments.

**Runbooks:** Step-by-step procedures with validation criteria per step. For complex multi-step remediations or human execution.

**IAM policy drafts:** Least-privilege replacement policies based on actual usage analysis (provided by Identity Agent).

**Network policy changes:** Security group modifications, NACL updates. Always Tier 2 or Tier 3 due to operational sensitivity.

**Database modifications:** Schema changes, permission grants/revokes, encryption enablement. Generally Tier 3 due to data integrity sensitivity.

#### 14.3.2 Three-tier remediation authority

**Tier 1 — Autonomous (customer pre-authorized for specific action classes):**

Initial action classes available for Tier 1 authorization:
- Rotate confirmed-leaked AWS access keys (single key blast radius)
- Disable public S3/Blob/Cloud Storage ACLs on data flagged sensitive (single bucket blast radius)
- Quarantine confirmed-malicious workloads (single workload blast radius)
- Block known-bad IPs at WAF (single IP, mandatory TTL up to 1 hour)
- Disable suspicious service accounts (single SA, with rollback)
- Revoke compromised user sessions (single user, with rollback)
- Apply specific patches in non-production environments (limited scope)
- Remove stale unused IAM users (with grace period)

Each Tier 1 action class:
- Customer opt-in only (default off)
- Defined blast radius limit
- Mandatory automatic rollback timer
- Rate-limited per class per hour
- Comprehensive audit trail
- Insurance partner credit eligible
- Customer kill switch for instant revocation
- Mandatory pre-execution dry-run if dry-run available
- Mandatory post-execution validation

**Tier 2 — Approval-Gated (Default):**

Default for most remediations. Process:
1. Agent generates complete remediation artifact (Cloud Custodian, Terraform, etc.)
2. Agent computes blast radius
3. Agent generates rollback plan
4. Agent submits to customer-configured approval channel
5. Customer reviews and approves (or rejects with reasoning)
6. Agent executes approved action
7. Agent validates outcome
8. Agent reports result through approval channel

**Tier 3 — Recommend-Only (High Blast Radius):**

Always Tier 3 by default:
- IAM policy modifications affecting more than 10 users
- Production database schema modifications
- Network configuration changes affecting more than 25% of traffic
- Cross-region replication changes
- Encryption key rotations
- Authentication system modifications
- Backup configuration changes
- Compliance-critical control changes

Output is recommendation document, not executable artifact. Human SOC analyst executes manually.

#### 14.3.3 Safety mechanisms

**Mandatory pre-execution checks:**
- Authorization tier validation
- Blast radius computation
- Rollback plan generation
- Dry-run if available
- Concurrent action check
- Time-of-day check (production change windows)

**Mandatory during-execution monitoring:**
- Action progress tracking
- Failure detection
- Side effect monitoring
- Time budget enforcement

**Mandatory post-execution validation:**
- Outcome verification
- Side effect detection
- Customer notification of outcome
- Audit log finalization

**Auto-rollback for Tier 1:**
- Per-action rollback timer (default 1 hour, configurable per action class)
- Pre-action state captured
- Rollback procedure pre-computed and validated
- Validation criteria defined
- Auto-rollback if validation fails or timer expires without explicit confirmation
- Rollback failure escalates to human immediately

#### 14.3.4 Multi-channel approval workflows

**Supported channels:**
- Slack (primary for most customers)
- Microsoft Teams
- Email with signed links
- ServiceNow approval workflow integration
- Jira approval workflow integration
- Custom webhook for SOAR integration
- Console-based detailed review

**Workflow features:**
- Configurable approver groups per action type
- Escalation if approval not received in time window
- Multi-approver required for high-risk actions
- Audit trail with full context
- Approval reasoning capture
- Approval reversal within window

### 14.4 Prevention level

The Remediation Agent is the primary prevention/cure mechanism in the platform:
- Tier 1: pre-authorized autonomous actions execute within seconds of detection
- Tier 2: drafts ready for one-click approval, time-to-action measured in minutes
- Tier 3: comprehensive recommendations enable rapid human decision-making

### 14.5 Resolution capability

The Remediation Agent IS the resolution capability of the platform. Other agents detect and recommend; Remediation Agent acts.

Every remediation produces: action artifact, blast radius analysis, rollback plan, validation criteria, audit trail, outcome verification.

### 14.6 Three-layer description

#### 14.6.1 Backend infrastructure

**Action execution engines:**
- Cloud Custodian (primary cloud config remediation)
- Terraform CLI with state management
- CloudFormation API client
- Kubernetes API client (kubectl, kustomize)
- ARM/Bicep deployment client
- Pulumi automation API
- AWS CDK programmatic API
- Custom runbook executor

**Approval workflow infrastructure:**
- Slack API client with interactive components
- Microsoft Teams API client with adaptive cards
- Email engine with signed links
- ServiceNow REST API client
- Jira REST API client
- Webhook dispatcher

**Rollback infrastructure:**
- Pre-execution state capture (per resource type)
- Rollback procedure library (per action class)
- Rollback validation engine
- Rollback timer service
- Rollback failure escalation system

**Validation infrastructure:**
- Post-execution verification engine
- Side effect detection
- Outcome reporting system
- Customer notification dispatcher

**Audit infrastructure:**
- Comprehensive action audit log
- Approval audit log
- Rollback audit log
- Customer-accessible audit history

#### 14.6.2 Charter participation

**Special privileges (highest authority of any specialist):**
- Only agent allowed to modify customer infrastructure
- Customer credential vault access
- Cross-cloud action execution
- Long-running action coordination

**Special restrictions (most stringent of any specialist):**

Strict charter rules apply:
- Every action requires explicit authorization tier match
- Every action requires rollback plan computed BEFORE execution
- Tier 1 actions require auto-rollback timer
- All actions logged immutably to Audit Agent
- Cannot bypass approval workflow for Tier 2 actions
- Cannot execute actions outside customer's authorization profile
- Cannot execute actions exceeding declared blast radius
- Cannot execute actions during customer's declared change-freeze windows
- Cannot execute irreversible actions autonomously (always Tier 2/3)
- Must dry-run if dry-run capability available
- Must validate outcome and report
- Must escalate immediately on any rollback failure

**Charter enforcement specifically for Remediation:**

The charter enforces special mechanisms for this agent:
- Pre-execution blast radius validation
- Concurrent action limits per customer (max 10 in flight)
- Time-of-day enforcement (no production changes during configured windows)
- Authorization re-check immediately before execution (handles authorization revoked mid-flight)
- Rollback timer monitoring as separate process

#### 14.6.3 NLAH

Remediation Agent NLAH structure (full production approximately 1,800 lines, the longest after Investigation Agent). Key sections:

- ROLE: Security action drafter and executor with three-tier authority model
- EXPERTISE: Cloud Custodian (policy authoring, filter and action chains), Infrastructure-as-Code (Terraform state management, CloudFormation change sets, ARM/Bicep, Pulumi, AWS CDK), Kubernetes (kubectl patch, kustomize overlays, Helm), IAM (least-privilege generation, credential rotation, session revocation), approval workflow design, rollback design (state capture, procedure library, validation criteria, failure recovery)
- DECISION HEURISTICS: H1-H8 covering rollback-before-acting, dry-run-before-live, strict tier matching, smaller blast radius preference, reversible-over-irreversible, time-of-day mattering, validate-after-execute, page-humans-on-rollback-failure
- STAGES (Prompt Chaining, 9 stages): Parse, Authorize, Draft, Validate, Rollback Plan, Route, Execute, Verify, Handoff
- FAILURE TAXONOMY: F1-F10 covering authorization mismatch (demote tier), dry-run failure, partial application (immediate rollback), rollback failure (PAGE HUMANS), verification failure, authorization revoked mid-action, approval timeout, rollback timer expiry, concurrent action limits, change-freeze windows
- CONTRACTS YOU REQUIRE: Authorization profile current, cloud credentials, rollback infrastructure, approval channels, audit log, change-freeze windows
- WHAT YOU NEVER DO: Execute without authorization tier check, execute without rollback plan, execute when dry-run fails, take Tier 1 without auto-rollback timer, execute irreversible actions autonomously, skip verification, bypass approval workflow, execute outside change windows, continue after rollback failure without human escalation, execute exceeding declared blast radius
- PEER COORDINATION: ALWAYS for action recording (Audit Agent), originating agent (validation handoff), Investigation Agent (action failures), Cloud Posture Agent (drift verification), Compliance Agent (compliance impact verification), customer (action notifications via supervisor + Synthesis)

### 14.7 Execution contract template

```yaml
contract_version: 1.0
contract_id: <UUID>
identity:
  source_agent: <delegating>
  target_agent: remediation
  customer_id: <UUID>
  trace_id: <UUID>

task:
  type: draft | execute | rollback | bulk_remediate
  scope:
    finding_id: <UUID>
    proposed_action: structured
    target_tier: 1 | 2 | 3
    urgency: enum
  priority: emergency | urgent | normal | background

required_outputs:
  remediation:
    remediation_id: UUID
    finding_id: UUID
    source_agent: string
    tier_requested: enum
    tier_actual: enum
    tier_change_reason: text (if differs)
    
    action_artifact:
      type: enum [cloud_custodian, terraform, cfn, k8s, runbook, iam_policy]
      content: string
      content_hash: string
      target_resources: array
    
    blast_radius:
      affected_resources_count: int
      affected_resources: array
      estimated_impact: structured
      side_effect_risk: enum
    
    rollback_plan:
      rollback_steps: array
      pre_execution_state: structured
      estimated_rollback_time_seconds: int
      verification_method: string
      rollback_failure_recovery: structured
    
    validation:
      dry_run_passed: bool
      dry_run_output: text
      pre_execution_checks: array
      syntax_validation: bool
    
    approval_workflow:
      channel: enum [slack, teams, email, servicenow, jira, console]
      approvers: array
      submitted_at: ISO 8601
      approved_at: ISO 8601 | null
      rejected_at: ISO 8601 | null
      approval_reasoning: text
    
    execution:
      started_at: ISO 8601 | null
      completed_at: ISO 8601 | null
      outcome: enum [success, partial, failed, rolled_back, pending]
      validation_results: structured
      side_effects_detected: array
    
    audit_trail:
      events: array of {timestamp, event_type, details, actor}
    
    status: enum [drafted, validating, approval_pending, approved, executing, completed, rolled_back, failed]

budget:
  max_llm_calls:
    draft: 6
    execute: 3        # less LLM, more deterministic execution
    rollback: 4
  max_tokens:
    draft: 12000
    execute: 6000
    rollback: 8000
  max_wall_clock_seconds:
    draft: 60
    execute: 300      # actions can take time
    rollback: 120
  max_workspace_mb: 100

permitted_tools:
  # Drafting tools
  - draft_cloud_custodian_policy
  - draft_terraform_diff
  - draft_cfn_changeset
  - draft_arm_template
  - draft_k8s_patch
  - draft_runbook
  - draft_iam_policy
  
  # Approval tools
  - submit_for_approval
  - await_approval
  - record_approval
  
  # Execution tools
  - dry_run_action
  - execute_cloud_custodian
  - execute_terraform
  - execute_cfn
  - execute_kubectl
  - execute_runbook
  - validate_remediation
  
  # Rollback tools (always permitted, never blocked)
  - prepare_rollback_plan
  - execute_rollback
  - verify_rollback
  - schedule_auto_rollback
  
  # Authorization tools
  - check_tier1_authorization
  - check_change_freeze_window
  - enforce_blast_radius
  - check_concurrent_actions
  
  # Coordination tools
  - notify_audit_agent
  - notify_originating_agent
  - escalate_to_human
  - notify_customer
  - record_audit

conditional_tools:
  # Execute tools only with valid authorization match + dry_run_passed
  - execute_cloud_custodian: requires authorization_match AND dry_run_passed
  - execute_terraform: same
  - execute_cfn: same
  - execute_kubectl: same
  - execute_runbook: requires Tier 2+ approval

completion_condition: |
  Drafted: action artifact, blast radius, rollback plan all populated
  Validated: dry_run passed (if available), all checks passed
  Approved (Tier 2): approval received and recorded
  Executed: action applied, validated, outcome recorded
  Rolled back (if applicable): rollback completed and verified
  Audit: full trail recorded immutably

workspace: /workspaces/<customer_id>/<remediation_id>/remediation/
```

### 14.8 File-backed state schema

```
/workspaces/<customer_id>/<remediation_id>/remediation/
  task.yaml
  authorization_check.json
  draft/
    action_artifact.<ext>           # the actual code to execute
    blast_radius_analysis.json
    dry_run_result.json
  rollback_plan.yaml
  approval/
    request.json
    response.json
    approver_audit.jsonl
  execution/
    pre_state.json                  # captured before action
    execution_log.jsonl
    post_state.json                 # captured after action
    verification_result.json
    side_effects.json
  audit_trail.jsonl
  reasoning_trace.md
  output.yaml

/persistent/<customer_id>/remediation/
  authorization_profile.yaml        # tier 1/2/3 settings per action class
  remediation_history.jsonl
  rollback_history.jsonl
  effectiveness_scores.json         # which remediations work
  approval_patterns.yaml            # who approves what, when
  change_freeze_windows.yaml        # customer's production windows
  rate_limits.yaml                  # per-class rate limit history
  insurance_policy_log.jsonl        # for insurance partner credits
```

### 14.9 Self-evolution criteria

Remediation Agent has the strictest self-evolution criteria of any agent given its high blast radius:

**Strict thresholds:**
- Rollback rate > 2% triggers harness review (suggests bad remediation drafts)
- Approval rejection rate > 15% triggers harness review (poor drafts or wrong tier)
- Verification failures > 5% triggers harness review
- Dry-run failures > 10% triggers harness review
- ANY rollback failure triggers immediate engineering review (not Meta-Harness)
- Customer downgrades Tier 1 authorization (safety signal)
- Time-to-execution exceeds expected

**Critical incidents (immediate review, not Meta-Harness):**
- Tier 1 action causing unintended outcome
- Action executing during change-freeze window
- Action exceeding declared blast radius
- Action without proper audit trail
- Action authorized by Tier 1 when it should have been Tier 2/3

When triggered through normal Meta-Harness, evaluation against extensive eval suite of 500+ remediation scenarios with known outcomes. Cross-model validation mandatory.

When triggered as critical incident, engineering team reviews directly. Meta-Harness does not auto-deploy remediation NLAH changes — human approval mandatory for any remediation NLAH update due to high blast radius.

### 14.10 Pattern usage declaration

**Primary patterns:** Prompt chaining (strict 9-stage pipeline), Evaluator-optimizer (self-evolution on rollback/approval patterns)
**Forbidden patterns:** Orchestrator-workers (this agent does not spawn sub-agents)

### 14.11 Tools

35+ tools in permitted_tools (the most of any agent due to wide range of action types); full specifications in Tool Specification document.

### 14.12 Memory architecture

**Episodic:**
- Remediation history with outcomes
- Rollback history with causes
- Approval history per action class
- Side effects detected per action

**Procedural:**
- Effectiveness scores per remediation type
- Customer-specific successful patterns
- Approval pattern learning (who approves what, when, how fast)
- Rate limit effectiveness

**Semantic:**
- Customer's authorization profile per action class
- Customer's change freeze windows
- Customer's approval workflow configuration
- Customer's blast radius preferences

### 14.13 Inter-agent coordination

**Calls:**
- Audit Agent — ALWAYS for action recording (mandatory)
- Originating agent — for validation handoff after execution
- Investigation Agent — for action failures or unexpected outcomes
- Cloud Posture Agent — for drift verification after action
- Compliance Agent — for compliance impact verification
- Customer (via supervisor + Synthesis) — for action notifications

**Called by:**
- Cloud Posture Agent (configuration remediations)
- Vulnerability Agent (patch deployments, IaC fixes)
- Identity Agent (policy updates, credential rotation)
- Runtime Threat Agent (workload actions, file quarantine)
- Network Threat Agent (IP blocks, network actions)
- Data Security Agent (access tightening, encryption)
- Compliance Agent (compliance gap remediation)
- Investigation Agent (containment, eradication, recovery)

### 14.14 Wiz capability mapping

Wiz does not perform remediation autonomously — they have detection-only positioning. This is a category-defining differentiation for our platform. There is no Wiz analog for the Remediation Agent. Wiz customers must build their own remediation through SOAR platforms or manual processes.

This is one of our strongest competitive moats. The Remediation Agent represents architectural commitment that Wiz cannot easily replicate without rebuilding their platform.

### 14.15 Coverage progression

| Phase | Coverage | Notes |
|---|---|---|
| 1 | Tier 3 production + initial Tier 1 + Tier 2 | Production with all three tiers, narrow Tier 1 action classes |
| 2 | + expanded Tier 2 | More action classes available with approval |
| 3 | + expanded Tier 1 | Tier 1 expanded to 25+ action classes (with insurance partnerships) |
| 4 | Mature Tier 1 across many action classes | Vertical-specific Tier 1 patterns, mature self-evolution |

---

**Part 3 ends here.** Part 3 covered four cross-cutting agents:

- **Compliance Agent** (110+ frameworks, audit-ready evidence, gap analysis)
- **Investigation Agent** (orchestrator-workers pattern, sub-agent spawning, full DFIR)
- **Threat Intel Agent** (15+ external feeds, customer correlation, briefing generation)
- **Remediation Agent** (action endpoint, three-tier authority, highest blast radius, strictest safety)

Part 4 will cover the four support agents (Curiosity, Synthesis, Meta-Harness, Audit) plus sections 19-21 (Inter-Agent Coordination Patterns, Eval Infrastructure Per Agent, Production Readiness Checklist).
