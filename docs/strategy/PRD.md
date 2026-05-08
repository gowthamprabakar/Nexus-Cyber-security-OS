# PRODUCT REQUIREMENTS DOCUMENT
## [Product Name] — Autonomous Cloud Security Platform

**Document Version:** 1.0
**Status:** Draft for review
**Authors:** Founding Team
**Date:** [Current]
**Classification:** Confidential

---

## DOCUMENT CONTROL

| Version | Date | Author | Changes |
|---|---|---|---|
| 0.1 | [Date] | Founder | Initial outline |
| 1.0 | [Date] | Founding team | First production draft |

This document is the canonical source of truth for what the product is, who it serves, what it does, and what success looks like. All other product documents derive from this one. Changes require founder approval and version control.

---

## TABLE OF CONTENTS

1. Executive Summary
2. Problem Statement
3. Market Analysis
4. Target Customer Profile
5. Product Vision Summary
6. Product Scope
7. Detailed Capability Specification
8. User Personas and Journeys
9. Functional Requirements
10. Non-Functional Requirements
11. Integration Requirements
12. Compliance and Regulatory Requirements
13. Out of Scope (Explicit Exclusions)
14. Success Metrics and KPIs
15. Pricing and Packaging
16. Competitive Differentiation
17. Risks and Open Questions
18. Glossary

---

## 1. EXECUTIVE SUMMARY

### 1.1 The product in one paragraph

[Product Name] is an autonomous cloud security platform that combines deterministic detection, agentic reasoning, and tiered autonomous remediation. It deploys as a single-tenant edge runtime connected to a centralized SaaS control plane, providing security teams with a virtual SOC operating continuously across cloud, hybrid, and on-premises environments. The platform delivers detection capability comparable to the leading Cloud Native Application Protection Platforms (CNAPPs) while adding two architectural innovations the incumbents do not provide: autonomous remediation through a three-tier authority model, and edge mesh deployment supporting hybrid and air-gapped environments.

### 1.2 Why now

Three forces converge to make this product viable today and necessary tomorrow.

First, the cloud security detection layer has commoditized. Open-source tools — Prowler, Trivy, Falco, Checkov, Cartography, Kubescape — collectively provide 75-85% of the detection capability that commercial CNAPPs charge enterprises hundreds of thousands of dollars to access. The remaining 15-25% gap is engineering polish and brand trust, not fundamental capability.

Second, the agentic AI capability needed to orchestrate this detection foundation into a coherent autonomous system has matured. Foundation models from Anthropic and others now demonstrate the reasoning quality required for production security operations when properly harnessed. The "harness engineering" discipline emerging from Tsinghua, Stanford, and Anthropic provides the framework for reliable agentic systems.

Third, enterprise security teams are drowning. The 2025 industry data shows 61% of security leaders cannot remediate the cloud exposures they detect. Alert fatigue is universal. Skilled security headcount is scarce and expensive. Organizations need force multiplication, not more dashboards.

### 1.3 What we deliver that no one else does

Three differentiations defended by architecture, not feature checklists:

**Autonomous remediation through tiered authority.** The platform does not just detect — it acts. Through a customer-controlled three-tier authorization model, the platform autonomously executes pre-authorized actions (Tier 1), drafts remediations for one-click approval (Tier 2), and generates recommendations for human execution (Tier 3). Wiz, the dominant cloud security platform, has chosen detection-only positioning. CrowdStrike's response is endpoint-centric. Palo Alto's emerging AgentiX framework is approval-gated only. We are the first to deliver true tiered autonomy with rollback safety.

**Edge mesh deployment.** The platform deploys as a single-tenant runtime at the customer's edge — in their cloud account, their on-premises data center, their factory floor, their hospital, their air-gapped enclave — connected to our centralized SaaS control plane. This architecture gives us visibility into hybrid and OT environments that pure-cloud-SaaS competitors architecturally cannot reach.

**Multi-agent autonomous SOC.** The platform operates as a team of fourteen specialized AI agents under a runtime charter that enforces execution contracts, file-backed state, and self-evolution. Each agent is a domain expert: Cloud Posture, Vulnerability, Identity, Runtime Threat, Data Security, Network Threat, Compliance, Investigation, Threat Intelligence, Remediation, plus orchestration and audit support agents. Together they execute the heartbeat-driven autonomous loop that detects, reasons, decides, and acts continuously.

### 1.4 Target outcome

Customers achieve four measurable outcomes within ninety days of deployment:

**Detection breadth.** Coverage equivalent to leading CNAPPs across CSPM, CWPP, CIEM, DSPM, IaC scanning, secrets detection, runtime threats, and vulnerability management. Customers can decommission their existing point tools in this space.

**Remediation velocity.** Mean time to remediation reduced from days to minutes for Tier 1 action classes; from hours to minutes for Tier 2 with one-click approval; clear prioritization for Tier 3 human action. Customer-controlled authorization tiers prevent unsafe autonomy.

**SOC capacity multiplication.** Security analysts redirected from triage and rule-tuning to higher-value work. The platform handles the volume; humans handle the judgment calls. Effective force multiplication of 3-5x measured against current SOC throughput.

**Compliance posture.** Audit-ready evidence collection across CIS, NIST 800-53, PCI-DSS, HIPAA, SOC 2, ISO 27001, GDPR, FedRAMP, plus vertical-specific frameworks. Continuous compliance monitoring instead of point-in-time audits.

### 1.5 Business outcome

The company targets $25M ARR by Month 36 with 65-75% gross margin, positioned for either continued independence at $50M+ ARR or strategic acquisition at $300M-1B+ valuation. The target market is mid-market hybrid enterprises, manufacturing OT, regulated healthcare, and defense — segments where pure-cloud SaaS security tools are architecturally inadequate and where enterprise-priced incumbents are inaccessible.

---

## 2. PROBLEM STATEMENT

### 2.1 The cloud security paradox

Cloud security spending has grown more than 30% annually for five consecutive years. Major CNAPP platforms — Wiz, Palo Alto Prisma Cloud, CrowdStrike Falcon Cloud Security, Lacework, Orca — have collectively raised over $5 billion in venture capital and reached aggregate market capitalization north of $50 billion. Wiz alone was acquired by Google for $32 billion in 2025.

Despite this investment, security outcomes have not improved at the same rate.

The Cymulate 2025 Threat Exposure Validation Report found that 61% of security leaders cannot identify and remediate cloud exposures at the pace required by their threat environment. The IBM Cost of Data Breach 2024 report showed cloud-based breach costs increased to $4.88M average, with mean time to identify breaches in cloud environments at 277 days.

This is not a tooling deficit. Customers have tools — too many of them. The deficit is in operational capacity to act on what tools find. A typical mid-market organization receives thousands of cloud security findings per week from their CNAPP and processes a single-digit percentage to remediation.

### 2.2 Three structural problems with the current market

**Problem One: Detection without remediation.**

The dominant CNAPP architecture, exemplified by Wiz, is detective. It finds problems, prioritizes them, and presents them to humans. The remediation is the customer's responsibility. This made sense when the bottleneck was visibility into cloud environments. The bottleneck has moved. Now the bottleneck is action.

Customers report processing 10-20% of CNAPP findings. The other 80-90% sit in dashboards. Critical findings get attention; medium-severity findings accumulate into a debt that eventually becomes a breach. The CNAPP industry has optimized the wrong end of the funnel.

**Problem Two: Cloud-only architecture in a hybrid world.**

Pure cloud-native platforms are designed around APIs to AWS, Azure, GCP. They have no visibility into:

- On-premises infrastructure that 70%+ of mid-market enterprises still run
- Operational technology and industrial control systems in manufacturing
- Medical devices and clinical IT in hospitals
- Branch office networks and edge computing
- Air-gapped or classified environments
- Hybrid cloud-to-on-premises lateral movement paths

Wiz architecturally cannot scan a factory floor PLC, a hospital MRI machine, or a regional bank's branch infrastructure. Its CSPM scanners run against cloud APIs. When the threat moves between cloud and on-premises, current CNAPPs lose visibility precisely at the most dangerous boundary.

**Problem Three: Enterprise pricing in a mid-market world.**

CNAPP pricing is calibrated for Fortune 1000 enterprises. Wiz typical deals start at $300K and scale to multi-million dollar contracts. CrowdStrike Falcon Cloud Security similar. Palo Alto Prisma Cloud similar.

Mid-market organizations (1,000-10,000 employees) face the same threat environment as enterprises but cannot afford enterprise pricing. They make do with:

- Free tier of cloud provider native tools (limited capability)
- Open-source DIY stacks (high operational cost)
- Generic MSSP packages (low quality, no accountability)
- Single-product point tools (visibility gaps)

This segment is structurally underserved. The 2025 Techaisle research shows 74% of mid-market firms identify cyberattacks as a primary business risk, and 88% agree operational resiliency reduces business risk, yet effective security platforms remain financially inaccessible.

### 2.3 The compounding cost of these problems

The three problems compound. Detection without remediation creates alert backlog. Cloud-only architecture creates visibility gaps where attackers pivot. Enterprise pricing means most organizations have inferior tools that worsen both problems.

The result: cloud breach costs continue rising despite massive security investment. The economics of attacker (cost to attack) versus defender (cost to defend) favor attackers in current architecture.

### 2.4 Why this problem is not solved by incumbents

Wiz, CrowdStrike, Palo Alto, and the other CNAPP vendors are not blind to these problems. They will eventually attempt to address them. They have not done so for structural reasons:

**Wiz.** Committed to centralized SaaS architecture. Adding edge deployment requires fundamentally new product surface. Product investment focused on cloud-native customers rather than hybrid mid-market. Acquisition by Google reinforces cloud-first positioning. Detection-first culture; remediation requires different organizational competencies. Pricing model anchored at enterprise; mid-market pricing would cannibalize existing revenue.

**CrowdStrike.** Endpoint-first DNA. Cloud security is an extension product, not core. Their cloud security customers are primarily existing endpoint customers. Multi-agent autonomous architecture would require dismantling the Falcon sensor architecture they have heavily invested in.

**Palo Alto.** Most positioned to compete given their portfolio breadth, but the AgentiX agentic framework is approval-gated only and conservatively scoped. Multi-product company complicates architectural pivots. Distribution model still enterprise-focused.

**Lacework, Orca, Sysdig, others.** Similar architectural choices to Wiz with less capital and customer base.

The window exists because incumbents are committed to architectural choices that constrain their ability to address these problems. The window will not stay open forever. A new platform built around the right architectural primitives can establish defensible position before incumbents pivot.

### 2.5 Customer voice

From customer discovery interviews, the pain articulated in customers' own words:

*"We have Wiz. It tells us everything that's wrong. It does not help us fix anything. My team is drowning."* — VP of Security, mid-market healthcare, 2,400 employees.

*"We can't afford Wiz. We're using a mix of native cloud tools, open-source stuff, and a managed service. None of it talks to each other. I have no idea what our actual posture is."* — CISO, regional financial services, 1,800 employees.

*"Our factory floor has equipment from the 1990s. Our cloud environment is on AWS. Wiz doesn't see our factories. Our OT vendor doesn't see our cloud. The attacker doesn't care about our org chart."* — Director of IT Security, manufacturing, 5,000 employees.

*"I want autonomy. I want the system to fix the basic stuff and let my analysts work on the hard stuff. Every vendor tells me 'sure but only if you approve every action.' Then it's not autonomy. It's slow approval workflow."* — VP Engineering, technology company, 1,200 employees.

These are not marketing-amplified pains. These are direct quotes from prospective buyers describing operational reality.

---

## 3. MARKET ANALYSIS

### 3.1 Total addressable market

The cloud security market is addressed in three nested segments:

**Total Addressable Market (TAM): $87B by 2027**
Global cloud security spending across all segments and product categories. Includes CNAPP, CSPM, CWPP, CIEM, DSPM, runtime detection, SIEM, SOAR, and adjacent categories. Growth rate 18-22% CAGR.

**Serviceable Addressable Market (SAM): $32B**
Cloud security spending in segments where the product is competitive: mid-market (1,000-10,000 employees) globally, plus hybrid enterprise segments where edge deployment matters (manufacturing, healthcare, defense, regulated financial), plus regulated mid-market with compliance requirements. Excludes pure-enterprise Fortune 500 segment where Wiz/CrowdStrike incumbency is too strong, and excludes SMB segment where price points are too low.

**Serviceable Obtainable Market (SOM): $1.2B by Year 5**
Realistic capture given startup constraints, sales velocity, and competitive dynamics. Targets 1-2% of SAM in addressable verticals with 4-5 year ramp.

### 3.2 Market segmentation by vertical

**Mid-market hybrid enterprise (35% of SAM):**
Companies between 1,000 and 10,000 employees with multi-cloud deployments and on-premises infrastructure. Approximately 25,000 such organizations globally. Average security budget $1-5M annually. Current CNAPP penetration 30-40%; remaining 60-70% use point tools or no platform.

**Manufacturing with operational technology (15% of SAM):**
Manufacturing organizations with industrial control systems, SCADA, PLC networks, and IoT. Roughly 12,000 mid-to-large manufacturing organizations globally relevant to this category. Critical infrastructure subset (NERC-CIP, water utilities, etc.) represents ~3,000 high-priority targets. Currently underserved by both IT security platforms (don't speak OT) and OT security platforms (don't speak cloud).

**Healthcare hybrid (12% of SAM):**
Hospital systems, regional healthcare networks, healthcare technology companies. Roughly 6,000 organizations globally with sufficient complexity. HIPAA compliance pressure drives security investment. Currently served by mix of healthcare-specialized vendors (limited functionality) and generic cloud security (limited healthcare specialization).

**Regional financial services (10% of SAM):**
Community banks, credit unions, regional insurers, regional asset managers. Roughly 8,000 organizations globally. Strong compliance requirements (FFIEC, NYDFS, PCI). Mid-market budgets but enterprise-grade compliance needs.

**Defense and intelligence community (8% of SAM):**
Defense contractors, intelligence agencies, classified environments requiring FedRAMP High and air-gap deployment. Smaller customer base but high contract values and stable revenue. Long sales cycles (12-24 months) but strong retention.

**Regulated mid-market other (20% of SAM):**
Energy and utilities, transportation and logistics, education, government contractors. Smaller individual segment value but combined significant.

### 3.3 Market dynamics

**Demand drivers:**

Cloud adoption continues accelerating. Public cloud spending grew 20.7% in 2024 to $679 billion globally. Each new workload is a new attack surface.

Regulatory pressure intensifies. NIS2 in Europe expanded scope dramatically. SEC cyber disclosure rules in the US require breach reporting. State-level data privacy laws proliferating. HIPAA enforcement continuing. Healthcare and financial sector regulations tightening.

Threat environment escalating. 2024 saw record ransomware attacks against healthcare and manufacturing. Nation-state actors targeting critical infrastructure. Cloud-native attack techniques (IMDS abuse, lateral movement via cloud APIs, supply chain compromise) increasing.

Talent shortage worsening. ISC2 reports 4 million unfilled cybersecurity positions globally. Average tenure of CISOs declining. Burnout rates extreme.

Insurance market hardening. Cyber insurance premiums up 20-100% year over year. Insurance carriers requiring specific security controls before underwriting. Some industries becoming uninsurable without continuous monitoring.

**Supply dynamics:**

Major CNAPP vendors at scaling stage with enterprise focus. Mid-market underserved.

MSSP/MDR market growing rapidly but commoditizing. Customers want platform plus managed service, not just managed service.

Open source security tooling reaching maturity. Detection capability commoditized; orchestration and operations are the new value layer.

Foundation model capability enabling agentic security operations that were not feasible 18 months ago.

### 3.4 Competitive landscape

**Direct CNAPP competitors:**

| Competitor | Strengths | Weaknesses | Strategy vs them |
|---|---|---|---|
| Wiz | Strongest detection, best UX, dominant brand, Google backing | Cloud-only, enterprise pricing, detection-only, no edge | Compete on edge, remediation, mid-market price |
| CrowdStrike Falcon | Endpoint dominance, threat intel quality, brand trust | Endpoint-first, cloud as extension, monolithic | Compete on cloud-native depth and multi-agent architecture |
| Palo Alto Prisma | Broad portfolio, network strength, agentic emerging | Complex, expensive, slow, multi-product friction | Compete on simplicity and pure-play focus |
| Lacework | Mature CNAPP, behavioral analytics | Capital constraints, slow innovation | Compete on agentic architecture |
| Orca | Agentless innovation, design quality | Smaller team, limited verticals | Compete on remediation and edge |
| Sysdig | Runtime strength, container expertise | Container-focused, narrow | Compete on breadth and remediation |

**Adjacent competitors:**

Cloud provider native security: AWS GuardDuty, Azure Defender, Google SCC. Limited to single-cloud, no remediation orchestration.

SIEM/SOAR platforms: Splunk, Sentinel, Chronicle, Datadog. Detection orchestration but no native cloud security capability.

OT security specialists: Claroty, Dragos, Nozomi. Strong OT, no cloud.

Healthcare security: Medigate, Cynerio, Armis. Strong medical IoT, weak cloud.

GRC platforms: Drata, Vanta, Secureframe. Compliance management but limited security operations.

**Indirect competitors:**

MSSP/MDR providers: Arctic Wolf, Huntress, Blumira, ReliaQuest. Managed services, not platforms.

DIY open-source: Customer-built stacks of Falco/Trivy/Prowler/etc. Free in licensing, expensive in operations.

### 3.5 Why we win

We win in target segments through architectural advantages competitors cannot easily match:

**Architectural advantage: Edge mesh.** Wiz cannot deploy at customer edges without rebuilding their platform. CrowdStrike could but it conflicts with their endpoint architecture. Palo Alto would require reconciling multiple product lines.

**Architectural advantage: Multi-agent autonomous.** All competitors have built monolithic detection engines. Retrofitting multi-agent architecture requires rebuilding from foundations.

**Architectural advantage: Tiered remediation.** Industry default is approval-gated only. Tiered authority requires safety engineering competitors haven't invested in.

**Pricing advantage: Mid-market accessible.** Competitors structurally cannot drop enterprise pricing without revenue impact.

**Vertical advantage: Hybrid OT/healthcare/defense.** Platforms designed for cloud-native enterprise don't fit these segments.

We do not win in pure-cloud Fortune 500 segment where Wiz dominates. We do not try to.

---

## 4. TARGET CUSTOMER PROFILE

### 4.1 Primary Ideal Customer Profile

**Organization characteristics:**
- 1,000 to 10,000 employees
- Mid-market revenue ($100M to $2B annually)
- Multi-cloud or hybrid infrastructure (AWS + Azure most common, often plus on-premises)
- Existing security team of 5 to 30 people including CISO/VP Security
- Active compliance pressure (HIPAA, PCI, SOC 2, FFIEC, NYDFS, or vertical-specific)
- Annual security budget $1M to $10M
- Currently using either no CNAPP, generic point tools, or managed security service

**Vertical priority order for go-to-market:**

Priority 1 — Healthcare hybrid networks. Hospital systems, healthcare technology, regional healthcare networks. Pain: HIPAA compliance, medical device visibility, ransomware exposure. Decision velocity: medium (3-6 months). Reference value: extremely high in segment.

Priority 2 — Manufacturing with OT. Manufacturing organizations with industrial control. Pain: IT/OT convergence, OT visibility, ransomware against production. Decision velocity: slow (6-9 months). Reference value: high in segment.

Priority 3 — Regional financial services. Community banks, credit unions, regional insurance and asset management. Pain: FFIEC compliance, ransomware, third-party risk. Decision velocity: medium-slow (6-9 months). Reference value: very high (peer recommendations critical in financial).

Priority 4 — Mid-market hybrid technology and SaaS. Technology companies with multi-cloud and meaningful on-premises. Pain: SOC 2 compliance, audit readiness, fast scaling. Decision velocity: fast (2-4 months). Reference value: medium (less peer-driven).

Priority 5 — Defense contractors and government adjacent. Defense industrial base, government contractors. Pain: FedRAMP, CMMC, classified environment security. Decision velocity: very slow (12-24 months). Reference value: extremely high once landed.

### 4.2 Buyer personas

**Primary economic buyer: VP of Security / CISO**

Profile: Senior security leader, typically reports to CIO or CTO. 10-20 years experience. Has deployed security platforms before. Budget authority for security spending.

Pains:
- Cannot demonstrate measurable improvement to board
- Team capacity exceeded by alert volume
- Audit findings and compliance pressure
- Personal liability anxiety post-SEC disclosure rules
- Difficulty hiring and retaining security talent
- Tool sprawl frustration

Goals:
- Reduce mean time to remediation
- Demonstrate compliance posture continuously
- Force-multiply security team
- Reduce tool count and vendor management overhead
- Build defensible security program

Decision criteria:
- Total cost of ownership (not just license cost)
- Speed to value
- Compliance evidence quality
- Vendor stability and support
- Reference customers in similar context
- Compatible with existing security stack

Communication style: Strategic, business-outcome focused. Wants clear ROI narrative. Skeptical of new vendors but open to differentiated capabilities.

**Technical evaluator: Director of Security / Security Architect**

Profile: Senior practitioner. Will test the product. Influences VP/CISO heavily. Often the actual person doing customer discovery calls.

Pains:
- Tool integration complexity
- False positive volume
- Inability to cover hybrid and edge environments
- Compliance reporting overhead
- Platform vendor inflexibility

Goals:
- Real detection capability, not marketing
- Clean integration with existing tools
- Customizability for their environment
- Real automation that doesn't break things
- Data they can actually trust

Decision criteria:
- Technical depth in proof of concept
- API quality and integration breadth
- Detection rule transparency
- Remediation safety mechanisms
- Customization flexibility

Communication style: Technical depth required. Allergic to marketing speak. Will read documentation thoroughly.

**Operational user: Security Engineer / SOC Analyst**

Profile: Day-to-day operator of the platform. Will use the product daily. Influences renewal decisions through usage patterns.

Pains:
- Alert fatigue
- Dashboard switching
- Manual investigation overhead
- Repetitive remediation work
- Lack of context in alerts

Goals:
- Get to the root cause faster
- Spend time on interesting work, not triage
- Trust the platform's prioritization
- See what's actually happening in the environment

Decision criteria:
- Daily UX quality
- Integration with their actual workflow
- Alert quality (signal vs noise)
- Investigation depth and speed

Communication style: Direct, pragmatic, technical. Wants to see it work.

**Compliance buyer: Director of GRC / Compliance Officer**

Profile: GRC leader. Responsible for audit outcomes. Often separate budget from security.

Pains:
- Manual evidence collection
- Point-in-time audits
- Framework mapping complexity
- Auditor demands

Goals:
- Continuous compliance evidence
- Auditor-ready reports
- Framework coverage breadth
- Documentation quality

Decision criteria:
- Compliance framework breadth
- Evidence quality
- Audit support quality
- Framework update velocity

**Secondary stakeholders:**

CIO (final budget approval), CFO (ROI scrutiny), CTO (technical due diligence), Procurement (contract negotiation), Legal (data handling review), Privacy Officer (GDPR/CCPA review).

### 4.3 Disqualified profiles

Explicit disqualifications to focus go-to-market:

- Fortune 500 enterprises with deeply entrenched Wiz/CrowdStrike deployments (replacement risk too high; we don't win)
- Pure cloud-native startups under 200 employees (price sensitive, don't need our edge capability, better served by free tier of native cloud security)
- Public sector requiring full FedRAMP High at launch (Phase 5+ capability, not Phase 1)
- Organizations requiring on-premises only deployment with no SaaS component (architectural mismatch)
- Healthcare organizations under 500 employees (operational complexity exceeds our service capacity initially)
- Customers seeking purely managed service (we are platform plus partner-delivered service, not pure MDR)

### 4.4 Customer success criteria

Customer is successful when:

90 days post-deployment: Production deployment complete; Tier 3 (recommend-only) operational; first compliance report generated; security team using platform daily; baseline metrics established.

180 days post-deployment: Tier 2 (approval-gated) operational; integration with existing security stack complete; mean time to remediation reduced 50% from baseline; first audit cycle supported.

365 days post-deployment: Tier 1 (autonomous) operational for at least one action class; demonstrated reduction in security incidents; compliance posture improved; customer expanded scope (more accounts, more action classes, more verticals).

Renewal indicators: Daily active users from security team. Tier 2 approval queue under 5 days. Customer-initiated expansion. Reference willingness.

---

## 5. PRODUCT VISION SUMMARY

The full Vision Document is a separate document. Summarized here for context:

**Five-year vision:** [Product Name] becomes the standard autonomous security platform for hybrid enterprises and regulated mid-market organizations globally. We define the agentic security operations category. Our runtime charter becomes a foundation other security platforms reference. We achieve $100M+ ARR through compounding execution against a 30-month roadmap, positioning for either continued independence or strategic acquisition by a major security or cloud platform.

**Three-year vision:** Operating at $25-50M ARR with 200+ customers across primary verticals. SOC 2 Type II, FedRAMP Moderate, vertical compliance certifications complete. Multi-agent architecture mature with 14+ specialist agents. Self-evolution proven in production. Reference customers in healthcare, manufacturing, financial services, defense.

**One-year vision:** First 25 paying customers in production. Initial verticals validated. Tier 1 autonomous remediation operational for narrow action classes. Series A complete. SOC 2 Type II achieved. Product-market fit demonstrated.

---

## 6. PRODUCT SCOPE

### 6.1 Scope statement

[Product Name] delivers integrated cloud security across the detect-prevent-investigate-remediate-comply lifecycle through a multi-agent autonomous platform deployed at customer edge with centralized SaaS control. The platform addresses cloud, hybrid, and on-premises infrastructure across AWS, Azure, GCP, Kubernetes, and physical/virtual on-premises environments.

### 6.2 Core capabilities included

The platform includes the following capability layers, each detailed in subsequent sections:

**Detection capabilities:**
- Cloud Security Posture Management (CSPM) across AWS, Azure, GCP, Kubernetes
- Cloud Workload Protection (CWPP) with runtime threat detection
- Cloud Infrastructure Entitlement Management (CIEM) with effective permissions analysis
- Data Security Posture Management (DSPM) with sensitive data classification
- Vulnerability management across containers, VMs, serverless, IaC
- Secrets detection across code, configurations, container layers
- Infrastructure-as-Code security scanning
- AI Security Posture Management (AI-SPM)
- Network threat detection
- Identity threat detection

**Prevention capabilities:**
- Pre-deployment IaC scanning (CI/CD integration)
- Runtime policy enforcement via Kubernetes admission controllers
- Network microsegmentation recommendations
- Identity drift detection and prevention
- Pre-emptive threat blocking based on threat intelligence

**Investigation capabilities:**
- Automated incident triage
- Timeline reconstruction
- Root cause analysis
- IOC pivoting and enrichment
- MITRE ATT&CK technique mapping
- Cross-domain correlation (cloud + identity + runtime + network)
- Forensic snapshot capture

**Remediation capabilities:**
- Three-tier remediation authority (autonomous, approval-gated, recommend-only)
- Cloud Custodian policy execution
- Terraform diff generation and execution
- Kubernetes manifest patching
- IAM policy modification with least-privilege drafting
- Network policy changes
- Auto-rollback for autonomous actions
- Multi-channel approval workflows

**Compliance capabilities:**
- Continuous compliance monitoring against 100+ frameworks
- Audit-ready evidence collection and packaging
- Control-by-control mapping for major frameworks
- Compliance drift detection
- Audit support and reporting
- Vertical-specific compliance (HIPAA, PCI, FFIEC, HITRUST, NERC-CIP, FedRAMP)

**Threat intelligence capabilities:**
- Continuous ingestion from 15+ external sources
- Customer-specific threat correlation
- Active campaign tracking
- Industry-specific threat briefings
- Vulnerability exploitation prioritization

**Operational capabilities:**
- Conversational interface (chat-first UX)
- Real-time activity transparency
- Multi-tier deployment (cloud, hybrid, air-gapped)
- Multi-tenant isolation with strict data boundaries
- Comprehensive audit logging with hash-chain integrity
- Self-evolution of detection and reasoning

**Integration capabilities:**
- 30+ pre-built integrations at launch
- SIEM forwarding (Splunk, Sentinel, Chronicle, Datadog, Elastic)
- Ticketing systems (Jira, ServiceNow, Linear)
- ChatOps (Slack, Teams, Discord)
- Identity providers (Okta, Azure AD, Google Workspace)
- Alert routing (PagerDuty, Opsgenie)
- Source control (GitHub, GitLab, Bitbucket, Azure DevOps)
- Cloud provider native (AWS Security Hub, Azure Defender, GCP SCC)

### 6.3 Deployment models

**Standard SaaS-edge deployment:**
Edge agent deployed in customer's cloud account or data center. Connected to centralized SaaS control plane via outbound HTTPS. Default deployment model for most customers.

**Hybrid deployment:**
Edge agents in multiple customer environments (cloud accounts, regional offices, factories, hospitals). All connected to single centralized control plane. Same single-tenant principles applied per-environment.

**Air-gapped deployment:**
Edge agents deployed with no control plane connectivity. Updates delivered via signed offline bundles through approved channels. Findings exported to customer SIEM via on-premises integration. For defense, classified, regulated environments.

**Multi-region deployment:**
For customers with data residency requirements (EU, APAC, regulated US), edge agents in customer's required regions with control plane components in matching residency regions.

### 6.4 Operating modes

**Continuous monitoring mode (default):**
Heartbeat-driven autonomous operation. Detection scanners run on configured schedules. Agent loop processes findings continuously. Customer interaction primarily through alerts, approvals, and conversational interface.

**Event-driven mode:**
Real-time response to critical events. Runtime Threat Agent and Network Threat Agent operate continuously rather than only on heartbeat. Active threats trigger immediate processing and Tier 1 actions where authorized.

**Investigation mode:**
Triggered by customer request or critical finding. Investigation Agent orchestrates deep-dive with sub-agent spawning. Extended budgets, deeper reasoning, comprehensive evidence collection.

**Compliance audit mode:**
Triggered by upcoming audit or customer request. Compliance Agent generates comprehensive evidence packages. Cross-references findings to control frameworks. Produces auditor-ready documentation.

**Onboarding mode:**
First 30 days of deployment. Conservative defaults. Higher human review thresholds. Baseline establishment for behavioral analytics. Tier 1 disabled by default.

### 6.5 What we explicitly do not include

Listed explicitly to prevent scope creep:

**Not included in any phase:**
- Full SIEM functionality (we forward to customer's SIEM, we are not their SIEM)
- Full SOAR platform (we orchestrate within our domain, we are not a generic SOAR)
- Endpoint Detection and Response (EDR) for general endpoints (we cover cloud workloads and runtime, we are not CrowdStrike)
- Email security
- DLP for endpoints
- Mobile device management
- Identity provider (we integrate with Okta/Azure AD, we are not them)
- Privileged Access Management (PAM)
- Penetration testing as a service
- Vulnerability scanning of network appliances and traditional infrastructure
- DDoS mitigation
- WAF management (we recommend, we don't operate)
- Bug bounty platform
- Security awareness training
- Backup and disaster recovery

**Not included in Phase 1 but added in subsequent phases:**

(Per Interpretation A, all capability layers ship in Phase 1. The list above represents permanent exclusions.)

---

## 7. DETAILED CAPABILITY SPECIFICATION

This section specifies every capability in production detail. Subsequent layer-specific documents (Detection Layer Document, Prevention Layer Document, etc.) provide implementation depth. This section establishes the contract.

### 7.1 Detection layer capabilities

#### 7.1.1 Cloud Security Posture Management (CSPM)

**Capability statement:**
Continuously detect misconfigurations across cloud infrastructure that violate security baselines, compliance frameworks, or customer-defined policies. Provide context-rich findings that include business impact, attack path implications, and remediation guidance.

**Coverage:**
- AWS: 1,200+ misconfiguration patterns across 100+ services
- Azure: 1,000+ patterns across 80+ services
- GCP: 800+ patterns across 60+ services
- Kubernetes: 600+ patterns across cluster, workload, network, RBAC
- Microsoft 365: 200+ patterns
- OCI and Alibaba Cloud: targeted coverage of 200+ patterns each (vertical-driven)

**Specific detection categories:**

Storage and data:
- Public storage buckets across S3, Blob, Cloud Storage
- Unencrypted storage at rest
- Missing access logging
- Missing versioning where required
- Cross-account access misconfigurations
- Lifecycle policy gaps
- Block public access setting violations
- Storage class misconfigurations

Compute:
- Public IPs in private subnets
- Security groups with overly permissive ingress
- Missing IMDSv2 enforcement
- Unencrypted EBS volumes and snapshots
- Default VPC usage
- Outdated AMIs
- Missing instance metadata protections

Database:
- Publicly accessible databases
- Missing encryption at rest
- Missing encryption in transit
- Weak password policies
- Missing automated backups
- Public snapshots
- Missing deletion protection
- Default credentials in use

Identity and access (basic — deep analysis in CIEM):
- Root account usage
- Missing MFA on root and privileged accounts
- Old access keys (>90 days)
- Weak password policies
- Cross-account trust relationships
- Federation misconfigurations

Logging and monitoring:
- Missing CloudTrail / Activity Log / Audit Log
- Missing VPC flow logs
- Missing DNS logging
- Disabled Config / Policy / SCC
- Missing log file validation
- Missing log encryption

Networking:
- Default VPC usage
- VPC peering misconfigurations
- NACL overly permissive
- Route table issues
- Missing WAF where appropriate
- TLS configuration weaknesses

Container and serverless:
- Public container registries
- Lambda functions with public invocation
- Functions with secrets in environment variables
- Cluster API server publicly accessible
- Privileged containers
- Container running as root
- Missing pod security standards

Application services:
- API Gateway misconfigurations
- Load balancer misconfigurations
- CloudFront/CDN misconfigurations
- Message queue access control issues

Encryption and key management:
- Customer-managed keys without rotation
- Key policies overly permissive
- Default encryption keys where customer keys required
- KMS key sharing issues

**Output specification per finding:**
- Unique finding identifier
- Asset identifier and resource details
- Misconfiguration type and severity
- Business impact reasoning (200-500 character contextualized explanation)
- Affected compliance controls (mapped to CIS, NIST, PCI, HIPAA, SOC 2, etc.)
- Recommended remediation (linked to Remediation Agent draft)
- Confidence score (0-1)
- First seen / last seen timestamps
- Status (active, acknowledged, suppressed, resolved)
- Related findings (graph relationships)
- Attack path implications if applicable

#### 7.1.2 Cloud Workload Protection Platform (CWPP)

**Capability statement:**
Detect runtime threats on cloud workloads including VMs, containers, serverless functions, and Kubernetes pods. Use eBPF-based monitoring for low-overhead deep visibility. Correlate runtime activity with infrastructure context for accurate threat assessment.

**Coverage:**
- Linux VMs (all major distributions)
- Windows VMs
- Containers (Docker, containerd, CRI-O)
- Kubernetes pods
- AWS ECS/Fargate
- Lambda functions (limited, function-level)
- Azure Functions
- Google Cloud Functions

**Specific detection categories:**

Process behavior:
- Suspicious process execution patterns
- Unusual parent-child relationships
- Process injection
- DLL injection
- LD_PRELOAD abuse
- Unusual binary execution from temp directories
- Reverse shell patterns
- Cryptocurrency mining activity

Container threats:
- Container escape attempts (host filesystem, host network, host PID)
- Privilege escalation within containers
- Capability abuse
- Mount-based escapes
- cgroup-based escapes
- Suspicious docker socket usage
- Privileged container abuse

Network activity (workload-level):
- Reverse shell connections
- C2 callbacks
- Cryptocurrency mining pools
- Tor network usage
- Unusual outbound connections
- Lateral movement within VPCs
- DNS tunneling
- ICMP tunneling

File integrity:
- Critical system file modifications
- Unauthorized config file changes
- Sensitive file access patterns
- Suspicious file writes to system directories
- Persistence mechanism creation
- Ransomware behavioral patterns

Kubernetes runtime:
- Pod creation with privileged settings outside expected pattern
- Service account token abuse
- Suspicious exec into pods
- Anomalous Kubernetes API usage
- Container runtime API abuse

Operating system:
- Persistence mechanisms (cron, systemd, rc.d, kernel modules)
- Privilege escalation exploitation
- Rootkit indicators
- Bootkit indicators
- LD_PRELOAD abuse
- Kernel module loading

Cloud control plane (workload-triggered):
- Workloads making unexpected cloud API calls
- IMDS abuse from compromised workloads
- Credential theft attempts
- Token replay attempts

**Detection mechanism:**
- Falco eBPF sensor (primary)
- Tracee as backup detection engine
- Tetragon for advanced kernel telemetry
- OSQuery for endpoint queryability
- Wazuh for HIDS-style file integrity monitoring

**Resource overhead:**
- Maximum 2% sustained CPU per host (verified through benchmark suite)
- Maximum 256 MB RAM per host
- Network bandwidth maximum 10 KB/sec sustained per host

**Output specification:**
Each runtime finding includes process tree, network connections, file activity, kernel events, MITRE ATT&CK technique mapping, threat intelligence correlation, severity assessment, recommended action (no_action, monitor, draft_quarantine, autonomous_kill).

#### 7.1.3 Cloud Infrastructure Entitlement Management (CIEM)

**Capability statement:**
Analyze identity and entitlement configurations across cloud providers to detect over-privileged identities, attack paths, anomalous access patterns, and identity-based threats. Calculate effective permissions across all policy types and recommend least-privilege replacements.

**Coverage:**
- AWS IAM: full coverage including SCPs, permission boundaries, session policies, resource policies, identity-based policies
- Azure RBAC: subscription, management group, resource group, resource scopes
- Azure AD / Entra ID: roles, groups, conditional access, federation
- GCP IAM: organization, folder, project, resource hierarchy
- Federation: SAML, OIDC, OAuth across providers
- Hybrid identity: on-premises AD synchronized to Azure AD/Entra

**Specific detection categories:**

Permission analysis:
- Effective permissions calculation across all policy types
- Permissions granted but never used (90-day usage window)
- Excessive permissions for role
- Privilege escalation paths
- Cross-account trust relationships
- Federated access risks
- Service-linked role abuse

Authentication and access control:
- Identities without MFA
- Long-lived access keys (>90 days)
- Weak password policies
- Default credentials
- Shared accounts
- Service accounts with interactive login enabled

Identity attack chains:
- User → assume role → privileged role → crown jewel asset
- Service account with excessive permissions accessible from compromised workload
- Federation chains exposing on-premises to cloud
- Cross-account chains across organization

Privileged access:
- Standing admin access where just-in-time should apply
- Break-glass account misuse
- Service account key sprawl
- Unused privileged accounts
- Orphaned accounts (inactive >180 days)

Anomalous behavior:
- First-time permission use
- Access from unusual geographic location
- Access at unusual time
- Unusual resource access pattern
- Authentication anomalies
- Token theft indicators

Federation security:
- SAML response manipulation indicators
- Conditional access bypass attempts
- OIDC misconfigurations
- Cross-tenant synchronization abuse

**Detection mechanism:**
- PMapper for AWS privilege escalation analysis
- Cloudsplaining for AWS policy danger analysis
- AWS IAM Access Analyzer integration
- Custom policy simulator engine
- Azure RBAC analyzer (custom implementation)
- GCP IAM analyzer (custom implementation)
- CloudTrail/Activity Log/Audit Log analysis for usage patterns

**Output specification:**
Each finding includes principal ARN/ID, finding type, effective permissions summary, unused permissions, attack paths if applicable, recommended policy (least-privilege replacement), severity, confidence.

#### 7.1.4 Data Security Posture Management (DSPM)

**Capability statement:**
Discover, classify, and protect sensitive data across cloud storage, databases, and AI workloads. Detect data exposure risks including public access, over-privileged access, residency violations, and unauthorized data flows.

**Coverage:**
- Cloud storage: S3, Azure Blob, GCP Cloud Storage, OCI Object Storage
- Databases: RDS, Cosmos DB, BigQuery, Snowflake, Azure SQL, Cloud SQL
- Data warehouses: Snowflake, Redshift, BigQuery, Databricks
- File systems: EFS, Azure Files, FSx, Filestore
- Streaming: Kinesis, Event Hubs, Pub/Sub
- AI/ML: SageMaker, Bedrock, Vertex AI, Azure AI

**Specific detection categories:**

Sensitive data discovery:
- Personally Identifiable Information (PII): names, addresses, phone, email, SSN, government IDs
- Protected Health Information (PHI): medical records, health identifiers, prescription data
- Payment Card Industry data (PCI): card numbers, CVVs, magnetic stripe data
- Financial data: account numbers, routing numbers, SWIFT, IBAN
- Authentication data: credentials, tokens, certificates
- Intellectual property markers
- Customer-defined sensitive patterns (custom classifiers)

Data exposure:
- Sensitive data in publicly accessible storage
- Sensitive data in development/staging environments
- Sensitive data accessible by over-privileged identities
- Sensitive data without encryption
- Sensitive data crossing residency boundaries
- Sensitive data in code repositories
- Sensitive data in CI/CD logs

Data flow:
- Cross-region data movement
- Cross-cloud data transfer
- Production-to-development data leaks
- External data sharing
- Data movement to AI services
- Unencrypted data in transit

Data lineage:
- Origin tracking for sensitive data
- Data copy chains
- Access history
- System processing chains

AI training data:
- Sensitive data in ML training sets
- Sensitive data exposed to LLM services
- Custom model training data classification
- AI service prompt logging containing sensitive data

**Detection mechanism:**
- Microsoft Presidio for ML-based PII classification (open source)
- AWS Macie integration for AWS data
- Microsoft Purview integration for Azure data
- GCP DLP API integration for GCP data
- Custom classifier engine for customer-specific patterns
- DataHub or OpenMetadata for lineage tracking
- eBPF-based data-in-motion monitoring (coordinated with CWPP)

**Privacy contract:**
The DSPM agent operates under strict privacy contracts:
- Never logs actual sensitive data values
- Only logs classifications and locations
- Sample-based scanning (statistical sampling, not exhaustive)
- Customer-controlled retention of classification results
- Classification-only outputs (no raw data exfiltration to control plane)

**Output specification:**
Each finding includes datastore identifier, sensitive data types detected (categories only), record count estimate, confidence, access exposure (public, accessible-by, encrypted), residency compliance, toxic combination flag, recommendation.

#### 7.1.5 Vulnerability Management

**Capability statement:**
Detect known vulnerabilities (CVEs) across cloud workloads, container images, infrastructure-as-code, and software dependencies. Prioritize vulnerabilities based on actual exploitability for the specific customer environment, not just CVSS scores.

**Coverage:**
- Container images: any registry (ECR, ACR, GCR, Docker Hub, Quay, Harbor, etc.)
- Virtual machines: Linux (RHEL, Ubuntu, Debian, Amazon Linux, SUSE, Alpine), Windows
- Serverless: Lambda, Azure Functions, GCP Cloud Functions
- Container orchestration: Kubernetes, ECS, Fargate
- Application dependencies: npm, pip, Maven, NuGet, Go modules, RubyGems, Cargo
- IaC: Terraform, CloudFormation, Kubernetes manifests, Helm charts, ARM templates, Pulumi, CDK

**Specific detection categories:**

Operating system vulnerabilities:
- Kernel CVEs
- System library CVEs (glibc, openssl, etc.)
- Package CVEs across distributions
- Runtime version vulnerabilities (Java, Python, Node.js, Go, Ruby)

Application vulnerabilities:
- Direct dependency CVEs
- Transitive dependency CVEs
- Vulnerable application frameworks
- Database engine CVEs

Container-specific:
- Image layer vulnerabilities
- Base image freshness
- Multi-stage build security
- Image signing verification
- Distroless vs full OS recommendations

Serverless-specific:
- Function runtime vulnerabilities
- Function layer vulnerabilities
- Permission misconfigurations contributing to vuln impact

Supply chain:
- Suspicious package patterns (typosquatting, dependency confusion)
- Malicious package detection
- License compliance issues
- Package signing verification
- SBOM (Software Bill of Materials) generation and analysis

IaC vulnerabilities:
- Terraform misconfigurations contributing to vulns
- Helm chart vulnerabilities
- Kubernetes manifest issues
- CloudFormation issues

**Prioritization mechanism:**
- CVSS v3 base score
- EPSS (Exploit Prediction Scoring System) score
- CISA KEV (Known Exploited Vulnerabilities) status
- Public exploit availability
- Asset criticality (from customer context)
- Network exposure (is vulnerable component reachable?)
- Active exploitation in customer's industry vertical
- Whether vulnerable component is actually executed (runtime correlation)

**Detection mechanism:**
- Trivy as primary scanner (containers, VMs, IaC, secrets)
- Grype as backup container scanner
- Syft for SBOM generation
- Dependency-Track for SCA continuous monitoring
- OSV-Scanner for OSV database queries
- Custom snapshot scanner for cloud workloads (SideScanning equivalent)

**Output specification:**
Each vulnerability finding includes CVE ID, affected assets, CVSS v3, EPSS score, KEV status, exploit availability, actual severity (after prioritization), fix availability, fix version, recommendation.

#### 7.1.6 Secrets Detection

**Capability statement:**
Detect exposed credentials, keys, and secrets across source code, configuration files, container layers, infrastructure-as-code, and runtime environment variables. Validate detected secrets against their issuing systems where possible to confirm active exposure.

**Coverage:**
- Source code repositories (GitHub, GitLab, Bitbucket, Azure DevOps)
- Container image layers
- Infrastructure-as-Code files
- Cloud configuration (environment variables, parameter stores)
- Local file systems on workloads
- Database content (limited)
- CI/CD pipeline logs

**Specific detection categories:**

Cloud credentials:
- AWS access keys and secret keys
- Azure service principals and SAS tokens
- GCP service account keys
- Cloud provider session tokens

API keys and tokens:
- Stripe, Twilio, SendGrid, and 800+ other service API keys
- OAuth access and refresh tokens
- JWT tokens with sensitive claims
- Webhook secrets

Authentication credentials:
- Database connection strings with embedded credentials
- LDAP/AD credentials
- SSH keys (RSA, ED25519, DSA)
- TLS private keys
- API keys from internal services

Cryptographic material:
- Private keys (PEM, PKCS#8, PKCS#12)
- HMAC keys
- Encryption keys
- Signing keys

Generic patterns:
- High-entropy strings in code
- Suspicious base64-encoded values
- Patterns matching credential formats

**Validation mechanism:**
For detected secrets, the agent attempts validation:
- AWS keys: STS GetCallerIdentity (read-only)
- Azure tokens: limited scope validation
- API keys: provider-specific validation endpoints
- Database connections: connection test (read-only)

Validation produces three states:
- Valid: secret is currently active and grants access
- Invalid: secret was rotated or revoked
- Unvalidated: validation infrastructure unavailable; treat as if valid

**Detection mechanism:**
- Trufflehog (primary) with 800+ secret detectors
- Gitleaks as backup
- detect-secrets for pre-commit hooks
- Custom regex engine for customer-specific patterns

**Output specification:**
Each secret finding includes secret type, location (file path, line, container layer, etc.), validation status, recommended action (rotate, revoke, investigate), severity, related findings.

#### 7.1.7 Infrastructure-as-Code Security

**Capability statement:**
Detect security misconfigurations in infrastructure-as-code before deployment. Integrate into developer workflows (CI/CD, pull requests, pre-commit) to prevent misconfigurations from reaching production.

**Coverage:**
- Terraform (HCL): all major providers
- CloudFormation (YAML/JSON)
- Kubernetes manifests (YAML)
- Helm charts
- ARM templates (Azure)
- Pulumi (TypeScript, Python, Go)
- AWS CDK (TypeScript, Python)
- Serverless Framework
- Ansible playbooks (limited)

**Detection categories:**

Same as CSPM categories applied to IaC:
- Storage misconfigurations declared in IaC
- Network misconfigurations
- IAM misconfigurations
- Encryption gaps
- Logging gaps
- Compliance violations

Plus IaC-specific:
- Hardcoded secrets in IaC
- Hardcoded credentials in module variables
- Insecure module sources
- Missing required tags
- Cost violations (oversized resources)
- License compliance in modules

**Integration points:**
- Pre-commit hooks (developer machine)
- Pull request scanning (GitHub, GitLab, Bitbucket)
- CI/CD pipeline integration (Jenkins, GitHub Actions, GitLab CI, CircleCI, etc.)
- Pre-deployment scanning (in deployment pipelines)

**Detection mechanism:**
- Checkov (primary) — same engine as Palo Alto Prisma Cloud
- KICS as backup
- tfsec for Terraform-specific
- terrascan for multi-IaC

**Output specification:**
Each IaC finding includes file path, line number, misconfiguration type, severity, suggested fix (with diff), related production resources if drift detection enabled.

#### 7.1.8 Network Threat Detection

**Capability statement:**
Detect network-layer threats including reconnaissance, lateral movement, command-and-control, and data exfiltration through network IDS, DNS analysis, and traffic flow analysis.

**Coverage:**
- VPC traffic (AWS), VNet traffic (Azure), VPC traffic (GCP)
- East-west traffic within cloud environments
- North-south traffic at cloud boundaries
- DNS traffic
- Cloud-to-on-premises traffic
- On-premises network traffic (where edge agents deployed)

**Specific detection categories:**

Reconnaissance:
- Port scans (TCP/UDP/SYN/FIN/XMAS/NULL)
- Port sweeps across hosts
- Service enumeration
- Vulnerability scanning patterns
- DNS enumeration

Lateral movement:
- Unexpected service-to-service communication
- East-west traffic violating microsegmentation
- Privilege escalation network indicators
- SMB-based lateral movement
- RDP-based lateral movement
- SSH-based lateral movement

Command and control:
- Beaconing patterns
- DGA (Domain Generation Algorithm) DNS queries
- DNS tunneling
- HTTPS to suspicious destinations
- Tor network usage
- Unusual user-agents

Data exfiltration:
- Large outbound transfers to unexpected destinations
- Data uploaded to file-sharing services
- DNS-based exfiltration
- ICMP-based exfiltration
- Unusual protocol usage

Denial of service:
- Volumetric attacks
- Protocol attacks (SYN flood, UDP amplification)
- Application-layer attacks
- Slow-rate attacks

Cloud-specific:
- Suspicious VPC peering activity
- Unusual cross-region traffic
- Direct Connect anomalies
- Transit gateway abuse
- VPN abuse

**Detection mechanism:**
- Suricata (rule-based IDS) with Emerging Threats Open ruleset
- Zeek (network analysis framework) for behavioral analysis
- Custom DGA detection model
- Beacon detection through temporal pattern analysis
- VPC Flow Logs API analysis
- DNS log analysis
- Threat intelligence-based IP/domain reputation

**Output specification:**
Each network finding includes finding type, source, destination, evidence (packet captures, flow records, DNS queries), confidence, recommended action.

#### 7.1.9 AI Security Posture Management (AI-SPM)

**Capability statement:**
Detect security risks in AI/ML infrastructure including unmanaged AI services, AI training data exposure, malicious models, and AI-specific attack techniques.

**Coverage:**
- AWS Bedrock, SageMaker
- Azure AI Services, Azure Machine Learning
- Google Vertex AI
- OpenAI API integrations
- Anthropic API integrations
- Self-hosted LLMs (Ollama, vLLM, etc.)
- ML pipelines (Kubeflow, MLflow, etc.)
- Model registries

**Specific detection categories:**

AI infrastructure:
- Unmanaged or shadow AI services
- AI services with public inference endpoints
- AI services without authentication
- AI services with sensitive training data
- Misconfigured AI access controls

Training data:
- Sensitive data in ML training sets (coordinates with DSPM)
- Sensitive data exposed to LLM services
- Training data residency violations
- Training data freshness gaps

Models:
- Malicious AI models (pickle deserialization vulnerabilities)
- Model files with embedded code
- Models from untrusted sources
- Model signing verification gaps

AI runtime:
- Anomalous AI service usage patterns
- Cost anomalies suggesting abuse
- Prompt injection attempts (from logs where available)
- Model output exfiltration patterns

Application AI security:
- Unauthorized AI API key usage
- API keys for AI services in source code (coordinates with secrets detection)
- Sensitive data flowing to external AI services without controls

**Detection mechanism:**
- Garak (NVIDIA) for LLM vulnerability scanning
- ModelScan (ProtectAI) for malicious model detection
- PyRIT (Microsoft) for AI red-teaming
- LLM Guard for input/output security
- Custom AI service inventory via cloud APIs
- MITRE ATLAS framework for adversary technique mapping

**Output specification:**
Each AI-SPM finding includes AI service identifier, risk type, severity, confidence, recommendation.

#### 7.1.10 Identity Threat Detection

**Capability statement:**
Detect active identity-based threats including credential theft, session hijacking, federation abuse, and authentication anomalies. Coordinate with CIEM for posture and Runtime Threat Agent for active response.

(Detailed in CIEM section 7.1.3 — this is the active threat dimension of identity.)

### 7.2 Prevention layer capabilities

#### 7.2.1 Pre-deployment IaC scanning

(Detailed in 7.1.7 above)

#### 7.2.2 Runtime policy enforcement

**Capability statement:**
Enforce security policies at runtime through Kubernetes admission controllers, network policies, and configuration drift prevention. Block unsafe configurations from reaching production.

**Mechanisms:**
- Kyverno admission controller for Kubernetes
- OPA Gatekeeper as alternative
- Custom admission webhooks
- Network policy enforcement
- Configuration drift detection and reversion

#### 7.2.3 Network microsegmentation recommendations

**Capability statement:**
Analyze network traffic patterns and recommend microsegmentation policies that minimize attack surface while preserving operational requirements.

**Mechanisms:**
- Traffic flow analysis through Network Threat Agent
- Communication graph generation
- Policy recommendation engine
- Phased rollout support
- Drift monitoring after deployment

#### 7.2.4 Identity drift prevention

**Capability statement:**
Detect changes to identity configurations that violate baseline policies and prevent or reverse unauthorized changes.

**Mechanisms:**
- Continuous monitoring of identity changes
- Baseline-vs-current comparison
- Just-in-time access recommendations
- Service account key rotation
- Federation configuration monitoring

#### 7.2.5 Pre-emptive threat blocking

**Capability statement:**
Block known-bad indicators (IPs, domains, hashes, URLs) before they can be exploited, based on threat intelligence and customer-specific threat exposure.

**Mechanisms:**
- IP blocking at WAF/firewall
- DNS-based blocking
- Container image policy enforcement
- File hash blocking via runtime sensor

### 7.3 Investigation layer capabilities

#### 7.3.1 Automated incident triage

**Capability statement:**
When critical findings or alerts occur, automatically triage to determine severity, scope, and required investigation depth.

**Process:**
- Initial event reception
- Severity classification
- Scope assessment (single asset vs multi-asset)
- Investigation depth determination (light, medium, deep)
- Routing to Investigation Agent if deep investigation required
- Notification to appropriate stakeholders

#### 7.3.2 Timeline reconstruction

**Capability statement:**
Reconstruct the sequence of events leading to and following a security event using cross-source telemetry.

**Sources:**
- Cloud control plane logs (CloudTrail, Activity Log, Audit Log)
- Runtime telemetry (Falco, eBPF events)
- Network telemetry (VPC flow logs, DNS logs, Suricata alerts)
- Identity events (authentication logs, federation events)
- Application logs (where available)
- Endpoint events (where applicable)

**Output:**
Chronological timeline with timestamped events, source attribution, technique mapping, asset correlation.

#### 7.3.3 Root cause analysis

**Capability statement:**
Determine the root cause of security incidents, distinguishing between contributing factors and the actual root cause that, if addressed, would have prevented the incident.

**Mechanism:**
- Five Whys methodology applied to evidence
- Counterfactual analysis (would addressing X have prevented this?)
- Failure mode classification
- Contributing factor identification
- Documentation in standardized format

#### 7.3.4 IOC pivoting and enrichment

**Capability statement:**
Extract indicators of compromise from incidents and pivot to find related compromised assets.

**Process:**
- IOC extraction (IPs, domains, hashes, file paths, registry keys, etc.)
- IOC enrichment (threat intelligence, reputation, attribution)
- Pivot search across customer environment
- Related incident detection
- Campaign correlation

#### 7.3.5 MITRE ATT&CK technique mapping

**Capability statement:**
Map observed attacker behavior to MITRE ATT&CK techniques to support analyst understanding and defensive planning.

**Coverage:**
- MITRE ATT&CK Enterprise Matrix
- MITRE ATT&CK Cloud Matrix
- MITRE ATLAS (AI-specific)
- Tactic and technique identification
- Sub-technique identification where evidence supports

#### 7.3.6 Cross-domain correlation

**Capability statement:**
Correlate events across cloud, identity, runtime, network, and data domains to identify attacks that span multiple domains.

**Capability examples:**
- Cloud control plane abuse + workload execution
- Identity compromise + lateral movement
- Network reconnaissance + workload exploitation
- Data exfiltration + identity abuse

#### 7.3.7 Forensic snapshot capture

**Capability statement:**
Capture forensic-quality snapshots of compromised workloads for offline analysis without disrupting production.

**Mechanisms:**
- EBS/Disk snapshots for AWS/Azure/GCP
- Memory dumps where supported
- Network packet captures
- Filesystem snapshots
- Container snapshots
- Signed, hashed, and stored in evidence locker

### 7.4 Remediation layer capabilities

#### 7.4.1 Three-tier remediation authority

**Tier 1 — Autonomous:**

Customer pre-authorizes specific action classes. Platform executes without human intervention within authorized scope. Auto-rollback timer per action. Customer kill switch for instant revocation.

Initial action classes available for Tier 1 authorization:
- Rotate confirmed-leaked AWS access keys
- Disable public S3/Blob/Cloud Storage ACLs on data flagged sensitive
- Quarantine confirmed-malicious workloads
- Block known-bad IPs at WAF (with TTL)
- Disable suspicious service accounts
- Revoke compromised user sessions
- Apply specific patches in non-production environments
- Remove stale unused IAM users

Each action class:
- Customer opt-in only (default off)
- Defined blast radius limit
- Mandatory automatic rollback timer
- Rate-limited
- Comprehensive audit trail
- Insurance partner credit eligible

**Tier 2 — Approval-Gated:**

Default for most remediations. Platform drafts complete remediation script. Sends to customer-configured approval channel. Customer approves with one click; platform executes. Customer rejects; platform records reasoning.

Approval channels:
- Slack message with approve/reject buttons
- Microsoft Teams adaptive card
- Email with signed approval link
- API for programmatic approval
- Console review and approval

**Tier 3 — Recommend-Only:**

For high-risk actions or where customer has not authorized higher tiers. Platform generates detailed recommendation. Human executes manually using their tools.

Always Tier 3 by default:
- IAM policy modifications affecting >10 users
- Production database modifications
- Network configuration changes affecting >25% of traffic
- Anything affecting cross-region replication

#### 7.4.2 Cloud Custodian policy execution

**Capability statement:**
Generate and execute Cloud Custodian policies for cloud configuration remediation. Cloud Custodian provides multi-cloud policy-as-code with built-in safety mechanisms.

**Coverage:**
- 1,000+ pre-built remediation policies
- Custom policy generation per finding
- Dry-run before execution
- Rollback capability
- Audit logging

#### 7.4.3 Terraform diff generation

**Capability statement:**
For customers using Terraform for infrastructure management, generate Terraform diffs that fix detected misconfigurations. Optionally create pull requests in customer's source control.

**Mechanism:**
- Map production resources to Terraform state
- Generate minimal diff to address finding
- Validate diff syntactically
- Optional: push as pull request to customer's repo
- Customer reviews and merges; their CI/CD applies

#### 7.4.4 Kubernetes manifest patching

**Capability statement:**
For Kubernetes-related findings, generate manifest patches that fix issues.

**Mechanism:**
- Generate kubectl patch or kustomize overlay
- Validate against admission policies
- Apply via kubectl or push to GitOps repo
- Verify after apply

#### 7.4.5 IAM policy least-privilege drafting

**Capability statement:**
For over-privileged identities, draft replacement policies that grant only the permissions actually used over a 90-day window.

**Process:**
- Analyze actual permission usage from CloudTrail
- Generate minimal policy
- Compare to current policy (show what's removed)
- Risk assessment of removed permissions
- Customer review and approval
- Apply with rollback capability

#### 7.4.6 Auto-rollback for autonomous actions

**Capability statement:**
Every Tier 1 autonomous action has an automatic rollback timer. If conditions are not validated within the rollback window, the action is automatically reversed.

**Mechanism:**
- Per-action rollback timer (default 1 hour, configurable per action class)
- Pre-action state capture
- Rollback procedure pre-computed
- Validation criteria defined
- Auto-rollback if validation fails or timer expires without explicit confirmation
- Rollback failure escalates to human immediately

#### 7.4.7 Multi-channel approval workflows

**Capability statement:**
Tier 2 remediations route through customer-configured approval workflows.

**Supported channels:**
- Slack (primary)
- Microsoft Teams
- Email
- ServiceNow approval workflow
- Jira approval workflow
- Custom webhook
- Console-based review

**Workflow features:**
- Configurable approver groups per action type
- Escalation if approval not received in time window
- Multi-approver for high-risk actions
- Audit trail with full context
- Approval reasoning capture

### 7.5 Compliance layer capabilities

#### 7.5.1 Continuous compliance monitoring

**Capability statement:**
Continuously assess customer environment against compliance frameworks. Detect drift from baseline. Surface emerging gaps before audits.

**Coverage:**
- 100+ compliance frameworks at launch
- Daily monitoring frequency
- Real-time monitoring for critical controls
- Historical posture tracking
- Drift detection and alerting

#### 7.5.2 Audit-ready evidence collection

**Capability statement:**
Collect, organize, and package evidence for compliance audits.

**Process:**
- Evidence requirement determination per control
- Automated evidence collection from platform telemetry
- Evidence packaging in auditor-preferred formats
- Cryptographic signing for evidence integrity
- Searchable evidence repository per audit

#### 7.5.3 Control-by-control framework mapping

**Capability statement:**
Map every detection rule, every finding, every remediation to applicable compliance controls across all supported frameworks.

**Frameworks supported at launch:**

General security:
- CIS Benchmarks (AWS, Azure, GCP, Kubernetes, Linux)
- NIST 800-53 Rev 5
- NIST Cybersecurity Framework 2.0
- ISO/IEC 27001:2022
- SOC 2 Type II Trust Services Criteria
- COBIT 2019

Privacy:
- GDPR (EU)
- CCPA/CPRA (California)
- PIPEDA (Canada)
- LGPD (Brazil)

Financial:
- PCI-DSS 4.0
- FFIEC Cybersecurity Assessment Tool
- NYDFS Part 500
- SWIFT CSP

Healthcare:
- HIPAA Security Rule
- HITRUST CSF
- HITECH

Government:
- FedRAMP Moderate
- FedRAMP High
- StateRAMP
- CMMC Level 1, 2, 3
- IL2, IL4, IL5

Cloud-specific:
- AWS Well-Architected Framework
- Azure Cloud Adoption Framework
- Google Cloud Architecture Framework
- AWS Foundational Technical Review (FTR)

Industry:
- NERC-CIP (electric utility)
- HIPAA + 42 CFR Part 2 (substance abuse)
- TSA Pipeline Security Directives
- IEC 62443 (industrial control systems)

International:
- BSI C5 (Germany)
- IRAP (Australia)
- TISAX (German automotive)
- C5 (German government)
- ENS (Spain)

Custom:
- Customer-defined frameworks
- Internal policy frameworks

#### 7.5.4 Compliance drift detection

**Capability statement:**
Detect when compliance posture degrades over time and alert before it becomes audit-blocking.

**Mechanism:**
- Daily compliance score per framework
- Trend analysis
- Threshold-based alerting
- Drift visualization in dashboard
- Predictive alerts (if trend continues, will fail next audit)

#### 7.5.5 Audit support and reporting

**Capability statement:**
Generate audit-ready reports and provide auditor-direct access to evidence.

**Report types:**
- Executive summary (board-level, 5-10 pages)
- Auditor evidence package (control-by-control with evidence)
- Internal compliance status (operational, monthly)
- Vertical-specific reports (HIPAA Security Rule report, PCI ROC support, etc.)
- Custom reports per customer requirement

**Auditor access:**
- Time-limited auditor access account
- Read-only evidence access
- Audit log of auditor activity
- Auditor question/answer interface

### 7.6 Threat intelligence capabilities

#### 7.6.1 Continuous external feed ingestion

**Capability statement:**
Continuously ingest threat intelligence from multiple external sources, normalize into unified format, and make available to all detection and reasoning systems.

**Sources at launch:**

Standards bodies:
- MITRE ATT&CK (Cloud, Enterprise, ICS)
- MITRE ATLAS (AI/ML)
- MITRE D3FEND
- CSA Cloud Controls Matrix

Government:
- CISA Known Exploited Vulnerabilities (KEV)
- CISA Alerts
- NIST National Vulnerability Database (NVD)

Cloud-specific:
- Wiz Cloud Threat Landscape (public RSS + STIX)
- AWS Security Bulletins
- Azure Security Bulletins
- GCP Security Bulletins

Industry:
- Unit 42 (Palo Alto) GitHub IOCs and reports
- CrowdStrike Global Threat Report
- Mandiant public reports
- Microsoft Threat Intelligence Center publications

Community:
- AlienVault OTX
- abuse.ch (URLhaus, ThreatFox, MalwareBazaar)
- VirusTotal Intelligence
- GreyNoise

Vertical:
- FS-ISAC (financial)
- H-ISAC (healthcare)
- E-ISAC (electricity)
- Auto-ISAC (automotive)
- Aviation-ISAC

OSS vulnerability:
- OSV (Open Source Vulnerabilities)
- GitHub Advisory Database
- npm Advisory Database
- PyPI vulnerability data

#### 7.6.2 Customer-specific threat correlation

**Capability statement:**
Correlate observed activity in customer environments to known threat actor behavior and active campaigns.

**Mechanisms:**
- Industry vertical → threat actor mapping
- Tech stack → relevant threat technique mapping
- Observed indicators → campaign attribution
- Behavioral pattern → threat actor TTPs
- Customer threat exposure scoring

#### 7.6.3 Active campaign tracking

**Capability statement:**
Track active threat campaigns relevant to customer environment. Notify customer when their environment exposure changes.

**Capability:**
- Real-time campaign feed
- Customer-specific relevance filtering
- Notification when campaign techniques observed in customer env
- Recommendation when new campaign emerges
- Retrospective hunting for campaign indicators

#### 7.6.4 Industry-specific threat briefings

**Capability statement:**
Generate periodic threat briefings tailored to customer's industry vertical, geographic region, and tech stack.

**Briefing schedule:**
- Daily: critical alerts only (automated)
- Weekly: industry threat summary (semi-automated)
- Monthly: comprehensive briefing (with human curation)
- Quarterly: executive threat report (heavily curated)

#### 7.6.5 Vulnerability exploitation prioritization

**Capability statement:**
For every vulnerability in customer environment, provide exploitation context: who's exploiting it, when, against whom, with what consequences.

**Data integration:**
- CISA KEV catalog
- Exploit code databases (Exploit-DB, Metasploit)
- Active exploitation reports
- Customer industry exposure
- Customer's specific asset exposure

### 7.7 Operational capabilities

#### 7.7.1 Conversational interface

**Capability statement:**
Customer interaction primarily through natural language conversation with the platform's agent system. Traditional dashboards available as secondary surface.

**Capabilities:**
- Natural language queries about findings, remediation, posture
- Multi-turn conversations with context retention
- Specialist agent routing (transparent to customer)
- Evidence and citation in responses
- Clarification questions when ambiguous
- Action initiation through conversation
- Audit trail of conversational decisions

#### 7.7.2 Real-time activity transparency

**Capability statement:**
Customers can see what the platform is doing in real time — what agents are observing, reasoning, deciding, executing. This is genuinely differentiating; competitors hide this.

**Surfaces:**
- Live activity feed in console
- Per-agent activity views
- Decision history with reasoning
- Action history with outcomes
- Health metrics
- Resource usage

#### 7.7.3 Multi-tier deployment

(Detailed in section 6.3)

#### 7.7.4 Multi-tenant isolation

**Capability statement:**
Strict per-customer data boundaries. No cross-tenant data access ever. Validated through SOC 2 audits and continuous internal verification.

**Mechanisms:**
- Tenant ID enforced at every database query
- Network segmentation between tenants
- Per-tenant encryption keys
- Cross-tenant query attempts logged and alerted
- Quarterly tenant isolation testing

#### 7.7.5 Comprehensive audit logging

**Capability statement:**
Every action by every agent, every API call, every state change recorded in immutable audit log with hash chain integrity.

**Coverage:**
- All agent invocations
- All tool calls
- All state changes
- All authorization decisions
- All approvals/rejections
- All Tier 1 autonomous actions
- All cross-tenant access attempts
- All authentication events

**Retention:** 7 years (most stringent compliance requirement).

#### 7.7.6 Self-evolution

**Capability statement:**
The platform continuously improves itself through Meta-Harness Agent reading raw execution traces and proposing optimizations. Optimizations are eval-gated, signed, and deployed via canary rollout.

**Operational details:**
- Customer-specific tuning is automatic
- Cross-customer pattern distillation is vendor-curated
- All optimization is auditable
- Customers see optimization activity in transparency surface
- Customers can opt out of self-evolution if desired

### 7.8 Integration capabilities

(Detailed in Integration Specification document. Summary listing in section 6.2.)

---

## 8. USER PERSONAS AND JOURNEYS

(Detailed personas in section 4.2. This section covers user journeys.)

### 8.1 Journey: VP Security evaluation

**Day 0:** Customer discovery call. Sales engineer walks through capability overview. Customer expresses interest in pilot.

**Day 1-7:** Pre-pilot preparation. Customer provides test cloud account, AWS read role, integration credentials. Platform deployed to test environment.

**Day 7-14:** Initial scan. Platform produces first findings. VP Security reviews with security architect. Findings calibrated against customer's known issues.

**Day 14-30:** Pilot evaluation. Daily usage by security team. Test integrations. Validate reporting. Compare to current tooling.

**Day 30-45:** Commercial discussion. Pricing finalized. Contract negotiation.

**Day 45-90:** Production rollout. Full cloud accounts. Full integrations. Production monitoring.

**Day 90+:** Optimization. Tuning. Tier 2 enabled. First compliance report. QBR.

### 8.2 Journey: Security analyst daily usage

**Morning:** Review overnight digest in Slack. Triaged findings show what platform handled, what needs human attention.

**Mid-morning:** Investigate flagged findings. Platform's investigation report provides timeline, evidence, recommendations. Analyst makes decisions, approves remediations.

**Mid-day:** Conversational interface for ad-hoc queries: "what changed in our AWS production account this week?" "Which assets are running CVE-2024-XXXX?"

**Afternoon:** Approve Tier 2 remediations. Review proposed actions, approve via Slack. Platform executes, validates, reports outcome.

**End of day:** Quick check on platform health. Any failed scans? Any pending issues?

### 8.3 Journey: Compliance officer audit prep

**90 days before audit:** Configure audit period in platform. Identify applicable frameworks.

**60 days before:** Review compliance posture trends. Address emerging gaps.

**30 days before:** Generate preliminary audit package. Review with internal team.

**14 days before:** Final remediation push for any remaining gaps.

**Audit:** Provide auditor with read-only access. Platform's evidence package answers most auditor questions automatically.

**Post-audit:** Review audit findings. Address any gaps for next cycle. Update compliance baselines.

### 8.4 Journey: Incident response

**Hour 0:** Critical alert. Platform's runtime detection identifies confirmed malware on production workload. Tier 1 quarantine executes if authorized; otherwise Tier 2 approval requested.

**Hour 0-1:** Investigation Agent automatically initiates deep investigation. Spawns sub-investigations for timeline, IOC, asset enumeration, attribution.

**Hour 1-2:** Investigation findings consolidated. Customer's SOC team receives comprehensive report: what happened, what's affected, what's contained, what's recommended next.

**Hour 2-8:** Containment, eradication, recovery executed with platform assistance.

**Day 1+:** Post-incident review with platform's reconstruction. Lessons learned feed into platform tuning.

---

## 9. FUNCTIONAL REQUIREMENTS

(Each functional requirement specified with ID, description, priority, acceptance criteria. This section is approximately 80 pages in production. Excerpt below for illustration.)

### 9.1 Detection requirements (FR-DET-*)

**FR-DET-001: AWS CSPM Coverage**
The system shall detect 1,200+ misconfiguration patterns across AWS services including but not limited to S3, EC2, IAM, RDS, KMS, Lambda, ECS, EKS, VPC, CloudTrail, Config.

Priority: P0
Acceptance criteria: Demonstrated detection of all CIS AWS Foundations Benchmark v3.0 controls, plus 500+ additional patterns. Validated through eval suite of 500 ground-truth test cases.

**FR-DET-002: Multi-cloud coverage**
The system shall provide CSPM coverage for AWS, Azure, GCP from launch.

Priority: P0
Acceptance criteria: Demonstrated detection of CIS Benchmarks Level 1 and Level 2 for each cloud provider.

**FR-DET-003: Real-time runtime detection**
The system shall detect runtime threats with maximum 30-second latency from event to alert.

Priority: P0
Acceptance criteria: 95th percentile latency under 30 seconds measured across MITRE ATT&CK runtime technique evaluation suite.

(Continues for all detection capabilities.)

### 9.2 Prevention requirements (FR-PREV-*)

(Detailed for each prevention capability.)

### 9.3 Investigation requirements (FR-INV-*)

(Detailed for each investigation capability.)

### 9.4 Remediation requirements (FR-REM-*)

(Detailed for each remediation capability.)

### 9.5 Compliance requirements (FR-COMP-*)

(Detailed for each compliance framework and capability.)

### 9.6 Operational requirements (FR-OP-*)

(Detailed for operational capabilities.)

### 9.7 Integration requirements (FR-INT-*)

(Detailed for each supported integration.)

---

## 10. NON-FUNCTIONAL REQUIREMENTS

### 10.1 Performance

- Edge agent CPU overhead: maximum 2% sustained per host
- Edge agent memory: maximum 256 MB per host (excluding scanner runs)
- Detection scan completion: 95th percentile under target time per scan type
- Alert latency: 95th percentile under 60 seconds for critical findings
- Remediation execution: 95th percentile under 5 minutes for Tier 2 approved actions
- Conversational interface response: 95th percentile under 5 seconds for most queries
- Console load time: 95th percentile under 2 seconds

### 10.2 Reliability

- Control plane uptime: 99.9% measured over rolling 30-day windows
- Edge agent uptime: 99.5% (customer infrastructure-dependent)
- Detection scan success rate: 99.5%
- Remediation execution success rate: 99% (excluding rollbacks)
- Mean time to recovery from incidents: under 1 hour for SEV-1, 4 hours for SEV-2

### 10.3 Scalability

- Customer scale: support 1,000+ customers per control plane region
- Per-customer scale: support 10,000+ workloads per customer
- Findings throughput: 1M+ findings ingested per day per customer
- Concurrent agent invocations: 10,000+ across platform
- Knowledge graph size: 100M+ nodes per customer subgraph

### 10.4 Security

(Detailed in Security Architecture Document. Summary requirements:)
- All data encrypted at rest and in transit
- Strict tenant isolation
- SOC 2 Type II certification
- Compliance with all customer-applicable frameworks
- Penetration testing quarterly
- Bug bounty program active
- Vulnerability response within SLA

### 10.5 Usability

- Time-to-first-finding: under 1 hour from deployment
- Time-to-meaningful-value: under 30 days from deployment
- New user onboarding: under 2 hours for security analyst
- Documentation completeness: every feature documented
- Internationalization: English at launch; Japanese, German, French in Phase 5

### 10.6 Maintainability

- Code quality: enforced via linting, type checking, code review
- Test coverage: 80%+ for production code
- Documentation: every public API documented
- Deployment frequency: continuous deployment with canary rollout
- Mean time to deploy fix: under 4 hours for critical bugs

---

## 11. INTEGRATION REQUIREMENTS

(Detailed in Integration Specification Document. Summary in section 6.2.)

---

## 12. COMPLIANCE AND REGULATORY REQUIREMENTS

### 12.1 Platform compliance certifications

Required at launch:
- SOC 2 Type I (in progress, complete by Month 12)
- HIPAA Business Associate Agreement capability
- GDPR DPA capability

Required Phase 2:
- SOC 2 Type II
- ISO 27001
- PCI-DSS Level 2

Required Phase 3-4:
- FedRAMP Moderate
- HITRUST CSF
- StateRAMP

Required Phase 5:
- FedRAMP High
- IL5 (DoD)
- C5 (Germany)

### 12.2 Regulatory requirements

- GDPR (EU): full compliance including data subject rights, DPA, data residency
- CCPA/CPRA (California): full compliance
- HIPAA (US healthcare): BAA capability, technical safeguards
- PCI-DSS: customer-side compliance support
- SEC cyber disclosure: customer support for breach reporting
- State data breach notification laws (50 states): customer support
- International data residency: EU, APAC, regulated US options

### 12.3 Customer compliance support

The platform supports customer compliance with frameworks listed in section 7.5.3.

---

## 13. OUT OF SCOPE (EXPLICIT EXCLUSIONS)

(Detailed in section 6.5.)

---

## 14. SUCCESS METRICS AND KPIS

### 14.1 Product success metrics

**Engagement metrics:**
- Daily active users per customer
- Findings reviewed per week
- Remediations approved per week
- Conversational queries per day
- Tier 1 actions executed per month
- Custom rules created per customer

**Quality metrics:**
- False positive rate (target: <10%)
- True positive rate (target: >85% for critical)
- Mean time to detection (target: <60 seconds for critical)
- Mean time to remediation (target: <5 minutes for Tier 2)
- Customer-reported issues per month (target: declining trend)

**Outcome metrics:**
- Customer security incidents (target: declining vs baseline)
- Audit pass rate (target: 100%)
- Compliance posture improvement
- Customer NPS (target: >50)

### 14.2 Business success metrics

**Revenue:**
- ARR by quarter (target: per phase plan)
- Net revenue retention (target: >120%)
- Gross revenue retention (target: >95%)
- Customer count
- Average contract value
- Sales cycle length

**Efficiency:**
- Customer acquisition cost
- LTV:CAC ratio (target: >3:1)
- Gross margin (target: 65-75%)
- Sales efficiency (Magic Number, target: >1.0)

**Growth:**
- New logos per quarter
- Expansion revenue per quarter
- Pipeline coverage (target: 3-4x quota)

---

## 15. PRICING AND PACKAGING

### 15.1 Pricing tiers

**Edge Pro — Mid-Market:**
- $30,000 base annual
- $5,000 per cloud account
- $10 per workload per month
- Includes: full detection stack, Tier 2 and Tier 3 remediation, Slack/Teams integration, business-hours support, 100-customer rule packs
- Target: 1,000-5,000 employee organizations
- Typical ACV: $50K-$120K

**Edge Enterprise — Hybrid Enterprise:**
- Custom pricing starting $150,000
- Per-account and per-workload structures
- Includes: full detection stack, Tier 1 + Tier 2 + Tier 3 remediation, all integrations, 24/7 support, custom rule pack authoring, dedicated CSM, air-gap deployment, vertical specialization
- Target: 5,000+ employee organizations, regulated industries
- Typical ACV: $200K-$500K

**Edge Open — Lead Generation:**
- Free tier
- Limited to: 1 cloud account, 50 workloads, generic rule packs only, no remediation, community support
- Conversion path to paid via product limits
- Drives: brand awareness, developer adoption, lead funnel

### 15.2 Pricing rationale

Edge Pro positions 40-60% below Wiz/CrowdStrike enterprise pricing while delivering 85% of capability plus differentiated features (autonomous remediation, edge deployment).

Edge Enterprise positions for high-touch sales to organizations needing customization, vertical specialization, or air-gap deployment.

Edge Open creates funnel without cannibalizing paid tiers.

### 15.3 Discounting policy

- Multi-year discounts: 10% for 2-year, 15% for 3-year
- Volume discounts: tiered by customer scale
- Initial customers (first 10 design partners): 50% discount in exchange for reference rights
- Vertical reference customers: 30% discount in exchange for case study and reference

### 15.4 Renewal and expansion

- Annual contracts standard
- Auto-renewal with 90-day cancellation notice
- Mid-term expansion at pro-rated rates
- True-up pricing for over-consumption

---

## 16. COMPETITIVE DIFFERENTIATION

(Detailed in Competitive Analysis Document. Summary positioning:)

**vs Wiz:** Edge deployment + autonomous remediation + mid-market pricing + vertical specialization. We don't compete in pure cloud-native enterprise.

**vs CrowdStrike Falcon Cloud:** Cloud-native depth + multi-agent architecture + edge deployment for non-endpoint contexts.

**vs Palo Alto Prisma:** Simplicity + autonomous capability + faster deployment + better mid-market fit.

**vs Lacework/Orca/Sysdig:** Multi-agent architecture + autonomous remediation + edge deployment.

**vs OT specialists (Claroty/Dragos):** Cloud + OT unified platform.

**vs Healthcare specialists (Medigate/Cynerio):** Cloud + medical IoT unified.

**vs MSSPs:** Platform plus partner-delivered service rather than pure managed service.

**vs DIY open-source:** Curated, supported, integrated, with SLAs and accountability.

---

## 17. RISKS AND OPEN QUESTIONS

### 17.1 Product risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Detection rule false positive rate too high | Medium | High | Conservative defaults, tuning service for new customers, FP monitoring |
| Tier 1 autonomous action causes outage | Low | Critical | Strict scoping, rollback timers, blast radius limits, insurance partnership |
| Edge deployment complexity exceeds customer capability | Medium | Medium | Standard packaging, automated installers, deployment partner program |
| Self-evolution drift in unintended directions | Low | High | Eval gating, signed deployments, monitoring, customer opt-out |
| LLM cost exceeds margin expectations | Low | High | Charter budget enforcement, model tier optimization, caching |
| Compliance certification delays | Medium | Medium | Compliance-first design, early auditor engagement |
| Multi-cloud coverage gaps embarrass at customer | Medium | Medium | Honest scoping, transparent roadmap, fast iteration |

### 17.2 Market risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Wiz adds edge deployment | Medium | High | Vertical specialization, integrated remediation, mid-market lock-in |
| Major LLM provider outage | Low | High | Multi-provider fallback architecture |
| Mid-market security spending contracts | Low | High | Diversification across verticals |
| Regulatory restrictions on agentic AI | Medium | Medium | Conservative autonomy, full auditability, compliance-first |

### 17.3 Open questions

- Optimal go-to-market motion: founder-led → AE-led → channel? Validate timing.
- Vertical sequence: healthcare first or manufacturing first? Customer discovery determines.
- Air-gap deployment timing: Phase 3 default. Earlier if defense customers materialize.
- International expansion: when to add EU and APAC? Likely Year 3.
- Acquisition vs IPO: don't decide yet. Optimize for optionality.

---

## 18. GLOSSARY

(Approximately 200 terms defined for production document. Excerpt:)

**Agent:** A combination of an LLM model and a harness implementing specific behavior. Distinct from "agent" in cybersecurity sense (which we call "edge agent" or "sensor").

**Charter:** The runtime laws governing all agents in the platform. Defines contracts, state management, communication, patterns, self-evolution, failure handling, observability.

**CNAPP:** Cloud Native Application Protection Platform. The product category dominated by Wiz, CrowdStrike, Palo Alto Prisma.

**Edge agent:** The single-tenant runtime deployed at customer environment. Houses detection scanners, local agents, customer-specific state.

**Heartbeat:** The 60-second cycle on which the supervisor agent triggers periodic processing.

**NLAH:** Natural Language Agent Harness. The structured natural language defining an agent's task-specific control logic.

**Specialist agent:** Domain-focused agent (Cloud Posture, Vulnerability, Identity, etc.) that does the actual security work under supervisor delegation.

**Supervisor:** The lightweight routing agent that delegates work to specialists. Does not perform detection or remediation directly.

**Tier 1/2/3:** Remediation authority tiers. Tier 1 autonomous within authorized action classes. Tier 2 approval-gated. Tier 3 recommend-only.

**Toxic combination:** Multi-condition risk where individual findings would be lower severity but the combination represents critical attack opportunity.

**Workspace:** Per-invocation file-backed state directory for agents.

(Continues for full glossary.)

---

## DOCUMENT ENDS

This PRD is the canonical source of truth for what we're building. All other product documents derive from this. Changes require founder approval and version control.

**Next documents:**
1. Vision Document (next, completes Batch 1)
2. Detailed Agent Specification (Batch 2)
3. Platform Architecture (Batch 2)
4. NLAH Authoring Guide (Batch 3)
5. Detection Engineering Methodology (Batch 3)
6. Layer-specific documents (Batch 3)
