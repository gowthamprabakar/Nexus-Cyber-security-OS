# PLATFORM ARCHITECTURE
## Engineering Blueprint — Deployment, Infrastructure, Operations

This document translates the agent specification and runtime charter into the engineered system. While the spec defines what each agent does and the charter defines the laws every agent operates under, this document defines how the actual platform is deployed, scaled, secured, and operated.

This is the document your engineering team builds from.

---

## DOCUMENT SET CONTEXT

This is document 3 of 3:
1. **Agent Specification** — fourteen agents, each with five-layer treatment
2. **Runtime Charter** — universal physics governing all agents
3. **Platform Architecture** (this document) — engineered system

Read together, these three documents fully specify the platform.

---

## PART 1 — DEPLOYMENT TOPOLOGY

### 1.1 The two-plane model

The platform has two planes:

**Control Plane (your SaaS):**
- Runs in your cloud (AWS recommended for Phase 1, multi-cloud later)
- Multi-tenant — serves all customers
- Houses: master knowledge graph, threat intel pipeline, fleet manager, eval infrastructure, control APIs, customer console
- Owns: rule registry, NLAH versions, eval suites, signing keys

**Edge Plane (per customer):**
- Runs in customer's environment
- Single-tenant — one deployment per customer
- Houses: detection scanners, local agents, workspace storage, customer-specific persistent state
- Reports to control plane

This separation is non-negotiable. It's modeled on CrowdStrike Falcon's proven architecture (sensor at edge, brain in cloud) and provides:
- Customer data sovereignty (sensitive data stays at edge)
- Latency for real-time response (Runtime Threat Agent acts locally)
- Air-gap deployment option (edge can run disconnected)
- Scaling independence (control plane scales by tenant count, edge scales per customer)

### 1.2 Control plane architecture

```
                    ┌─────────────────────────┐
                    │   Customer Console       │
                    │   (Next.js + Tailwind)   │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │    API Gateway           │
                    │    (Kong + Rate Limit)   │
                    └────────────┬────────────┘
                                 │
        ┌────────────────────────┼────────────────────────┐
        │                        │                        │
┌───────▼────────┐   ┌──────────▼──────────┐   ┌─────────▼─────────┐
│ Conversational │   │   Tenant Manager     │   │   Fleet Manager   │
│ API (FastAPI)  │   │   (Customers, RBAC)  │   │   (Edge agents)   │
└───────┬────────┘   └──────────┬──────────┘   └─────────┬─────────┘
        │                        │                        │
        └────────────────────────┼────────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │  Agent Runtime           │
                    │  (Charter + Agents)      │
                    └────────────┬────────────┘
                                 │
        ┌────────────┬───────────┼───────────┬────────────┐
        │            │           │           │            │
┌───────▼──────┐ ┌──▼───────┐ ┌─▼────────┐ ┌▼─────────┐ ┌▼─────────┐
│ LLM Service  │ │ Knowledge│ │ Findings │ │ Rule     │ │ Threat   │
│ (Anthropic)  │ │ Graph    │ │ Lake     │ │ Registry │ │ Intel    │
│              │ │ (Neo4j)  │ │(ClickHse)│ │ (PG+S3)  │ │ Pipeline │
└──────────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘
                                 
                    ┌────────────┴────────────┐
                    │  Audit Service           │
                    │  (Append-only, signed)   │
                    └─────────────────────────┘
                    
                    ┌─────────────────────────┐
                    │  Eval Infrastructure     │
                    │  (Test suites, runner)   │
                    └─────────────────────────┘
                    
                    ┌─────────────────────────┐
                    │  Meta-Harness Service    │
                    │  (NLAH optimization)     │
                    └─────────────────────────┘
```

### 1.3 Edge plane architecture

```
                    ┌─────────────────────────┐
                    │  Edge Manager (Go)       │
                    │  - Heartbeat scheduler   │
                    │  - Update receiver       │
                    │  - Health reporter       │
                    └────────────┬────────────┘
                                 │
        ┌────────────────────────┼────────────────────────┐
        │                        │                        │
┌───────▼─────────┐    ┌─────────▼─────────┐    ┌────────▼──────────┐
│ Detection       │    │ Local Agent       │    │ Telemetry         │
│ Scanners        │    │ Runtime           │    │ Collector         │
│ - Prowler       │    │ - Lightweight     │    │ - Vector / Fluent │
│ - Trivy         │    │   reasoning       │    │                   │
│ - Falco         │    │ - Charter subset  │    │                   │
│ - Cartography   │    │                   │    │                   │
│ - Checkov       │    │                   │    │                   │
│ - PMapper       │    │                   │    │                   │
│ - Trufflehog    │    │                   │    │                   │
│ - Kubescape     │    │                   │    │                   │
└─────────────────┘    └───────────────────┘    └───────────────────┘
                                 │
        ┌────────────────────────┼────────────────────────┐
        │                        │                        │
┌───────▼─────────┐    ┌─────────▼─────────┐    ┌────────▼──────────┐
│ Local           │    │ Workspace         │    │ Cloud API         │
│ Knowledge       │    │ Storage           │    │ Gateway           │
│ - Neo4j Comm.   │    │ (Local FS + S3)   │    │ (Per-cloud SDKs)  │
│ - SQLite        │    │                   │    │                   │
│ - TimescaleDB   │    │                   │    │                   │
└─────────────────┘    └───────────────────┘    └───────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │  Remediation Executor    │
                    │  (Cloud Custodian)       │
                    └─────────────────────────┘
                    
                    ┌─────────────────────────┐
                    │  Local Audit Log         │
                    │  (Tamper-evident)        │
                    └─────────────────────────┘
                    
                    ┌─────────────────────────┐
                    │  Credentials Vault       │
                    │  (HashiCorp Vault)       │
                    └─────────────────────────┘
```

### 1.4 Communication between planes

**Edge → Control Plane (always allowed):**
- Outbound HTTPS only
- Authenticated with per-customer mTLS certificate
- Encrypted with customer-managed key
- Compressed with zstd
- Sends: findings, telemetry, health reports, completed action audit logs

**Control Plane → Edge:**
- No direct inbound to edge (security requirement)
- Edge polls or maintains long-lived gRPC stream
- Pushes: signed rule packs, NLAH updates, configuration changes, fleet commands

**No edge-to-edge communication.** Each customer's edge is isolated.

### 1.5 Air-gap mode

For defense, classified, regulated customers:
- Edge runs entirely disconnected
- Updates delivered via signed bundles through approved channels (USB, MFT, cross-domain solution)
- Findings exported to customer SIEM via on-prem integration
- Bundle import has integrity verification before applying
- Local audit log replicated to customer-managed backup

Air-gap mode requires deployment Phase 3 features (air-gap bundler, offline rule pack format).

---

## PART 2 — INFRASTRUCTURE COMPONENTS

### 2.1 Control plane infrastructure

| Component | Technology | Purpose | Phase |
|---|---|---|---|
| **API Gateway** | Kong or AWS API Gateway | Public API, rate limiting, auth | 1 |
| **Customer Console** | Next.js 15 + Tailwind | Web UI | 1 |
| **Conversational API** | FastAPI + LangGraph | Chat interface backend | 1 |
| **Tenant Manager** | PostgreSQL + Go service | Customers, RBAC, billing | 1 |
| **Agent Runtime** | Python 3.12 + Anthropic SDK | Charter + agents execution | 1 |
| **LLM Service** | Anthropic API (Claude Sonnet primary) | Reasoning calls | 1 |
| **Knowledge Graph** | Neo4j Enterprise (clustered) | Master semantic graph | 1 |
| **Findings Lake** | ClickHouse | Aggregate findings analytics | 1 |
| **Rule Registry** | PostgreSQL + S3 | Versioned signed rules | 1 |
| **Threat Intel Pipeline** | Apache Airflow + Python | External feed ingestion | 1 |
| **Fleet Manager** | Go service + Kubernetes API | Edge agent management | 1 |
| **Audit Service** | PostgreSQL (append-only) + S3 | Hash-chained audit log | 1 |
| **Notification Engine** | Go service + Slack/Teams/SMS | Alert routing | 1 |
| **Compliance Reports** | Python + ReportLab | PDF generation | 1 |
| **Eval Infrastructure** | Python + custom test runner | Agent eval suites | 1 |
| **Meta-Harness Service** | Python + Anthropic SDK | NLAH optimization | 2 |
| **Signing Service** | AWS KMS or HSM | Rule pack signing | 1 |
| **Canary Controller** | Go service | Tiered rollout management | 2 |
| **FP Monitor** | Python + ClickHouse queries | Auto-detect rule regressions | 2 |
| **Auto-Rollback** | Go service | Revert bad deployments | 2 |
| **Differential Updater** | Go service | Delta-based updates | 2 |
| **Air-Gap Bundler** | Go service | Offline rule pack generation | 3 |

### 2.2 Edge plane infrastructure

| Component | Technology | Purpose | Phase |
|---|---|---|---|
| **Edge Manager** | Go binary | Heartbeat, updates, health | 1 |
| **Detection Scanners** | Open-source tools (see spec) | Run continuous scans | 1 |
| **Local Agent Runtime** | Python 3.12 (lightweight) | Charter subset + agents | 1 |
| **Local Knowledge Graph** | Neo4j Community | Customer subgraph | 1 |
| **Local Findings Store** | TimescaleDB | Episodic memory | 1 |
| **Local Procedural Memory** | PostgreSQL | Procedural memory | 1 |
| **Workspace Storage** | Local FS + optional S3 backup | Per-invocation workspaces | 1 |
| **Telemetry Collector** | Vector or Fluent Bit | Log/metric forwarding | 1 |
| **Cloud API Gateway** | Per-cloud SDKs + adapter layer | All cloud API calls | 1 |
| **Credentials Vault** | HashiCorp Vault Community | Customer cloud credentials | 1 |
| **Remediation Executor** | Cloud Custodian | Execute approved remediations | 2 |
| **Local Audit Log** | Append-only file + hash chain | Tamper-evident logging | 1 |
| **Update Manager** | Go binary | Receive signed packs, hot-reload | 1 |
| **Health Reporter** | Go binary | Periodic health to control plane | 1 |

### 2.3 Resource sizing

**Control plane (Phase 1, 5-10 customers):**
- Kubernetes cluster: 3 control nodes + 6 worker nodes (m5.xlarge equivalent)
- Neo4j cluster: 3 nodes (r5.xlarge)
- ClickHouse cluster: 3 nodes (m5.2xlarge)
- PostgreSQL: HA pair (db.r5.large)
- Total: ~$8-12K/month infrastructure

**Control plane (Phase 4, 75-150 customers):**
- Kubernetes cluster: scaled to 30+ worker nodes
- Neo4j cluster: 5 nodes (r5.2xlarge)
- ClickHouse cluster: 5 nodes (m5.4xlarge)
- Total: ~$50-80K/month

**Edge plane per mid-market customer:**
- 4 vCPU, 16 GB RAM, 100 GB storage
- ~$200-400/month if customer-hosted on their cloud

**Edge plane per enterprise customer:**
- 16 vCPU, 64 GB RAM, 500 GB storage
- ~$1-2K/month customer-hosted

---

## PART 3 — DATA MODEL

### 3.1 Customer data model

```
Customer
├── tenant_id (UUID)
├── identity (org name, billing, contacts)
├── tier (Edge Pro | Edge Enterprise)
├── authorization_profile
│   ├── tier_1_authorizations (action classes opted in)
│   ├── tier_2_approvers (who can approve)
│   └── tier_3_recipients (where recommendations go)
├── compliance_subscriptions (frameworks customer cares about)
├── communication_preferences
└── integrations (Slack, SIEM, ticketing)

CustomerEnvironment (per customer)
├── cloud_accounts (AWS, Azure, GCP)
├── kubernetes_clusters
├── on_prem_zones
├── asset_inventory (synced via Cartography)
└── custom_classifiers (for DSPM)

CustomerContext (semantic memory, per customer)
├── business_hours
├── change_windows
├── asset_criticality_map
├── known_good_patterns (exceptions)
├── industry_vertical
├── tech_stack_profile
└── threat_profile
```

### 3.2 Operational data model

```
Finding
├── finding_id (UUID)
├── customer_id
├── detected_by (agent name)
├── detected_at (timestamp)
├── asset (reference)
├── rule (reference to detection rule)
├── severity (info | low | medium | high | critical)
├── confidence (0-1)
├── status (active | acknowledged | suppressed | resolved)
├── compliance_impacts (frameworks affected)
└── attached_remediation (if any)

Remediation
├── remediation_id
├── customer_id
├── finding_id (parent)
├── tier (1 | 2 | 3)
├── action_artifact (the actual code)
├── rollback_plan
├── approval_status (pending | approved | rejected | autonomous)
├── execution_status
├── outcome (success | failed | rolled_back)
└── audit_trail

Incident (when investigation triggered)
├── incident_id
├── customer_id
├── triggered_by (finding(s))
├── investigation_report (path to workspace)
├── timeline
├── root_cause
├── adversary_techniques (MITRE)
├── containment_actions
├── eradication_actions
└── post_mortem_path
```

### 3.3 Knowledge graph data model

(Per spec — Technique, ThreatActor, CVE, MisconfigurationPattern, DetectionRule, RemediationAction, ComplianceControl, AssetType, IndustryVertical, plus per-customer subgraph nodes)

---

## PART 4 — SECURITY ARCHITECTURE

### 4.1 The product is a security target

Threat model: a security platform that gets compromised is catastrophic. Architectural security must match defensive sophistication.

### 4.2 Edge agent security

**Binary integrity:**
- All edge binaries cryptographically signed
- Signature verified at every startup
- Tamper detection runs continuously
- Unsigned binaries refuse to run

**Network security:**
- No inbound network access ever
- Outbound HTTPS only, mTLS authenticated
- Certificate pinning for control plane
- DNS-over-HTTPS to prevent DNS poisoning

**Local security:**
- All sensitive data encrypted at rest (customer-specific keys)
- Workspace files have strict permissions
- Credentials in Vault, never in plaintext config
- Audit log signed and hash-chained

**Privilege model:**
- Edge agent runs as dedicated non-root user
- Cloud API access via per-customer scoped IAM roles
- No long-lived credentials anywhere
- Just-in-time credential provisioning where possible

**Update security:**
- Rule packs and binary updates signed with HSM-backed keys
- Multi-party signing for major updates
- Canary rollout (1% → 10% → 50% → 100%)
- Automatic rollback on detection of issues

### 4.3 Control plane security

**Tenant isolation:**
- Strict per-customer data boundaries
- Tenant ID enforced at every database query layer
- Cross-tenant query attempts logged and alerted
- Network segmentation between customer data

**Encryption:**
- All data encrypted at rest (KMS-managed customer keys for sensitive data)
- All data encrypted in transit (TLS 1.3)
- Workspace contents encrypted with customer-specific keys
- Audit logs additionally encrypted with separate keys

**Access control:**
- SSO-only for internal access (Okta or Azure AD)
- MFA required, hardware tokens for production access
- Just-in-time access elevation
- All access logged immutably
- Quarterly access reviews

**Code signing:**
- All deployed code signed
- Build pipeline verifies signatures
- Production releases gated by multi-party approval
- Bug bounty program for vulnerabilities

### 4.4 LLM call security

**Prompt safety:**
- Customer data sanitization before LLM calls
- PII redaction where possible (Presidio in-line)
- Prompt injection detection on customer inputs
- Output validation before action

**Data residency:**
- LLM provider region matches customer requirements
- EU customers use EU LLM endpoints
- Sensitive data never sent to LLM if avoidable
- Caching with proper boundaries

**Cost protection:**
- Per-customer LLM spend caps
- Anomaly detection on cost patterns
- Auto-throttling on suspicious spikes
- Charter enforces budget caps per Article 2

### 4.5 Self-evolution security

**NLAH update integrity:**
- All NLAH versions signed
- Multi-party approval for major rewrites
- Eval gate non-bypassable
- Production rollout monitored and reversible

**Eval suite integrity:**
- Eval ground truth hash-checked
- Eval suite changes audit-logged
- Synthetic test cases reviewed before inclusion

### 4.6 Compliance certifications

Target certifications by phase:

**Phase 1-2 (Months 1-15):**
- SOC 2 Type I (Month 12)
- HIPAA Business Associate Agreement capability
- GDPR DPA capability

**Phase 2-3 (Months 16-21):**
- SOC 2 Type II (Month 18)
- ISO 27001
- PCI-DSS Level 2

**Phase 4 (Months 22-30):**
- FedRAMP Moderate
- HITRUST CSF (for healthcare vertical)
- StateRAMP (for state government)

**Phase 5+ (Months 31+):**
- FedRAMP High (for defense/classified customers)
- IL5 capability (DoD)
- C5 (German federal)

---

## PART 5 — OPERATIONS

### 5.1 Reliability targets

| Metric | Phase 1 | Phase 2 | Phase 4 |
|---|---|---|---|
| Control plane uptime | 99.5% | 99.9% | 99.95% |
| Edge agent uptime | 99% | 99.5% | 99.9% |
| Findings ingestion latency | < 5 min | < 2 min | < 1 min |
| Critical finding to alert | < 5 min | < 2 min | < 30 sec |
| Tier 1 action latency | N/A | < 60 sec | < 30 sec |
| Approval queue P95 | N/A | < 10 min | < 5 min |
| Customer console load time | < 2 sec | < 1.5 sec | < 1 sec |

### 5.2 SLO definition and monitoring

Service Level Objectives (SLOs) per service:

```yaml
slo:
  service: agent_runtime
  sli:
    - name: invocation_success_rate
      target: 99.5%
      window: 30d
    - name: invocation_p95_latency
      target: 60s
      window: 30d
  error_budget: 0.5% over 30 days
  alerting:
    - 50% budget consumed: warning
    - 80% budget consumed: page
    - 100% budget consumed: incident
```

SLOs are reviewed monthly with engineering leadership.

### 5.3 Incident response

**On-call rotation:**
- 24/7 coverage from Phase 2 onward
- Primary + secondary on-call
- Escalation to engineering leadership
- Customer communication via dedicated incident channel

**Severity levels:**
- **SEV-1:** Customer impact + data integrity at risk (CEO informed within 15 min)
- **SEV-2:** Customer impact, no data risk (Engineering leadership informed within 30 min)
- **SEV-3:** Degraded service, no customer-facing impact (Team lead informed)
- **SEV-4:** Internal issue, no customer impact (Standard ticket)

**Postmortem process:**
- Required for all SEV-1 and SEV-2
- Blameless culture
- Action items tracked in JIRA with owners
- Patterns reviewed quarterly

### 5.4 Customer onboarding

**Standard onboarding (mid-market, 30-60 days):**

Week 1: Discovery
- Kickoff call
- Environment review
- Authorization profile design
- Integration planning

Week 2-3: Deployment
- Edge agent deployment
- Cloud account integration
- Initial scanning configured
- Tier 3 (recommend-only) active

Week 4-6: Tuning
- False positive review
- Custom rule needs identified
- Customer baseline established
- First Tier 2 approvals demonstrated

Week 7-8: Production
- Tier 2 active
- SOC integration complete
- Customer success cadence established
- 30-day review scheduled

**Enterprise onboarding (60-120 days):**
- Add: vertical-specific configuration, custom compliance frameworks, air-gap deployment if needed, multi-region rollout
- Add: dedicated CSM assigned at kickoff

### 5.5 Customer success operating model

| Customer Tier | CSM Coverage | Response Time SLA |
|---|---|---|
| Edge Pro (mid-market) | Pooled CSM, 1 per 30 customers | Business hours, 4 hour |
| Edge Enterprise | Dedicated CSM, 1 per 5 customers | 24/7, 1 hour |

CSM responsibilities:
- Quarterly business reviews
- Quarterly threat landscape briefings (industry-specific)
- Authorization tier expansion guidance
- Custom rule pack design
- Audit support

---

## PART 6 — DEVELOPMENT AND DEPLOYMENT

### 6.1 Development environment

- Source control: Git (GitHub Enterprise)
- CI/CD: GitHub Actions + ArgoCD
- Infrastructure as Code: Terraform + Helm
- Local development: Devcontainers + tilt for hot reload
- Code review: mandatory two-reviewer for all changes
- Testing: pytest, Go testing, integration test environment

### 6.2 Deployment pipeline

```
Developer commits to feature branch
  ↓
PR created
  ↓
CI runs: linting, unit tests, integration tests, security scan
  ↓
Code review (2 reviewers)
  ↓
Merge to main
  ↓
CD pipeline:
  1. Build artifacts (signed)
  2. Deploy to staging
  3. Run smoke tests
  4. Deploy to canary (1% traffic)
  5. Monitor metrics for 4 hours
  6. Auto-promote if healthy
  7. Gradual rollout: 10% → 50% → 100%
  8. Auto-rollback if anomalies detected
```

### 6.3 Release cadence

- **Hot fixes:** Same-day for critical bugs
- **Detection rule updates:** Daily push (signed, canary-rolled)
- **NLAH updates:** Weekly (eval-gated, signed)
- **Charter updates:** Quarterly
- **Major features:** Monthly minor versions, quarterly major versions

### 6.4 Engineering team structure

**Phase 1 team (Months 4-9):**

```
Founders (2-3, including technical co-founder)
└── Principal Detection Engineer
    ├── Senior Backend Engineer (Agent Runtime)
    ├── Senior Backend Engineer (Detection Stack)
    ├── Senior Frontend Engineer (Console)
    └── DevOps/Platform Engineer
```

Total: ~7-8 people

**Phase 2-3 team (Months 10-21):**

Add:
- 2 more detection engineers (specialists per agent)
- 1 threat intelligence analyst
- 1 security engineer (compliance, pen testing)
- 1 product designer
- 2 customer success managers

Total: ~14-15 people

**Phase 4 team (Months 22-30):**

Add:
- VP Engineering
- VP Sales
- 4-5 more engineers
- 2-3 vertical specialist AEs
- 2 more CSMs
- Partner manager (MSSP channel)

Total: ~25-30 people

---

## PART 7 — COST MODEL

### 7.1 Unit economics per customer

**Mid-market customer (Edge Pro):**

Revenue: $50K-$100K ACV (avg $75K)

COGS per customer:
- LLM API costs: $600-1500/month ($7-18K/yr)
- Cloud infrastructure (control plane share): $200-400/month ($2-5K/yr)
- Threat intel licensing share: $50/month ($600/yr)
- Customer success cost (pooled CSM share): $200/month ($2.4K/yr)
- Support tooling share: $50/month ($600/yr)
- Total COGS: $13-26K/yr

Gross margin: 65-75%

**Enterprise customer (Edge Enterprise):**

Revenue: $200K-$500K ACV (avg $300K)

COGS per customer:
- LLM API costs: $2-5K/month ($24-60K/yr)
- Cloud infrastructure: $500-1K/month ($6-12K/yr)
- Dedicated CSM share: $2K/month ($24K/yr)
- Threat intel + compliance: $200/month ($2.4K/yr)
- Total COGS: $56-98K/yr

Gross margin: 67-81%

### 7.2 Operating expenses

**Phase 1 (Months 4-9):**
- Engineering: $1.6-2M (8 people × $200K loaded)
- Sales/CS: $250K (founder-led + 1 AE)
- Tools/infra: $200K
- Legal/compliance: $200K
- Marketing: $100K
- Total: ~$2.5M

**Phase 2-3 (Months 10-21):**
- Engineering: $3-3.5M
- Sales/CS: $1M
- Tools/infra: $400K
- Legal/compliance: $300K
- Marketing: $300K
- Total: ~$5-6M

**Phase 4 (Months 22-30):**
- Engineering: $5-6M
- Sales/CS: $3-4M
- Tools/infra: $800K
- Legal/compliance: $400K
- Marketing: $1M
- Total: ~$10-12M

### 7.3 Funding plan

**Seed: $3M (Month 1)**
- Carries through Phase 1
- Targets: 5 paying customers, MVP shipped, Tier 3 working

**Series A: $12-15M (Month 18)**
- Carries through Phase 2-3
- Targets: $5M ARR, SOC 2 Type II, 50+ customers

**Series B: $30-40M (Month 30+)**
- Carries through Phase 4 expansion
- Targets: $25M ARR, vertical dominance, MSSP channel

### 7.4 Path to profitability

Default-alive at ~$15M ARR with 70% gross margin. This means:
- Year 3: still investing for growth, ~30% of revenue burn
- Year 4: approaching break-even
- Year 5: profitable or strategic exit

Strategic exit (acquisition) is a credible alternative outcome. Cybersecurity M&A multiples are strong; OT security and vertical-specialized cloud security are explicitly undervalued. Year 3-4 acquisition offers from Wiz/CrowdStrike/Palo Alto plausible.

---

## PART 8 — IMPLEMENTATION ROADMAP DETAIL

### 8.1 Phase 0 — Validation (Months 1-3)

**Engineering:**
- Repo setup, infrastructure provisioning
- Basic charter implementation (contracts, file-backed state)
- Three-agent prototype (Supervisor, Cloud Posture, Vulnerability) working in dev
- Integration with Anthropic API

**Customer development:**
- 30 customer discovery interviews
- 5 design partner LOIs
- Pricing validation
- ICP refinement

**Hiring:**
- Principal Detection Engineer hired
- 2 senior engineers hired
- Founding team complete

**Funding:**
- $3M seed raised
- 18-24 months runway

**Exit gate:**
- 5 LOIs from design partners in target ICP
- Pricing model validated
- Founding team complete and aligned
- Three-agent prototype demonstrates basic supervisor + 2 specialists working

### 8.2 Phase 1 — MVP (Months 4-9)

**Engineering deliverables:**
- Charter v1.0 complete (all 9 articles implemented)
- Agents v1: Supervisor, Cloud Posture (AWS), Vulnerability, Compliance (basic), Investigation (basic), Threat Intel (basic), Remediation (Tier 3 only), Synthesis, Audit
- Detection scanners integrated: Prowler, Trivy, Cartography, Falco (basic), Checkov, Trufflehog, Kubescape
- Customer console v1 (chat-first interface)
- Threat intel pipeline (5 sources)
- Knowledge graph v1
- Audit service with hash chain
- Edge agent deployable as Helm chart
- AWS-only multi-account support
- SOC 2 Type I in progress

**Customer deliverables:**
- 3-5 paying customers (design partners converted)
- $200-300K ARR
- Customer console functional
- Slack integration
- Splunk webhook integration

**Exit gate:**
- 3 paying customers using product weekly
- Tier 3 agent stable in production
- 60% Wiz CSPM coverage on AWS
- Eval suite for shipped agents passing
- $300K ARR achieved

### 8.3 Phase 2 — Multi-Cloud + Tier 2 (Months 10-15)

**Engineering deliverables:**
- Azure support across all relevant agents
- GCP basic support
- Identity Agent in production
- Runtime Threat Agent in production (Falco-based)
- Tier 2 (approval-gated) remediation
- ChatOps approval flows (Slack + Teams)
- Curiosity Agent v1
- Meta-Harness Agent v1 (manual triggering)
- Improved knowledge graph (semantic memory)
- SOC 2 Type II achieved

**Detection coverage targets:**
- 75% Wiz CSPM (multi-cloud)
- 85% vulnerability management
- 70% CIEM (multi-cloud basic)
- 90% Kubernetes security
- 90% IaC scanning

**Customer deliverables:**
- 10-15 paying customers
- $500K-$1M ARR
- Splunk + Sentinel + ServiceNow + Jira + PagerDuty integrations
- HIPAA, SOC2, PCI compliance reports

**Exit gate:**
- 10 paying customers
- 75% Wiz coverage achieved
- SOC 2 Type II
- Self-evolution operational (manual trigger)
- $750K ARR

### 8.4 Phase 3 — Autonomous + Vertical (Months 16-21)

**Engineering deliverables:**
- Tier 1 (narrow autonomous) for 3-5 action classes
- Data Security Agent in production
- Network Threat Agent in production
- Vertical specialization (healthcare + manufacturing rule packs)
- Air-gap deployment option
- Cloud-to-code correlation (basic)
- Mobile app
- Advanced attack path analysis (more toxic combinations)

**Detection coverage targets:**
- 80% Wiz CSPM (full multi-cloud)
- 80% CIEM
- 75% DSPM
- 75% network threat detection
- 60% AI-SPM

**Customer deliverables:**
- 25-50 paying customers
- $1.5-3M ARR
- First Tier 1 customers (with insurance partner credits)
- Industry conference presence

**Exit gate:**
- 25 paying customers
- 80% Wiz coverage
- Tier 1 in production for 5+ customers
- $2M ARR
- Series A raised

### 8.5 Phase 4 — Scale + 85% Coverage (Months 22-30)

**Engineering deliverables:**
- SideScanning equivalent for AWS
- Production-grade DSPM with all classifiers
- Full AI-SPM module
- 10+ vertical compliance packs
- MSSP channel infrastructure
- Marketplace presence (AWS, Azure)
- Mature self-evolution (auto-deployment with strict criteria)

**Detection coverage targets (85% Wiz overall):**
- 85% CSPM
- 95% vulnerability management
- 90% CIEM
- 85% DSPM
- 85% network threat detection
- 85% AI-SPM
- 85% attack path analysis
- 80% cloud-to-code

**Customer deliverables:**
- 75-150 paying customers
- $5-10M ARR
- 5-10 MSSP partners
- 3-4 vertical references

**Exit gate:**
- 75 paying customers
- 85% Wiz coverage demonstrated
- $5M ARR
- Path to $25M ARR clear
- Acquisition or Series B option viable

### 8.6 Phase 5+ — Compounding Beyond (Months 31+)

- 90% coverage by Month 42
- 95% coverage by Month 54
- $25-50M ARR
- Acquisition or IPO trajectory

---

## PART 9 — RISK REGISTER

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Wiz adds edge deployment | Medium | High | Vertical specialization, integrated remediation, mid-market lock-in |
| Open-source upstream becomes hostile | Low | Medium | Hard forks within 90 days, alternatives at every layer |
| LLM cost spikes uncontrollably | Low | High | Charter budget enforcement, model tier optimization, caching |
| SOC 2 audit failure | Low | Critical | Compliance-first design, quarterly internal audits |
| Tier 1 autonomous action causes outage | Low | Critical | Strict gating, rollback timers, narrow scope, insurance |
| Talent acquisition challenges | Medium | High | Competitive comp, equity, mission, distributed-first |
| Customer churn from rule false positives | Medium | High | Conservative defaults, tuning service, FP monitoring |
| Major LLM provider outage | Low | High | Multi-provider fallback (Anthropic primary, OpenAI secondary) |
| Competitive feature parity (CrowdStrike) | High | Medium | Vertical depth, edge architecture, mid-market focus |
| Regulatory change in agentic AI | Medium | Medium | Conservative autonomy, full auditability, compliance-first |

---

## PART 10 — THE BOTTOM LINE

This architecture delivers:

**85% Wiz capability by Month 30** through the curated open-source detection foundation orchestrated by 14 specialized agents under the runtime charter, with deferred capabilities (SideScanning, full GCP, cloud-to-code) shipped through Phase 4.

**Autonomous agent layer** through the multi-agent supervisor pattern with three-tier remediation authority, file-backed state, contract-enforced execution, and self-evolution via Meta-Harness Agent. Genuinely novel product category.

**Edge mesh deployment** through single-tenant edge runtime + centralized SaaS control plane, modeled on CrowdStrike Falcon's proven architecture. Air-gap deployment for regulated customers in Phase 3.

**Defensible moats** through:
- Edge architecture Wiz cannot easily replicate (committed to centralized SaaS)
- Runtime charter with file-backed state, contracts, self-evolution (years of engineering to copy)
- Vertical specialization in healthcare, manufacturing, fintech, defense
- Mid-market accessibility at price points enterprise tools cannot serve
- Integrated detection + remediation + edge that no competitor combines

**Capital efficiency:**
- $3M seed → MVP and 5 customers (18-month runway)
- $12-15M Series A → Phase 2-3 to $5M ARR
- $30-40M Series B (optional) → Phase 4 expansion or strategic exit

**Team scale:**
- Phase 1: 8 people
- Phase 4: 25-30 people
- Manageable through Claude Code amplification + open-source foundation

**Time to milestones:**
- Month 9: First paying customers
- Month 18: SOC 2 Type II + $1M ARR
- Month 30: $5M ARR + 85% coverage + Series A
- Month 60: $25M+ ARR or strategic exit

**The unknowns at this point are not technical.** The architecture is buildable. The charter is implementable. The agents are specifiable. The infrastructure is conventional.

The remaining unknowns are market validation. The 30-customer discovery sprint in Phase 0 remains the single most important piece of work before commitment.

---

## DOCUMENT SET COMPLETE

You now have:

1. **Agent Specification** — what each of 14 agents does, with five-layer treatment
2. **Runtime Charter** — universal physics governing all agents, the technical moat
3. **Platform Architecture** (this) — engineered system, deployment, operations, business model

Together these specify a buildable, fundable, defensible cybersecurity platform that delivers 85% Wiz capability, autonomous agentic remediation, and edge mesh deployment through compounding execution over 30 months to a venture-scale outcome.

The kingdom is mapped. The territory awaits validation.

**Next steps in priority order:**
1. Validate ICP with 30 customer interviews (Month 1-3)
2. Hire Principal Detection Engineer (Month 1-2)
3. Raise $3M seed (Month 1-3)
4. Build three-agent prototype to demonstrate viability (Month 2-3)
5. Convert design partner LOIs to first paying customers (Month 4-9)
6. Execute the roadmap

The plan is solid. Go test it against reality.
