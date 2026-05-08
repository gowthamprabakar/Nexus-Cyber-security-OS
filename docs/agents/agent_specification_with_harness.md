# HARNESS-ENGINEERED AGENT SPECIFICATION
## Each Agent Specced With Full Five-Layer Treatment

This is the operational specification for every agent in the platform. Each agent is defined across five dimensions of harness engineering:

1. **Three-layer description** — backend infrastructure, charter participation, NLAH (natural language agent harness)
2. **Execution contract template** — required outputs, budgets, permissions, completion conditions
3. **File-backed state schema** — what files this agent reads/writes, their structure
4. **Self-evolution criteria** — failure signals that trigger harness rewrite
5. **Pattern usage declaration** — which canonical patterns the agent uses

Plus the original spec dimensions: domain, hire test, detection scope, prevention level, resolution capability, tools, memory, coordination, Wiz mapping, coverage.

This specification is what you build from. The runtime charter and architecture documents follow this.

---

## OVERVIEW — THE FOURTEEN AGENTS WITH HARNESS PRINCIPLES

| # | Agent | Type | Phase | Patterns Used |
|---|---|---|---|---|
| 0 | Supervisor | Lightweight router | 1 | Routing |
| 1 | Cloud Posture | Specialist | 1 | Chaining, Eval-Optimizer |
| 2 | Vulnerability | Specialist | 1 | Chaining, Parallelization |
| 3 | Identity | Specialist | 1 | Chaining, Eval-Optimizer |
| 4 | Runtime Threat | Specialist | 2 | Routing, Eval-Optimizer |
| 5 | Data Security | Specialist | 2 | Chaining, Parallelization |
| 6 | Network Threat | Specialist | 2 | Routing, Eval-Optimizer |
| 7 | Compliance | Specialist | 1 (basic) | Parallelization |
| 8 | Investigation | Specialist | 1 | Orchestrator-Workers, Chaining |
| 9 | Threat Intel | Specialist | 1 | Parallelization |
| 10 | Remediation | Specialist | 1 (Tier 3) | Chaining, Eval-Optimizer |
| 11 | Curiosity | Support | 2 | Parallelization |
| 12 | Synthesis | Support | 1 | Orchestrator-Workers |
| 13 | Meta-Harness | Support | 2 | Eval-Optimizer |
| 14 | Audit | Support | 1 | Chaining |

Note: Memory Curator from prior spec is replaced by **Meta-Harness Agent** which subsumes its function plus self-evolution. Synthesis Agent added per harness principles to keep Supervisor lightweight.

---

## AGENT 0 — SUPERVISOR AGENT

### Domain
Routing only. Lightweight delegation to specialists. Per harness principles, supervisor delegates ~90% of compute to child agents.

### Hire test
Senior SOC dispatcher — knows which analyst handles which finding type, knows when to fan-out, doesn't do the analysis themselves.

### Three-layer description

**Backend infrastructure:**
- Heartbeat scheduler (Kubernetes CronJob or systemd timer)
- Distributed lock service (Redis or etcd) for per-customer concurrency control
- Message queue for delegation (NATS or Redis Streams)
- Customer authorization service
- Audit log writer

**Runtime charter participation:**
Supervisor is the only agent that triggers from heartbeat. It is also the only agent allowed to:
- Spawn parallel specialist invocations
- Update shared customer context memory
- Authorize Tier 1 actions (after specialist drafts them)
- Hand off to Synthesis Agent for customer-facing output

Subject to charter rules:
- Maximum delegation depth: 2 (supervisor → specialist → at most one child)
- Must record every delegation in audit log before specialist begins work
- Cannot itself call detection or remediation tools

**NLAH (task-specific control logic):**
File `supervisor/nlah.md` — structured natural language defining:

```
ROLE: Security operations dispatcher

OBJECTIVE: For each heartbeat cycle, observe deltas in customer environment
and route work to appropriate specialists. Do not analyze. Delegate.

ROUTING RULES (consulted in order):

  IF delta_type = "S3 misconfiguration" → route to Cloud Posture Agent
  IF delta_type = "CVE detected" → route to Vulnerability Agent
  IF delta_type = "IAM permission change" → route to Identity Agent
    AND Cloud Posture Agent if config-related
  IF delta_type = "runtime alert" → route to Runtime Threat Agent
    AND Investigation Agent if confirmed-malicious
  IF delta_type = "data exposure" → route to Data Security Agent
  IF delta_type = "network anomaly" → route to Network Threat Agent
  IF delta_type = "compliance drift" → route to Compliance Agent
  IF delta_type = "novel pattern" → route to Investigation Agent for triage
  IF customer_query (natural language) → route to relevant specialist
    OR Synthesis Agent if multi-domain

PARALLEL DELEGATION RULES:
  Independent findings → fan-out in parallel
  Dependent findings → sequence with explicit handoffs
  Cross-cloud findings → parallel per cloud, then synthesis

FAILURE HANDLING:
  Specialist exceeds budget → log, escalate to Investigation Agent
  Specialist returns low confidence → request second opinion from peer specialist
  Specialist hits tool error → check Backend health, fallback specialist if available

WHAT YOU NEVER DO:
  - Run detection tools yourself
  - Make remediation decisions yourself
  - Synthesize multi-specialist outputs (delegate to Synthesis Agent)
  - Skip audit logging
```

### Execution contract template

When supervisor invokes a specialist:

```yaml
contract:
  delegation_id: <UUID>
  source_agent: supervisor
  target_agent: <specialist_name>
  task: <structured task description>
  required_outputs:
    finding_id: required
    severity: enum [info, low, medium, high, critical]
    confidence: float [0, 1]
    next_actions: array of structured action proposals
  budget:
    max_llm_calls: 10
    max_tokens: 16000
    max_wall_clock_seconds: 60
  permitted_tools: <subset of specialist's full toolset for this task>
  completion_condition: |
    All required_outputs populated
    AND confidence >= 0.6 OR escalate_with_reason
  escalation_rules:
    - if_budget_exceeded: report partial, return to supervisor
    - if_tool_failure: retry once, then report and return
    - if_confidence_low: request_second_opinion from peer
  workspace: /workspaces/<customer_id>/<delegation_id>/
```

### File-backed state schema

```
/workspaces/<customer_id>/supervisor/
  current_heartbeat.json          # current cycle state
  routing_history.jsonl           # append-only routing decisions log
  active_delegations.json         # delegations in flight
  peer_health.json                # specialist health snapshot
  customer_context.md             # shared customer context (read-only for specialists)
  authorization_profile.yaml      # tier 1/2/3 authorizations per action class
```

### Self-evolution criteria

Supervisor harness rewrite triggered when:
- Routing accuracy < 90% over rolling 1000 heartbeats (wrong specialist chosen)
- Average delegation depth > 1.5 (over-delegation indicating routing logic error)
- Specialist failure rate > 5% (suggests routing too-complex tasks to underpowered specialists)
- Customer satisfaction signal degraded (manual review cases increase)

When triggered: Meta-Harness Agent reads raw routing logs, proposes new `supervisor/nlah.md`, runs against eval suite, accepts if improvement.

### Pattern usage declaration

Primary: **Routing** (the entire job)
Secondary: **Parallelization** (when independent findings can fan-out)
Forbidden: Orchestrator-Workers (delegated to specialists), Eval-Optimizer (delegated to Meta-Harness)

### Tools (kept minimal per harness principle)

1. `delegate_to(agent_name, task, contract)` — primary action
2. `delegate_parallel(delegations[])` — fan-out
3. `query_routing_table()` — read agents.md
4. `read_customer_context()` — shared memory
5. `update_customer_context(entry)` — write shared memory (only supervisor allowed)
6. `check_tier1_authorization(action_class)` — authorization lookup
7. `escalate_to_human(message, severity)` — human handoff
8. `request_synthesis(specialist_outputs[])` — call Synthesis Agent
9. `record_audit(action, context)` — audit log write

**Total: 9 tools. Deliberately minimal.**

### Coverage and Wiz mapping
N/A — supervisor has no Wiz analog. Pure orchestration layer.

---

## AGENT 1 — CLOUD POSTURE AGENT

### Domain
Cloud Security Posture Management. Misconfigurations across AWS/Azure/GCP/K8s.

### Hire test
Cloud security analyst. Reviews configurations, knows CIS benchmarks, identifies attack surface.

### Three-layer description

**Backend infrastructure:**
- Prowler binary + Python wrapper
- Steampipe runtime + cloud plugins (AWS, Azure, GCP)
- Cloud Custodian (read-only mode for this agent)
- AWS Config / Azure Policy / GCP Security Command Center API clients
- Neo4j read connection (posture subgraph queries)
- ScoutSuite as backup scanner

**Runtime charter participation:**
- Subject to budget contracts on every invocation
- Reads from shared customer context (asset inventory, exceptions)
- Writes only to its own private workspace and posture findings store
- Cannot directly write to knowledge graph (must go through supervisor)
- Must log every cloud API call to its workspace for traceability
- Inherits charter's retry-with-backoff semantics for cloud API calls

**NLAH:**
File `cloud_posture/nlah.md`:

```
ROLE: Cloud security posture analyst

EXPERTISE:
  - AWS Well-Architected Framework, Azure Cloud Adoption Framework, GCP Architecture Framework
  - CIS Benchmarks (current versions for AWS, Azure, GCP, K8s)
  - Common misconfiguration patterns and their attacker abuse vectors
  - Business-context interpretation (production vs dev, regulated vs non-regulated)

DECISION HEURISTICS:
  H1: Severity is contextual. Check customer_context.md for asset criticality before scoring.
  H2: Always check for customer exceptions (user.md) before flagging.
  H3: Group findings by root cause. One alert per misconfiguration pattern, not per affected resource.
  H4: Provide business impact reasoning, not just technical detail.
  H5: When uncertain about severity, lean conservative (lower severity, recommend rather than autonomous).

STAGES (chained execution):
  Stage 1: SCAN — invoke appropriate scanner based on task scope
  Stage 2: ENRICH — for each finding, query asset context from graph
  Stage 3: ASSESS — apply heuristics to determine severity
  Stage 4: RECOMMEND — generate remediation hint (handoff to Remediation Agent)
  Stage 5: HANDOFF — return structured findings to supervisor

FAILURE TAXONOMY:
  F1: Cloud API rate limit hit → exponential backoff, log, partial result acceptable
  F2: Scanner returns malformed output → log raw, fall back to backup scanner
  F3: Finding cannot be enriched (asset not in graph) → flag for graph refresh, return with low confidence
  F4: Severity assessment ambiguous → escalate to Investigation Agent, do not guess

CONTRACTS YOU REQUIRE:
  - cloud account credentials available in customer_context.md
  - asset inventory in graph less than 24 hours old (else trigger refresh)
  - Prowler scanner binary version >= 5.0

WHAT YOU NEVER DO:
  - Execute remediations (handoff to Remediation Agent)
  - Make decisions outside posture domain (delegate to peer specialists)
  - Skip the customer exception check
  - Alert on findings without business context
```

### Execution contract template

```yaml
contract:
  delegation_id: <UUID>
  source_agent: supervisor
  target_agent: cloud_posture
  task:
    type: scan | assess_finding | enrich_finding
    scope:
      cloud_provider: aws | azure | gcp | k8s
      account_id: <id>
      regions: <list> | all
      check_categories: <list> | all
      scope_filter: <optional asset filter>
  required_outputs:
    findings:
      - finding_id: <UUID>
        category: <CIS control or NIST control>
        severity: enum [info, low, medium, high, critical]
        affected_assets: array
        business_impact: text (200-500 chars)
        remediation_hint: structured object
        compliance_impact: array of framework_id
        confidence: float [0, 1]
        evidence: array of evidence references
  budget:
    max_llm_calls: 8
    max_tokens: 12000
    max_wall_clock_seconds: 90
    max_cloud_api_calls: 200
  permitted_tools:
    - run_prowler_scan
    - run_steampipe_query
    - query_aws_config | query_azure_policy | query_gcp_scc
    - aws_describe_resource | azure_describe_resource | gcp_describe_resource
    - query_posture_graph
    - recall_similar_findings
    - check_customer_exception
    - get_customer_baseline
  forbidden_tools:
    - any execute_* tool
    - any tools belonging to peer specialists
  completion_condition: |
    All findings have populated severity, business_impact, remediation_hint, confidence
    AND confidence >= 0.6 for each finding OR escalate_with_reason
  escalation_rules:
    - severity_ambiguous: handoff to Investigation Agent
    - identity_dimension: handoff to Identity Agent for IAM analysis
    - vulnerability_dimension: handoff to Vulnerability Agent
  workspace: /workspaces/<customer_id>/<delegation_id>/cloud_posture/
```

### File-backed state schema

```
/workspaces/<customer_id>/<delegation_id>/cloud_posture/
  task.yaml                    # the contract for this invocation
  scan_inputs.json             # what we're scanning
  scan_outputs/
    prowler_raw.json           # raw scanner output
    steampipe_results.json     # SQL query results
    enrichment.json            # asset context lookups
  findings/
    <finding_id>.yaml          # one file per finding
    finding_index.json         # finding catalog
  reasoning_trace.md           # LLM reasoning log (raw, for Meta-Harness)
  cloud_api_log.jsonl          # every cloud API call made
  output.yaml                  # final structured output for supervisor

/persistent/<customer_id>/cloud_posture/
  customer_baseline.yaml       # what's normal for this customer
  exceptions.yaml              # known-good patterns (user.md)
  finding_history.jsonl        # episodic memory (last 90 days)
  remediation_effectiveness.json # procedural memory
```

### Self-evolution criteria

Triggers harness rewrite via Meta-Harness Agent:
- False positive rate > 15% over rolling 500 findings
- Customer marks finding as "not applicable" repeatedly for similar patterns
- Severity assessment disputed by Compliance Agent in cross-check
- Time-to-completion exceeds budget on > 20% of invocations
- Confidence scores cluster < 0.7 (suggests model uncertain about domain)

Self-evolution mechanism:
1. Meta-Harness Agent reads `reasoning_trace.md` from failed invocations (raw, not summary)
2. Identifies patterns in failure (e.g., "agent consistently misses business context for K8s findings")
3. Proposes refinement to `cloud_posture/nlah.md` (e.g., "add explicit K8s asset criticality lookup")
4. Tests refinement against eval suite (curated set of 200 historical findings with ground truth)
5. Accepts refinement if eval score improves AND no regression on existing tests
6. Versions and signs the new nlah.md, deploys via fleet manager

### Pattern usage declaration

**Primary patterns:**
- **Prompt chaining** — Stage 1 (scan) → Stage 2 (enrich) → Stage 3 (assess) → Stage 4 (recommend)
- **Evaluator-optimizer loop** — Self-evolution via Meta-Harness reading traces

**Secondary patterns:**
- **Routing** — When multi-domain finding, route enrichment to peer specialist

**Not used:**
- Parallelization (sequential nature of stages)
- Orchestrator-workers (this agent IS a worker, not an orchestrator)

### Tools

(Same as prior spec — 17 tools. Listed in NLAH's permitted_tools per task.)

### Coverage progression

| Phase | Coverage | Detection Rules | Cloud Coverage |
|---|---|---|---|
| 1 | 25% Wiz CSPM | 250 patterns | AWS only |
| 2 | 50% | 450 patterns | AWS + Azure |
| 3 | 65% | 800 patterns | AWS + Azure + GCP |
| 4 | 85% | 1300 patterns | + K8s deep, OCI/Alibaba targeted |

---

## AGENT 2 — VULNERABILITY AGENT

### Domain
CVE management across workloads, IaC scanning, secrets in code, supply chain.

### Hire test
Vulnerability manager / SCA engineer.

### Three-layer description

**Backend infrastructure:**
- Trivy binary + Python wrapper
- Grype as backup
- Syft for SBOM generation
- Checkov + KICS for IaC
- Trufflehog + Gitleaks for secrets
- NVD API client, OSV API client, CISA KEV checker, EPSS scorer
- GitHub Advisory Database client

**Runtime charter participation:**
- Same charter rules as Cloud Posture
- Special permission: can write to vulnerability_findings store directly (high-volume, low-risk writes)
- Inherits parallelization primitive — can scan multiple targets concurrently within budget

**NLAH:**
File `vulnerability/nlah.md`:

```
ROLE: Vulnerability management specialist

EXPERTISE:
  - CVE landscape, exploitability assessment
  - CVSS, EPSS, KEV, exploit code availability
  - Software composition analysis (SCA)
  - IaC misconfiguration patterns
  - Secret detection patterns and validation
  - Supply chain attack patterns

DECISION HEURISTICS:
  H1: CVSS alone is insufficient. Always check KEV, EPSS, customer asset criticality.
  H2: Active exploitation (KEV) elevates severity regardless of CVSS.
  H3: Vulnerable code that's not actually executed is lower priority than running vulnerable code.
  H4: Validate detected secrets — invalid secrets are noise.
  H5: Group CVEs by affected component and fix availability.

STAGES (chained, with parallelization opportunity):
  Stage 1: ENUMERATE — list scan targets
  Stage 2: SCAN (parallel) — scan all targets concurrently
  Stage 3: ENRICH — for each CVE, lookup KEV, EPSS, exploit availability
  Stage 4: VALIDATE_SECRETS — check if detected secrets are actually valid (Trufflehog validation)
  Stage 5: ASSESS — determine actual exploitability for THIS customer
  Stage 6: PRIORITIZE — order by exploitability × asset criticality
  Stage 7: RECOMMEND — patch path, fix availability, workarounds
  Stage 8: HANDOFF — return to supervisor

FAILURE TAXONOMY:
  F1: NVD/OSV/KEV API timeout → use cached data, mark confidence lower
  F2: Image too large to scan in budget → scan top layers only, flag incomplete
  F3: Cannot determine if CVE applies (configuration-dependent) → mark as "potentially affected"
  F4: Secret validation fails (network/auth issues) → mark as "unvalidated", treat as if valid

CONTRACTS YOU REQUIRE:
  - Container images accessible from edge agent
  - Cloud workload inventory in graph
  - NVD API key (for higher rate limit)
  - CISA KEV catalog refreshed within 24 hours

WHAT YOU NEVER DO:
  - Execute patches (handoff to Remediation Agent)
  - Block production deployments (advisory only)
  - Trust raw CVSS without exploitability context
  - Skip secret validation when validation is possible
```

### Execution contract template

```yaml
contract:
  target_agent: vulnerability
  task:
    type: scan_targets | assess_cve | validate_secret | scan_iac
    scope:
      target_type: container_image | vm | function | iac_file | repo
      targets: array of target identifiers
      scan_depth: shallow | deep
  required_outputs:
    vulnerabilities:
      - cve_id: string
        affected_assets: array
        cvss_v3: float
        epss_score: float
        cisa_kev: bool
        exploit_available: bool
        actual_severity: enum [info, low, medium, high, critical]
        fix_available: bool
        fix_version: string | null
        remediation_recommendation: structured
    secrets:
      - secret_type: enum
        location: string
        validation_status: valid | invalid | unvalidated
        recommended_action: rotate | revoke | investigate
  budget:
    max_llm_calls: 12
    max_tokens: 24000
    max_wall_clock_seconds: 180
    max_external_api_calls: 500
  permitted_tools:
    - run_trivy_scan
    - run_grype_scan
    - run_syft_sbom
    - run_checkov_scan
    - run_kics_scan
    - run_trufflehog_scan
    - run_gitleaks_scan
    - query_nvd
    - query_osv
    - query_cisa_kev
    - query_epss
    - query_github_advisory
    - list_container_images | list_vms | list_serverless_functions
    - recall_vulnerability_history
    - check_patching_cadence
    - get_asset_criticality
  completion_condition: |
    All targets scanned (or partial with explicit incomplete flag)
    AND all CVEs enriched with KEV/EPSS data
    AND all secrets have validation_status determined
  workspace: /workspaces/<customer_id>/<delegation_id>/vulnerability/
```

### File-backed state schema

```
/workspaces/<customer_id>/<delegation_id>/vulnerability/
  task.yaml
  scan_targets.json
  scans/
    <target_id>/
      trivy_raw.json
      grype_raw.json (if backup used)
      syft_sbom.json
  enrichment/
    cve_enrichment.json
    secret_validation.json
  reasoning_trace.md
  api_call_log.jsonl
  output.yaml

/persistent/<customer_id>/vulnerability/
  customer_baseline.yaml         # patching cadence, asset criticality
  exceptions.yaml                # accepted-risk CVEs (with justification)
  cve_history.jsonl              # episodic
  fix_effectiveness.json         # procedural — which fixes worked
```

### Self-evolution criteria

- False positive rate on secret detection > 10%
- CVE assessment accuracy disputed by customer > 5%
- Scan time exceeds budget on > 15% of invocations
- Validation failures correlate with specific scanner versions

Self-evolution: Meta-Harness rewrites stage prioritization in NLAH, adjusts parallelization batch sizes, refines validation heuristics.

### Pattern usage declaration

**Primary patterns:**
- **Prompt chaining** — 8 sequential stages
- **Parallelization** — Stage 2 scans multiple targets concurrently

**Secondary:**
- **Evaluator-optimizer** — self-evolution

### Tools

23 tools as in prior spec.

### Coverage progression

| Phase | Coverage | Notes |
|---|---|---|
| 1 | 80% | Strongest specialist Day 1 |
| 4 | 95% | + SideScanning equivalent for snapshot scanning |

---

## AGENT 3 — IDENTITY AGENT

### Domain
CIEM, effective permissions, identity attack chains.

### Hire test
IAM engineer / privileged access management specialist.

### Three-layer description

**Backend infrastructure:**
- PMapper for AWS privilege escalation analysis
- Cloudsplaining for AWS policy danger analysis
- AWS IAM Access Analyzer client
- Azure RBAC analyzer (Phase 2)
- GCP IAM analyzer (Phase 3)
- Cartography read connection (identity subgraph)
- Custom permission simulator

**Runtime charter participation:**
- Standard charter rules
- Special permission: can request real-time CloudTrail queries (higher rate limit budget)
- Inherits identity-anomaly detection primitive

**NLAH:**
File `identity/nlah.md`:

```
ROLE: Cloud identity and entitlement specialist

EXPERTISE:
  - AWS IAM, Azure RBAC, GCP IAM (semantic differences matter)
  - Effective permission calculation across SCPs, permission boundaries, session policies
  - Privilege escalation attack chains
  - Identity-based attacks (token theft, session hijacking, credential reuse)
  - Federation security (SAML, OIDC, cross-account)

DECISION HEURISTICS:
  H1: Effective permissions matter, not assigned permissions.
  H2: Unused permissions are over-privileges. Track 90-day usage windows.
  H3: Service accounts with admin access are worse than user accounts with admin.
  H4: Cross-account trust relationships are high-risk by default.
  H5: Standing privileged access should be just-in-time.

STAGES:
  Stage 1: ENUMERATE — list identities in scope
  Stage 2: COMPUTE_EFFECTIVE — calculate effective permissions across all policy types
  Stage 3: USAGE_ANALYSIS — query CloudTrail for actual permission usage
  Stage 4: ATTACK_PATH — find privilege escalation paths
  Stage 5: ANOMALY_CHECK — compare current behavior to baseline
  Stage 6: ASSESS — categorize findings by severity and exploitability
  Stage 7: RECOMMEND — least-privilege replacements, JIT options
  Stage 8: HANDOFF

FAILURE TAXONOMY:
  F1: Cannot fully resolve effective permissions (complex SCP chains) → return partial with explicit limit flagged
  F2: CloudTrail data missing for time window → use available data, mark confidence lower
  F3: Permission simulator returns ambiguous result → escalate to human review
  F4: Anomaly without sufficient baseline → wait for baseline maturity, low-confidence flag

CONTRACTS YOU REQUIRE:
  - IAM read access via assumed role
  - CloudTrail accessible (last 90 days minimum)
  - Identity baseline in semantic memory (else trigger 7-day baseline establishment)

WHAT YOU NEVER DO:
  - Modify IAM policies (handoff to Remediation Agent)
  - Disable identities (Tier 1 only via Remediation Agent with authorization)
  - Trust assigned permissions over computed effective permissions
```

### Execution contract template

```yaml
contract:
  target_agent: identity
  task:
    type: analyze_identity | find_attack_paths | check_anomaly | usage_analysis
    scope:
      cloud_provider: aws | azure | gcp
      account_id: <id>
      principal_filter: <optional>
      target_resources: <optional, for attack path analysis>
  required_outputs:
    identity_findings:
      - principal_arn: string
        finding_type: enum [over_privileged, unused_permission, attack_path, anomalous_activity, mfa_missing, key_rotation_overdue]
        effective_permissions_summary: structured
        unused_permissions: array
        attack_paths: array of {source, target, steps[]}
        recommended_policy: structured (least-privilege replacement)
        severity: enum
        confidence: float
  budget:
    max_llm_calls: 10
    max_tokens: 16000
    max_wall_clock_seconds: 120
    max_iam_api_calls: 300
    max_cloudtrail_queries: 50
  permitted_tools:
    - run_pmapper_analysis
    - run_cloudsplaining_analysis
    - query_iam_access_analyzer
    - simulate_aws_policy
    - query_azure_rbac (Phase 2+)
    - query_gcp_iam (Phase 3+)
    - list_iam_users | list_iam_roles
    - get_role_last_used
    - list_attached_policies
    - get_credential_report
    - query_cloudtrail
    - query_authentication_events
    - detect_anomalous_activity
    - query_identity_graph
    - find_attack_path
    - recall_identity_baseline
    - check_authorized_access_pattern
  completion_condition: |
    All in-scope identities analyzed
    AND attack paths computed if requested
    AND anomalies flagged if baseline available
  workspace: /workspaces/<customer_id>/<delegation_id>/identity/
```

### File-backed state schema

```
/workspaces/<customer_id>/<delegation_id>/identity/
  task.yaml
  identity_inventory.json
  effective_permissions/
    <principal_id>.json
  usage_analysis.json
  attack_paths.json
  anomaly_findings.json
  reasoning_trace.md
  output.yaml

/persistent/<customer_id>/identity/
  identity_baselines/             # per-principal baselines
    <principal_id>.yaml
  approved_patterns.yaml          # user.md — known-good service accounts etc
  privilege_history.jsonl
  policy_recommendations_outcomes.json
```

### Self-evolution criteria

- Customer rejects > 20% of recommended least-privilege policies (over-restrictive)
- Anomaly false positive rate > 15%
- Attack paths discovered but never exploited (over-aggressive flagging)
- Effective permission calculation disputed by customer

### Pattern usage

- **Prompt chaining** — 8 stages
- **Evaluator-optimizer** — self-evolution
- **Routing** — handoff for cross-domain findings

### Coverage progression

| Phase | Coverage | Notes |
|---|---|---|
| 1 | 70% | AWS-strong, Azure/GCP basic |
| 3 | 80% | Multi-cloud parity |
| 4 | 90% | Advanced behavioral analytics |

---

## AGENT 4 — RUNTIME THREAT AGENT

### Domain
Real-time runtime detection. eBPF-based monitoring, container threats, kernel events.

### Hire test
Threat hunter / runtime security engineer.

### Three-layer description

**Backend infrastructure:**
- Falco runtime + custom rule packs
- Tracee as backup
- Tetragon for advanced kernel telemetry
- OSQuery for endpoint queryability
- Wazuh for HIDS
- eBPF program loader

**Runtime charter participation:**
- Special charter privilege: real-time event stream (not heartbeat-driven for active threats)
- Can interrupt heartbeat cycle for critical threats (preempt budget)
- Inherits process-tree analysis primitive
- Inherits action-with-rollback primitive (for Tier 1 process kill, quarantine)

**NLAH:**
File `runtime_threat/nlah.md`:

```
ROLE: Runtime threat hunter and incident responder

EXPERTISE:
  - eBPF semantics, syscall analysis, process trees
  - MITRE ATT&CK runtime techniques
  - Container escape patterns, kernel exploitation
  - Malware behavioral patterns (cryptominers, ransomware, C2)
  - Linux internals (cgroups, namespaces, capabilities)

DECISION HEURISTICS:
  H1: Process tree context matters more than individual events.
  H2: Known-good baseline is the strongest signal.
  H3: High-fidelity signals (container escape syscalls) trump low-fidelity (network anomaly).
  H4: Active exploitation > suspicious behavior > anomaly score.
  H5: When uncertain about action, isolate (Tier 1 reversible) over kill (Tier 2 irreversible).

OPERATING MODES:
  Mode A — Heartbeat scan: review last interval of Falco events, identify patterns
  Mode B — Real-time alert: triggered by critical Falco rule, preempt for immediate response
  Mode C — Investigation support: invoked by Investigation Agent for deep runtime analysis

STAGES (Mode A — chained):
  Stage 1: AGGREGATE — group recent events by host, container, process tree
  Stage 2: BASELINE_COMPARE — flag deviations from customer baseline
  Stage 3: ENRICH — add MITRE technique mapping, threat intel context
  Stage 4: SCORE — confidence × severity × business impact
  Stage 5: DECIDE — autonomous action (Tier 1) vs draft (Tier 2) vs recommend (Tier 3)
  Stage 6: ACT or HANDOFF

STAGES (Mode B — preemptive routing):
  Stage 1: TRIAGE — confirmed-malicious vs suspicious
  Stage 2: IF confirmed AND Tier 1 authorized → immediate action with rollback timer
  Stage 3: ELSE → escalate to Investigation Agent + draft for Tier 2

FAILURE TAXONOMY:
  F1: Falco rule fires but no process tree context available → log, request OSQuery enrichment
  F2: Baseline insufficient (new customer) → conservative, no Tier 1 actions
  F3: Action fails (process already gone, container already terminated) → log, no escalation needed
  F4: Rollback fails → ESCALATE_TO_HUMAN immediately

CONTRACTS YOU REQUIRE:
  - Falco running and producing events
  - eBPF capability on host (if container deployment)
  - Customer baseline with at least 7 days of normal behavior

WHAT YOU NEVER DO:
  - Take Tier 1 action without authorization confirmation
  - Take action that cannot be rolled back
  - Wait for heartbeat in Mode B (active threat preempts)
  - Skip baseline comparison
```

### Execution contract template

```yaml
contract:
  target_agent: runtime_threat
  task:
    type: scan_interval | active_alert | investigation_support
    mode: heartbeat | preemptive | investigation
    scope:
      time_range: <if heartbeat>
      alert_id: <if preemptive>
      asset_filter: <optional>
  required_outputs:
    runtime_findings:
      - finding_id: string
        host_id: string
        process_tree: structured
        mitre_techniques: array
        severity: enum
        confidence: float
        recommended_action: enum [no_action, monitor, draft_quarantine, autonomous_kill]
        action_authorized: bool (if autonomous, was Tier 1 confirmed)
        evidence_files: array of file paths
  budget:
    max_llm_calls:
      heartbeat: 8
      preemptive: 3 (fast path)
      investigation: 15
    max_tokens:
      heartbeat: 12000
      preemptive: 4000
      investigation: 24000
    max_wall_clock_seconds:
      heartbeat: 60
      preemptive: 10
      investigation: 300
  permitted_tools:
    - query_falco_events
    - query_tracee_events | query_tetragon_events
    - run_osquery
    - query_wazuh_alerts
    - get_process_tree
    - get_network_connections
    - get_file_integrity_status
    - get_kernel_modules
    - inspect_container
    - get_container_capabilities
    - get_pod_security_context
    - notify_investigation_agent
    - notify_network_threat_agent
  conditional_tools:
    # Only if Tier 1 authorized for this action class
    - kill_process: requires customer.tier1_authorized.process_kill
    - quarantine_workload: requires customer.tier1_authorized.workload_quarantine
    - snapshot_workload: always permitted (forensic capture)
  completion_condition: |
    Mode A: All events in interval reviewed, findings categorized
    Mode B: Decision made within 10 seconds, action taken or escalated
    Mode C: Investigation findings returned to requesting Investigation Agent
  workspace: /workspaces/<customer_id>/<delegation_id>/runtime_threat/
```

### File-backed state schema

```
/workspaces/<customer_id>/<delegation_id>/runtime_threat/
  task.yaml
  events/
    falco_events.jsonl
    process_trees.json
    network_connections.json
  enrichment/
    mitre_mappings.json
    threat_intel_correlations.json
  decisions.json
  actions_taken.jsonl
  reasoning_trace.md
  output.yaml

/persistent/<customer_id>/runtime_threat/
  customer_baselines/
    process_baselines.yaml
    network_baselines.yaml
    file_integrity_baselines.yaml
  suppression_rules.yaml          # known-good behaviors
  threat_history.jsonl
  action_outcomes.json            # which actions worked, which caused issues
```

### Self-evolution criteria

- False positive rate on Falco rules > 10%
- Tier 1 actions caused operational issues > 1% (very strict)
- Baseline drift detection lag > 7 days
- Critical threats missed (ground truth from incident reviews)

Self-evolution especially important here — runtime detection rules need continuous tuning.

### Pattern usage

- **Routing** — Mode A vs Mode B vs Mode C dispatch
- **Evaluator-optimizer** — heavy use of self-evolution
- **Prompt chaining** — within each mode

### Coverage progression

| Phase | Coverage | Notes |
|---|---|---|
| 2 | 70% | Falco-based, basic rules |
| 3 | 90% | + Tetragon, custom rules, behavioral analytics |
| 4 | 95% | Mature with self-evolution |

---

## AGENT 5 — DATA SECURITY AGENT

(Phase 2 onward)

### Domain
DSPM, data classification, data flow, sensitive data exposure.

### Hire test
Data protection officer / privacy engineer.

### Three-layer description

**Backend infrastructure:**
- Microsoft Presidio for PII classification (open source ML)
- AWS Macie API client (Phase 2)
- Microsoft Purview API client (Phase 2)
- GCP DLP API client (Phase 2)
- DataHub / OpenMetadata for lineage (Phase 3)
- Custom regex engine for custom classifiers

**Runtime charter participation:**
- Standard charter rules
- Special: data scanning has specific privacy contract — never log actual sensitive data, only classifications
- Inherits sampling primitive (don't scan entire datasets, statistical sampling)

**NLAH:**
File `data_security/nlah.md`:

```
ROLE: Data security and privacy specialist

EXPERTISE:
  - Sensitive data taxonomies (PII, PHI, PCI, financial, IP)
  - Data classification techniques (regex, ML-based)
  - Data residency and sovereignty requirements
  - Privacy regulations (GDPR, CCPA, HIPAA, PCI-DSS)
  - Data lineage and flow analysis

DECISION HEURISTICS:
  H1: Sample, don't exhaustively scan. Statistical confidence is enough.
  H2: Context matters — credit card numbers in test data may be synthetic.
  H3: Sensitive data + public access + over-privileged identity = critical (toxic combination).
  H4: Custom classifiers per customer — generic patterns miss industry-specific data.
  H5: Never log the actual sensitive data, only classifications and locations.

STAGES (chained, with parallelization):
  Stage 1: INVENTORY — list data stores in scope
  Stage 2: SAMPLE (parallel) — pull representative samples from each
  Stage 3: CLASSIFY — run classifiers (built-in + customer custom)
  Stage 4: ASSESS_EXPOSURE — combine classification with access controls
  Stage 5: TRACE_FLOW — where does this data go (Phase 3+)
  Stage 6: PRIORITIZE — toxic combinations first
  Stage 7: RECOMMEND — access tightening, encryption, lineage controls
  Stage 8: HANDOFF

FAILURE TAXONOMY:
  F1: Sample retrieval fails (encryption, access denied) → flag, do not retry with elevated privileges
  F2: Classifier returns ambiguous result → use multiple classifiers, vote
  F3: Custom classifier configuration error → fall back to built-in, alert customer
  F4: Lineage data unavailable → mark flow analysis as incomplete

CONTRACTS YOU REQUIRE:
  - Read access to data stores (with audit logging)
  - Custom classifier configurations from user.md if any
  - Data residency policy in customer_context.md

WHAT YOU NEVER DO:
  - Log actual sensitive data values
  - Retain sensitive data samples beyond classification window
  - Scan production data without sampling (operational risk)
  - Make access changes (handoff to Identity/Cloud Posture/Remediation)
```

### Execution contract template

```yaml
contract:
  target_agent: data_security
  task:
    type: classify_datastore | trace_data_flow | check_residency
    scope:
      datastore_type: s3_bucket | rds | dynamo | blob | bigquery
      datastores: array
      sample_size: int (default 1000 records)
      classifiers: array (built_in + custom)
  required_outputs:
    classifications:
      - datastore_id: string
        sensitive_data_types_detected: array of enum
        record_count_estimate: int
        confidence: float
        access_exposure: structured (public, accessible_by, encrypted)
        residency_compliant: bool
        toxic_combination_flag: bool
        recommendation: structured
  privacy_contract: |
    NEVER include actual sensitive data values in outputs or logs
    ONLY include type classification and locations
  budget:
    max_llm_calls: 6
    max_tokens: 10000
    max_wall_clock_seconds: 120
    max_data_api_calls: 100
  permitted_tools:
    - run_macie_scan | run_purview_scan | run_gcp_dlp_scan
    - run_presidio_scan
    - classify_content
    - scan_database_columns
    - query_database_metadata
    - query_datahub | query_openmetadata
    - recall_data_classification
    - get_data_residency_policy
    - notify_identity_agent
    - notify_runtime_threat_agent
  workspace: /workspaces/<customer_id>/<delegation_id>/data_security/
```

### File-backed state schema

```
/workspaces/<customer_id>/<delegation_id>/data_security/
  task.yaml
  inventory.json
  classifications/
    <datastore_id>.json     # NO actual data, only classifications
  exposure_analysis.json
  flow_analysis.json (Phase 3+)
  reasoning_trace.md
  output.yaml

/persistent/<customer_id>/data_security/
  custom_classifiers.yaml
  data_residency_policy.yaml
  classification_history.jsonl
  data_inventory.yaml          # known data stores and their classifications
```

### Self-evolution criteria

- Classification accuracy < 90% (validated by spot checks)
- Custom classifier requests recurring (suggests built-ins inadequate for customer)
- Sampling missing actual sensitive data (false negatives in spot checks)

### Pattern usage

- **Prompt chaining** — 8 stages
- **Parallelization** — Stage 2 sampling across stores

### Coverage progression

| Phase | Coverage | Notes |
|---|---|---|
| 2 | 50% | Cloud-native DLP integration |
| 3 | 75% | + Lineage analysis |
| 4 | 85% | + AI training data, custom classifiers mature |

---

## AGENT 6 — NETWORK THREAT AGENT

(Phase 2 onward)

### Domain
Network IDS, traffic analysis, network-layer threats.

### Hire test
Network security analyst.

### Three-layer description

**Backend infrastructure:**
- Suricata (rule-based IDS)
- Zeek (network analysis framework)
- VPC Flow Logs API clients (AWS, Azure, GCP)
- DNS log aggregator
- DGA detection model

**Runtime charter participation:**
- Real-time event stream like Runtime Threat Agent
- Tier 1 action capability for IP blocking (with auto-expiry)
- Inherits network policy generation primitive

**NLAH:**
File `network_threat/nlah.md`:

```
ROLE: Network security analyst and traffic threat hunter

EXPERTISE:
  - Network protocols (TCP/IP, DNS, HTTP/S, TLS)
  - Network attack patterns (port scans, DDoS, lateral movement, exfil)
  - DGA detection, beacon analysis, C2 patterns
  - Cloud network constructs (VPC, NSG, peering, transit gateways)
  - Microsegmentation principles

DECISION HEURISTICS:
  H1: Connection pattern matters more than individual packets.
  H2: Beacon detection requires temporal analysis, not single-event.
  H3: DGA scoring is probabilistic, not binary.
  H4: Internal lateral movement is harder to detect than external — focus there.
  H5: Block decisions for IPs need TTL — never permanent without human review.

STAGES:
  Stage 1: AGGREGATE — group network events by source, destination, time window
  Stage 2: PATTERN_DETECT — port scans, beacons, DGA queries
  Stage 3: BASELINE_COMPARE — anomaly vs normal traffic
  Stage 4: THREAT_INTEL_ENRICH — IP/domain reputation lookups
  Stage 5: SCORE — composite threat score
  Stage 6: DECIDE — block (Tier 1), recommend block (Tier 2), monitor (Tier 3)
  Stage 7: ACT or HANDOFF

FAILURE TAXONOMY:
  F1: Flow logs missing → request VPC config check from Cloud Posture
  F2: DGA model unavailable → use entropy-based heuristic
  F3: Block fails → check WAF connectivity, alert if persistent
  F4: Auto-expiry fails → ESCALATE — block must be temporary

CONTRACTS YOU REQUIRE:
  - VPC flow logs accessible
  - DNS logs accessible (cloud-native or via DNS server integration)
  - Threat intel feeds current
  - WAF/firewall API access for block actions

WHAT YOU NEVER DO:
  - Block IPs permanently autonomously
  - Block IPs without TTL
  - Make network policy changes (handoff to Cloud Posture)
  - Block private IP ranges autonomously
```

### Execution contract template

```yaml
contract:
  target_agent: network_threat
  task:
    type: scan_interval | active_alert | analyze_traffic
    scope:
      time_range: <range>
      vpc_filter: <optional>
      analysis_depth: shallow | deep
  required_outputs:
    network_findings:
      - finding_type: enum [port_scan, beacon, dga, exfil, lateral_movement, ddos]
        source: string
        destination: string
        evidence: structured
        confidence: float
        recommended_action: enum [no_action, monitor, block_temporary, recommend_block]
        action_taken: bool
        ttl_seconds: int (if blocked)
  budget:
    max_llm_calls: 6
    max_tokens: 10000
    max_wall_clock_seconds: 60
  permitted_tools:
    - query_suricata_alerts
    - query_zeek_logs
    - query_vpc_flow_logs
    - query_dns_logs
    - analyze_dga_likelihood
    - analyze_beacon_pattern
    - notify_runtime_threat_agent
  conditional_tools:
    - block_ip_at_waf: requires customer.tier1_authorized.network_block AND ttl <= 3600
  workspace: /workspaces/<customer_id>/<delegation_id>/network_threat/
```

### File-backed state schema

```
/workspaces/<customer_id>/<delegation_id>/network_threat/
  task.yaml
  aggregations/
    flow_summary.json
    dns_summary.json
  pattern_detections.json
  reasoning_trace.md
  actions.jsonl
  output.yaml

/persistent/<customer_id>/network_threat/
  baselines/
    traffic_baseline.yaml
    dns_baseline.yaml
  blocked_ips.jsonl              # with TTL tracking
  whitelist.yaml                 # known-good IPs/domains
```

### Self-evolution criteria

- DGA false positive rate > 5%
- Beacon detection misses (verified after-the-fact)
- Block actions causing legitimate traffic disruption > 0.5%
- Baseline staleness causing false anomaly flags

### Pattern usage

- **Routing** — handoff to Runtime Threat for workload-level
- **Evaluator-optimizer** — self-evolution

### Coverage progression

| Phase | Coverage | Notes |
|---|---|---|
| 2 | 50% | Suricata + cloud-native flow logs |
| 3 | 75% | + Zeek deep analysis, DGA models |
| 4 | 85% | + Microsegmentation recommendations |

---

## AGENT 7 — COMPLIANCE AGENT

### Domain
Framework mapping, audit evidence, control coverage reporting.

### Hire test
GRC analyst / compliance auditor.

### Three-layer description

**Backend infrastructure:**
- Compliance framework knowledge base (in graph)
- Prowler compliance modules
- OpenSCAP for traditional compliance
- InSpec for compliance-as-code
- PDF generation engine for reports

**Runtime charter participation:**
- Standard rules
- Special: can request evidence from any other specialist
- Inherits report generation primitive

**NLAH:**
File `compliance/nlah.md`:

```
ROLE: Compliance and audit readiness specialist

EXPERTISE:
  - Major frameworks (CIS, NIST 800-53/CSF, PCI-DSS, HIPAA, SOC 2, ISO 27001, FedRAMP, GDPR)
  - Industry-specific (HITRUST, NERC-CIP, FFIEC, NYDFS for verticals)
  - Audit evidence collection and packaging
  - Control mapping across frameworks (CSA CCM mapping ATT&CK to controls)
  - Compliance-as-code patterns

DECISION HEURISTICS:
  H1: One finding can violate multiple controls — map all of them.
  H2: Compensating controls reduce severity.
  H3: Audit-blocking findings get top priority regardless of CVSS.
  H4: Customer's certification calendar drives priority (audit in 30 days = urgent).
  H5: Generate evidence proactively, not at audit time.

STAGES (parallelized across frameworks):
  Stage 1: INVENTORY — list applicable frameworks for customer
  Stage 2: MAP (parallel) — map findings to controls per framework
  Stage 3: COVERAGE — calculate control coverage percentages
  Stage 4: GAP_ANALYSIS — identify missing controls for upcoming audits
  Stage 5: EVIDENCE — request evidence from other specialists for satisfied controls
  Stage 6: REPORT — generate audit-ready outputs

FAILURE TAXONOMY:
  F1: Framework version mismatch (CIS 1.5 vs 2.0) → use customer's specified version
  F2: Control mapping ambiguous → flag for human review, do not guess
  F3: Evidence request fails (specialist unavailable) → mark control as "evidence pending"
  F4: Report generation timeout → generate partial, flag completion percentage

CONTRACTS YOU REQUIRE:
  - Customer's compliance framework selections in user.md
  - Customer's audit calendar in user.md
  - Findings from other specialists accessible

WHAT YOU NEVER DO:
  - Implement controls (recommendation only, handoff to Remediation)
  - Approve audit findings (advisory)
  - Generate false evidence
```

### Execution contract template

```yaml
contract:
  target_agent: compliance
  task:
    type: map_findings | generate_report | gap_analysis | continuous_monitoring
    scope:
      frameworks: array
      time_range: <for reports>
      customer_id: <id>
      report_format: pdf | html | json
  required_outputs:
    compliance_status:
      framework_id:
        coverage_percentage: float
        controls_satisfied: array
        controls_unsatisfied: array
        evidence_packages: array of file paths
        gaps: structured array
        recommendations: array
  budget:
    max_llm_calls: 8
    max_tokens: 16000
    max_wall_clock_seconds: 180
  permitted_tools:
    - map_finding_to_controls
    - generate_compliance_report
    - query_control_coverage
    - identify_control_gaps
    - query_compliance_history
    - request_evidence
    - update_compliance_status
  workspace: /workspaces/<customer_id>/<delegation_id>/compliance/
```

### File-backed state schema

```
/workspaces/<customer_id>/<delegation_id>/compliance/
  task.yaml
  framework_inventory.json
  mappings/
    <framework_id>_mappings.json
  coverage_analysis.json
  gap_analysis.json
  evidence/
    <control_id>/
      evidence_files...
  reports/
    <framework_id>_report.pdf
  reasoning_trace.md
  output.yaml

/persistent/<customer_id>/compliance/
  framework_subscriptions.yaml      # which frameworks customer cares about
  audit_calendar.yaml               # upcoming audits
  certification_status.yaml         # current certifications
  exception_register.yaml           # accepted-risk items
  historical_reports/               # past audit packages
```

### Self-evolution criteria

- Auditor disputes findings > 5% (mapping accuracy)
- Evidence collection failures > 10%
- Report generation time exceeds budget
- Customer requests new framework not yet supported

### Pattern usage

- **Parallelization** — Stage 2 mapping across frameworks concurrently
- **Prompt chaining** — overall flow

### Coverage progression

| Phase | Coverage | Notes |
|---|---|---|
| 1 | 60% | Basic frameworks via Prowler |
| 2 | 85% | Most major frameworks |
| 4 | 95% | + 10 vertical-specific (HITRUST, NERC-CIP, etc) |

---

## AGENT 8 — INVESTIGATION AGENT

### Domain
Deep-dive incident investigation, root cause analysis, evidence collection. **This agent uses orchestrator-workers pattern — it spawns sub-investigations.**

### Hire test
DFIR analyst / incident responder.

### Three-layer description

**Backend infrastructure:**
- Timeline reconstruction engine
- Cross-source query engine (Elasticsearch/OpenSearch on aggregated logs)
- IOC extraction tools
- VirusTotal / OTX API clients
- Forensic snapshot infrastructure
- Memory dump analysis tools

**Runtime charter participation:**
- Special: can spawn sub-agents for investigation tasks (only Investigation and Supervisor can)
- Extended budget caps (investigations are long-running)
- Inherits forensic capture primitive
- Can request elevated read permissions for forensic purposes (with audit trail)

**NLAH:**
File `investigation/nlah.md`:

```
ROLE: Incident investigator and DFIR analyst

EXPERTISE:
  - Timeline reconstruction across heterogeneous data sources
  - MITRE ATT&CK technique identification from evidence
  - IOC extraction and pivoting
  - Root cause analysis methodology
  - Containment, eradication, recovery planning

DECISION HEURISTICS:
  H1: Timeline first, hypothesis second. Build the timeline before deciding what happened.
  H2: Pivot on indicators — every IOC potentially reveals more compromised resources.
  H3: Containment before investigation — stop the bleeding first.
  H4: Document everything in real time — auditor will need this.
  H5: Decompose complex investigations into parallel sub-investigations.

OPERATING MODES:
  Mode A — Triage: quick assessment of incoming alert, decide investigation depth
  Mode B — Deep investigation: full DFIR with sub-agent delegation
  Mode C — Cross-incident analysis: pattern detection across multiple incidents

ORCHESTRATOR-WORKERS PATTERN:
  When investigating complex incidents, spawn sub-agents:
    - Timeline sub-agent: reconstructs event sequence
    - IOC sub-agent: extracts and pivots indicators
    - Asset enumeration sub-agent: finds all affected resources
    - Adversary attribution sub-agent: maps to known threat actors
  Each sub-agent has narrower scope, smaller context, focused tools.

STAGES (Mode B):
  Stage 1: SCOPE — define investigation boundaries
  Stage 2: SPAWN — create sub-investigations in parallel
  Stage 3: SYNTHESIZE — integrate sub-investigation outputs
  Stage 4: VALIDATE — cross-check hypotheses against evidence
  Stage 5: PLAN — containment, eradication, recovery
  Stage 6: HANDOFF — to Remediation Agent for actions

FAILURE TAXONOMY:
  F1: Sub-investigation budget exceeded → request extension or accept partial
  F2: Evidence not preserved → flag — incident response broken
  F3: Hypotheses contradict → document both, request human judgment
  F4: Cannot determine root cause → document what is known, flag uncertainty

CONTRACTS YOU REQUIRE:
  - Forensic preservation of affected workloads (immediate)
  - Read access to all logs and findings
  - Threat intelligence current
  - Sub-agent spawning capability authorized

WHAT YOU NEVER DO:
  - Take direct remediation actions (handoff to Remediation Agent)
  - Skip evidence preservation
  - Conclude investigation without documented chain of evidence
  - Allow sub-agents to escalate beyond their scope
```

### Execution contract template

```yaml
contract:
  target_agent: investigation
  task:
    type: triage | deep_investigation | cross_incident_analysis
    scope:
      incident_id: <UUID>
      initial_evidence: array
      severity: enum
      time_pressure: enum [routine, urgent, emergency]
  required_outputs:
    investigation_report:
      timeline: array of timestamped events
      affected_resources: array
      root_cause: structured
      contributing_factors: array
      adversary_techniques: array of MITRE IDs
      threat_actor_attribution: structured (with confidence)
      iocs: array
      containment_plan: structured
      eradication_steps: array
      recovery_validation_criteria: array
  budget:
    max_llm_calls: 30 (extended for deep investigations)
    max_tokens: 60000
    max_wall_clock_seconds: 600 (10 minutes)
    max_sub_agents: 4
    sub_agent_budget: <inherited proportionally>
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
    - request_runtime_action
    - request_network_block
    - request_identity_isolation
    - notify_compliance_agent
  spawnable_sub_agents:
    - investigation_timeline
    - investigation_ioc_pivot
    - investigation_asset_enumeration
    - investigation_attribution
  workspace: /workspaces/<customer_id>/<incident_id>/investigation/
```

### File-backed state schema

```
/workspaces/<customer_id>/<incident_id>/investigation/
  task.yaml
  scope.yaml
  evidence_locker/                 # immutable evidence preservation
    <evidence_id>_signed.zip
  sub_investigations/
    timeline/
      sub_task.yaml
      output.yaml
    ioc_pivot/
      sub_task.yaml
      output.yaml
    asset_enumeration/
      ...
    attribution/
      ...
  synthesis.md                     # how sub-investigations integrate
  hypotheses.md                    # hypothesis tracking
  validation.md                    # what was confirmed vs uncertain
  containment_plan.yaml
  eradication_steps.yaml
  recovery_plan.yaml
  reasoning_trace.md
  full_report.md
  output.yaml
```

### Self-evolution criteria

- Investigation accuracy disputed in postmortem > 10%
- Sub-agent spawning patterns leading to budget overruns
- Time-to-containment exceeding targets
- Hypotheses contradicting evidence (validation failures)

### Pattern usage

- **Orchestrator-workers** — primary pattern (spawns sub-agents)
- **Prompt chaining** — within each sub-investigation
- **Evaluator-optimizer** — self-evolution

### Coverage progression

| Phase | Coverage | Notes |
|---|---|---|
| 1 | 50% | Basic timeline + IOC extraction |
| 2 | 70% | + Sub-agent orchestration |
| 3 | 85% | Mature DFIR capability |

---

## AGENT 9 — THREAT INTEL AGENT

### Domain
External threat intelligence ingestion and correlation.

### Hire test
CTI analyst.

### Three-layer description

**Backend infrastructure:**
- STIX 2.1 parser
- TAXII feed clients
- MITRE ATT&CK / ATLAS sync engines
- CISA KEV monitor (real-time)
- Wiz Cloud Threat Landscape feed
- Unit 42 GitHub poller
- abuse.ch feed clients (URLhaus, ThreatFox, MalwareBazaar)
- AlienVault OTX client

**Runtime charter participation:**
- Background ingestion runs continuously (not heartbeat)
- Standard charter for queries from other agents
- Inherits feed-merge primitive

**NLAH:**
File `threat_intel/nlah.md`:

```
ROLE: Cyber threat intelligence analyst

EXPERTISE:
  - Threat actor tracking, campaign attribution
  - IOC pivoting and enrichment
  - Industry-specific threat landscapes
  - Adversary tactics, techniques, procedures (TTPs)
  - Cloud-specific threat patterns

DECISION HEURISTICS:
  H1: Recent intel matters more than historical (decay rates per intel type).
  H2: Industry-specific intel matters more than generic.
  H3: High-confidence sources (Mandiant, Unit 42, Wiz) outweigh community feeds.
  H4: IOC reputation matters but context matters more.
  H5: Customer's tech stack determines which threats are actually relevant.

STAGES (parallelized for ingestion):
  Mode A — Continuous ingestion:
    Stage 1: POLL (parallel) — query all feeds
    Stage 2: NORMALIZE — convert to STIX 2.1 internal model
    Stage 3: DEDUP — merge duplicates
    Stage 4: ENRICH — add cross-feed context
    Stage 5: GRAPH — upsert into knowledge graph

  Mode B — Query response:
    Stage 1: PARSE — understand what's being asked
    Stage 2: GRAPH_QUERY — retrieve relevant intel
    Stage 3: CONTEXTUALIZE — apply customer context
    Stage 4: RESPOND — structured output

FAILURE TAXONOMY:
  F1: Feed unavailable → use cached data, flag staleness
  F2: STIX parse error → log, skip entry, alert intel team
  F3: Conflicting intel from sources → present both with source confidence
  F4: Customer stack data missing → fall back to industry-generic

CONTRACTS YOU REQUIRE:
  - All feed credentials configured
  - Customer industry vertical in customer_context.md
  - Customer tech stack in customer_context.md (if available)

WHAT YOU NEVER DO:
  - Modify or delete intel from sources (read-only)
  - Generate fictional threat intel
  - Apply intel out of context
```

### Execution contract template

```yaml
contract:
  target_agent: threat_intel
  task:
    type: ingest | query | correlate | brief
    scope:
      feeds: array (for ingest)
      query: string (for query)
      observed_techniques: array (for correlate)
      time_range: <for briefings>
  required_outputs:
    ingest:
      records_ingested: int
      records_updated: int
      records_failed: int
    query:
      results: array of intel records
      confidence: float
      source_attribution: array
    correlate:
      matched_campaigns: array
      matched_threat_actors: array
      relevance_score: float
    brief:
      report_markdown: text
      key_threats: array
      recommendations: array
  budget:
    max_llm_calls: 5
    max_tokens: 10000
    max_wall_clock_seconds: 60
    max_external_api_calls: 100
  permitted_tools:
    - query_mitre_attack | query_mitre_atlas
    - query_cisa_kev
    - query_wiz_landscape
    - query_unit42
    - query_abuse_ch
    - query_otx
    - query_industry_feed
    - correlate_to_campaign
    - predict_targeted_industries
    - generate_threat_briefing
  workspace: /workspaces/<customer_id>/<delegation_id>/threat_intel/
```

### File-backed state schema

```
/workspaces/<customer_id>/<delegation_id>/threat_intel/
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
  correlation_history.jsonl
  briefing_history/
    <date>_briefing.md

/global/threat_intel/                # not customer-specific
  master_graph_sync_status.json
  feed_health.json
  ingestion_log.jsonl
```

### Self-evolution criteria

- Correlation accuracy disputed > 10%
- Customer feedback that briefings miss relevant threats
- New feeds requested by customers not yet integrated
- Latency on real-time intel queries exceeds budget

### Pattern usage

- **Parallelization** — feed ingestion (Mode A)
- **Prompt chaining** — query response (Mode B)

### Coverage progression

| Phase | Coverage | Notes |
|---|---|---|
| 1 | 70% | Basic feed ingestion (5-7 feeds) |
| 2 | 90% | + Industry-specific feeds, automated correlation |

---

## AGENT 10 — REMEDIATION AGENT

### Domain
Action drafting and execution. The "hands" of the platform.

### Hire test
Security automation engineer / SOAR specialist.

### Three-layer description

**Backend infrastructure:**
- Cloud Custodian execution engine
- Terraform CLI + state management
- CloudFormation API client
- Kubernetes API client
- ChatOps integration (Slack/Teams API)
- Approval workflow engine
- Rollback orchestrator

**Runtime charter participation:**
- Special: only agent allowed to execute actions on customer infrastructure
- Strict charter rules:
  - Every action requires explicit authorization tier match
  - Every action requires rollback plan computed BEFORE execution
  - Tier 1 actions auto-create rollback timer
  - All actions logged immutably to Audit Agent
- Inherits dry-run primitive (validate before execute)

**NLAH:**
File `remediation/nlah.md`:

```
ROLE: Security action drafter and executor

EXPERTISE:
  - Cloud Custodian policy authoring
  - Terraform diff generation
  - IAM policy least-privilege drafting
  - Kubernetes manifest patching
  - Runbook authoring for human execution
  - Rollback plan design

DECISION HEURISTICS:
  H1: Compute rollback BEFORE acting. No action without rollback plan.
  H2: Dry-run if possible before live execution.
  H3: Match action to authorized tier strictly. When in doubt, lower tier.
  H4: Smaller blast radius preferred over bigger.
  H5: Reversible action preferred over irreversible.

STAGES (chained for each remediation request):
  Stage 1: PARSE — understand the requested remediation
  Stage 2: AUTHORIZE — verify customer's tier authorization
  Stage 3: DRAFT — generate the executable action
  Stage 4: VALIDATE — dry-run, syntax check, blast radius computation
  Stage 5: ROLLBACK_PLAN — compute exact rollback steps
  Stage 6: ROUTE — Tier 1 (execute) | Tier 2 (approve gate) | Tier 3 (recommend only)
  Stage 7: EXECUTE (if authorized) — apply with monitoring
  Stage 8: VERIFY — confirm action took effect
  Stage 9: HANDOFF — return outcome to requester

FAILURE TAXONOMY:
  F1: Authorization mismatch → demote tier, do not refuse
  F2: Dry-run fails → return to draft stage with error context
  F3: Action partially applied → execute rollback immediately
  F4: Rollback fails → ESCALATE_TO_HUMAN immediately, page on-call
  F5: Verification fails → mark uncertain, schedule re-check

CONTRACTS YOU REQUIRE:
  - Customer authorization profile current
  - Cloud credentials with execution permissions
  - Rollback infrastructure operational

WHAT YOU NEVER DO:
  - Execute without authorization tier check
  - Execute without rollback plan
  - Execute when dry-run fails
  - Take Tier 1 action without auto-rollback timer
  - Execute irreversible actions autonomously
  - Skip verification step
```

### Execution contract template

```yaml
contract:
  target_agent: remediation
  task:
    type: draft | execute | rollback
    scope:
      finding_id: <UUID>
      proposed_action: structured
      target_tier: 1 | 2 | 3
  required_outputs:
    remediation:
      remediation_id: <UUID>
      tier_actual: 1 | 2 | 3 (may differ from requested if authorization issue)
      action_artifact:
        type: cloud_custodian | terraform | cfn | k8s | runbook | iam_policy
        content: string (the actual code/policy/runbook)
      rollback_plan:
        steps: array
        estimated_rollback_time: int (seconds)
        verification_method: string
      blast_radius:
        affected_resources: array
        estimated_impact: structured
      validation:
        dry_run_passed: bool
        dry_run_output: text
      status: drafted | approval_pending | approved | executing | completed | rolled_back | failed
      audit_trail: array of timestamped events
  budget:
    max_llm_calls: 8
    max_tokens: 16000
    max_wall_clock_seconds:
      draft: 30
      execute: 120
      rollback: 60
  permitted_tools:
    - draft_cloud_custodian_policy
    - draft_terraform_diff
    - draft_cfn_changeset
    - draft_arm_template
    - draft_k8s_patch
    - draft_runbook
    - draft_iam_policy
    - submit_for_approval
    - await_approval
    - record_approval
    - prepare_rollback_plan
    - check_tier1_authorization
    - enforce_blast_radius
    - schedule_auto_rollback
    - notify_audit_agent
  conditional_tools:
    # Execute tools only if authorization matches
    - execute_cloud_custodian: requires authorization match + dry_run_passed
    - execute_terraform: same
    - execute_cfn: same
    - execute_kubectl: same
    - execute_runbook: requires Tier 2+ approval
    - validate_remediation: always permitted post-execute
    - execute_rollback: always permitted (rollback never blocked)
    - verify_rollback: always permitted
  workspace: /workspaces/<customer_id>/<remediation_id>/remediation/
```

### File-backed state schema

```
/workspaces/<customer_id>/<remediation_id>/remediation/
  task.yaml
  authorization_check.json
  draft/
    action_artifact.<ext>          # the actual code to execute
    blast_radius_analysis.json
    dry_run_result.json
  rollback_plan.yaml
  approval/
    request.json
    response.json
  execution/
    pre_state.json
    execution_log.jsonl
    post_state.json
    verification_result.json
  audit_trail.jsonl
  reasoning_trace.md
  output.yaml

/persistent/<customer_id>/remediation/
  authorization_profile.yaml      # tier 1/2/3 settings per action class
  remediation_history.jsonl
  rollback_history.jsonl
  effectiveness_scores.json       # which remediations work
  approval_patterns.yaml          # who approves what, when
```

### Self-evolution criteria

- Rollback rate > 2% (suggests bad remediation drafts)
- Approval rejection rate > 15% (suggests poor drafts or wrong tier)
- Verification failures > 5%
- Dry-run failures > 10%
- Time-to-execution exceeds expected
- Customer downgrades Tier 1 authorization (safety signal)

### Pattern usage

- **Prompt chaining** — strict 9-stage pipeline
- **Evaluator-optimizer** — self-evolution on rollback/approval patterns

### Coverage progression

| Phase | Coverage | Notes |
|---|---|---|
| 1 | Tier 3 only | Recommendations only |
| 2 | + Tier 2 | Approval-gated |
| 3 | + narrow Tier 1 | 2-3 action classes autonomous |
| 4 | Mature Tier 1 | 10+ action classes, insurance partnerships |

---

## AGENT 11 — CURIOSITY AGENT (Phase 2+)

### Domain
Proactive hypothesis generation. Doesn't wait for findings.

### Hire test
Threat hunter — the "finds things nobody asked about" specialist.

### Three-layer description

**Backend infrastructure:**
- Behavioral sampling engine
- Statistical drift detection
- Threat intel correlation engine
- Hypothesis tracking database

**Runtime charter participation:**
- Runs on slower cycle (every 6 hours, not 60 seconds)
- Cannot take actions — only generates hypotheses for other agents
- Inherits sampling primitive

**NLAH:**
File `curiosity/nlah.md`:

```
ROLE: Proactive threat hunter

EXPERTISE:
  - Statistical anomaly detection
  - Behavioral drift analysis
  - Emerging threat correlation
  - Pattern recognition across heterogeneous data

DECISION HEURISTICS:
  H1: Generate hypotheses, not findings. Specialists determine actuality.
  H2: Quality over quantity — 5 good hypotheses beat 50 weak ones.
  H3: Track hypothesis outcomes — improve via feedback.
  H4: Industry threats trigger broader hunts.
  H5: New threat intel triggers retrospective hunts.

STAGES:
  Stage 1: SAMPLE — query asset behavior across last 7 days
  Stage 2: BASELINE_COMPARE — identify drift
  Stage 3: THREAT_MATCH — match observations to emerging threats
  Stage 4: TREND_ANALYZE — look for slow-burn patterns
  Stage 5: HYPOTHESIZE — generate testable propositions
  Stage 6: PRIORITIZE — score hypotheses by likelihood × impact
  Stage 7: SUBMIT — route top hypotheses to relevant specialists

FAILURE TAXONOMY:
  F1: Insufficient baseline → wait for baseline maturity
  F2: Hypothesis generation produces noise → tighten thresholds
  F3: Submitted hypothesis rejected by specialist → log, refine criteria
  F4: Hypothesis confirmed but missed by other agents → update routing rules

CONTRACTS YOU REQUIRE:
  - Customer baselines mature
  - Threat intel current
  - Submission slots available with target specialists

WHAT YOU NEVER DO:
  - Generate findings (you generate HYPOTHESES)
  - Take direct action
  - Overwhelm specialists with low-quality hypotheses
```

### Execution contract template

```yaml
contract:
  target_agent: curiosity
  task:
    type: hunt_cycle | targeted_hunt
    scope:
      asset_filter: <optional>
      time_window: 7d (default)
      threat_intel_focus: <optional>
  required_outputs:
    hypotheses:
      - hypothesis_id: <UUID>
        description: text
        target_specialist: agent_name
        evidence: structured
        likelihood: float
        impact_if_true: enum
        priority_score: float
        submission_status: submitted | held | discarded
  budget:
    max_llm_calls: 10
    max_tokens: 20000
    max_wall_clock_seconds: 300
  permitted_tools:
    - sample_asset_behavior
    - compare_to_baseline
    - match_emerging_threats
    - analyze_posture_trend
    - generate_hypothesis
    - submit_hypothesis
  workspace: /workspaces/<customer_id>/<hunt_cycle_id>/curiosity/
```

### Self-evolution criteria

- Hypothesis acceptance rate by specialists < 30% (too noisy)
- Hypothesis confirmed-true rate < 10% (low quality)
- Specialists complaining about volume

### Pattern usage

- **Parallelization** — sampling and threat matching concurrent
- **Evaluator-optimizer** — heavy self-evolution required

### Coverage
New capability not in Wiz. Differentiator.

---

## AGENT 12 — SYNTHESIS AGENT (NEW — Phase 1)

### Domain
Integrates outputs from multiple specialists into customer-facing summaries. Per harness principles, this offloads synthesis from Supervisor (which should remain lightweight).

### Hire test
Senior security analyst who writes executive summaries.

### Three-layer description

**Backend infrastructure:**
- LLM service (uses Claude Sonnet for synthesis)
- Multi-source aggregation
- Customer communication preferences

**Runtime charter participation:**
- Pure reasoning agent — no detection or action tools
- Reads from multiple specialist workspaces
- Outputs to customer-facing channels via supervisor

**NLAH:**
File `synthesis/nlah.md`:

```
ROLE: Synthesizer of specialist findings into customer-facing summaries

EXPERTISE:
  - Translation from technical to business language
  - Prioritization and storytelling
  - Customer communication preferences
  - Cross-domain integration

DECISION HEURISTICS:
  H1: Lead with what matters most to the customer.
  H2: Group related findings into coherent narratives.
  H3: Quantify impact in business terms when possible.
  H4: Always provide clear next actions.
  H5: Match tone to customer preference (technical, executive, conversational).

STAGES:
  Stage 1: COLLECT — gather all specialist outputs for the synthesis request
  Stage 2: RELATE — identify connections between findings
  Stage 3: PRIORITIZE — order by business impact
  Stage 4: NARRATIVE — construct coherent story
  Stage 5: ACTION — clarify next steps
  Stage 6: FORMAT — match output to channel (chat, email, dashboard, report)
  Stage 7: HANDOFF — return synthesized output

FAILURE TAXONOMY:
  F1: Specialist outputs contradict → present both with reasoning
  F2: Output too long for channel → summarize hierarchically
  F3: Insufficient context for narrative → request from specialists

WHAT YOU NEVER DO:
  - Generate findings yourself
  - Add information not from specialists
  - Make remediation decisions
```

### Execution contract template

```yaml
contract:
  target_agent: synthesis
  task:
    type: customer_query | morning_briefing | incident_summary | weekly_report
    scope:
      specialist_outputs: array of workspace paths
      target_channel: chat | email | dashboard | pdf_report
      customer_communication_style: technical | executive | conversational
      length_constraint: brief | normal | detailed
  required_outputs:
    synthesis:
      summary: text
      key_findings: array
      recommended_actions: array
      detailed_sections: array (if detailed)
      formatted_for_channel: text
  budget:
    max_llm_calls: 4
    max_tokens: 16000
    max_wall_clock_seconds: 30
  permitted_tools:
    - query_workspace
    - read_specialist_output
    - format_for_channel
  workspace: /workspaces/<customer_id>/<synthesis_id>/synthesis/
```

### File-backed state schema

```
/workspaces/<customer_id>/<synthesis_id>/synthesis/
  task.yaml
  inputs/
    <specialist_name>_output_links.json
  draft/
    narrative.md
  output_<channel>.<ext>
  reasoning_trace.md
```

### Self-evolution criteria

- Customer satisfaction signal (downvote, request rephrase) > 10%
- Synthesis missing critical findings (specialist had it, synthesis dropped it)
- Wrong tone for customer (e.g., too technical for executive)

### Pattern usage

- **Orchestrator-workers** (sort of — reads from peer agents' outputs)
- **Prompt chaining** — 7 stages

---

## AGENT 13 — META-HARNESS AGENT (Phase 2+)

### Domain
Reads raw execution traces, proposes harness rewrites, runs against eval suites. The self-evolution engine.

### Hire test
ML engineer + senior agent designer.

### Three-layer description

**Backend infrastructure:**
- Trace analysis engine
- Eval framework with curated test sets per agent
- Harness diff generator
- Signed deployment pipeline

**Runtime charter participation:**
- Special privileges: can read all agents' raw traces (audit-logged)
- Can propose new NLAH versions
- Cannot deploy without human approval (initial Phase 2-3) or auto-deploy with strict criteria (Phase 4+)

**NLAH:**
File `meta_harness/nlah.md`:

```
ROLE: Self-evolution engineer for the agent ecosystem

EXPERTISE:
  - LLM agent failure modes
  - Prompt and harness optimization
  - Eval-driven iteration
  - Cross-model harness transferability

DECISION HEURISTICS:
  H1: Raw traces are essential. Never optimize from summaries.
  H2: Narrow self-evolution (focused). Don't broaden until failures justify.
  H3: Acceptance gating mandatory. New harness must beat old on eval suite + no regression.
  H4: Subtraction over addition. Often the fix is removing complexity, not adding.
  H5: Cross-model test. Verify new harness works across model versions.

STAGES (continuous):
  Stage 1: COLLECT — gather raw execution traces from triggered agents
  Stage 2: DIAGNOSE — identify failure patterns
  Stage 3: PROPOSE — draft new NLAH version
  Stage 4: EVAL — run against curated eval suite
  Stage 5: DECIDE — accept (improvement + no regression) or reject
  Stage 6: DEPLOY — versioned, signed, fleet-pushed

FAILURE TAXONOMY:
  F1: Eval suite too small → flag for human curation expansion
  F2: Proposed harness regresses → discard, log learning
  F3: Cross-model transfer fails → narrow change to specific model
  F4: Acceptance gate triggered for major rewrite → human review required

WHAT YOU NEVER DO:
  - Deploy without eval gate
  - Optimize from summarized traces
  - Auto-deploy major rewrites without human review (Phase 2-3)
  - Skip versioning and signing
```

### Execution contract template

```yaml
contract:
  target_agent: meta_harness
  task:
    type: optimize_agent
    scope:
      target_agent: <agent_name>
      trigger_reason: enum
      trace_window: <time range>
  required_outputs:
    proposal:
      old_nlah_version: string
      new_nlah_version: string
      diff: text
      eval_results:
        old_score: float
        new_score: float
        regression_check: pass | fail
      cross_model_results: array
      recommendation: deploy | review | reject
  budget:
    max_llm_calls: 50 (heavy reasoning)
    max_tokens: 100000
    max_wall_clock_seconds: 1800 (30 minutes)
  permitted_tools:
    - read_agent_traces
    - analyze_failure_patterns
    - propose_nlah_diff
    - run_eval_suite
    - cross_model_eval
    - sign_and_version
    - submit_for_human_review
  workspace: /workspaces/global/meta_harness/<optimization_id>/
```

### File-backed state schema

```
/workspaces/global/meta_harness/<optimization_id>/
  task.yaml
  trace_analysis/
    raw_traces/
      <trace_id>.md
    failure_patterns.md
  proposals/
    nlah_v_<old>.md
    nlah_v_<new>.md
    diff.md
  evals/
    old_score.json
    new_score.json
    cross_model.json
  decision.yaml
  deployment_status.yaml

/persistent/global/meta_harness/
  eval_suites/
    <agent_name>/
      test_cases.yaml
      ground_truth.yaml
  nlah_versions/
    <agent_name>/
      v1.md
      v2.md
      ...
  optimization_history.jsonl
```

### Pattern usage

- **Evaluator-optimizer** — primary, always
- **Prompt chaining** — within optimization run

### Coverage
New capability not in Wiz. Critical for self-improvement.

---

## AGENT 14 — AUDIT AGENT

### Domain
Compliance evidence, audit log integrity, regulatory reporting for the platform itself.

### Hire test
Internal auditor.

### Three-layer description

**Backend infrastructure:**
- Append-only audit log database
- Hash chain for log integrity
- Evidence package generator
- Compliance reporting engine

**Runtime charter participation:**
- Receives audit events from every other agent (mandatory)
- Cannot modify or delete audit records
- Inherits integrity verification primitive

**NLAH:**
File `audit/nlah.md`:

```
ROLE: Internal auditor for the platform

EXPERTISE:
  - Audit log integrity (hash chains, tamper detection)
  - Evidence collection and packaging
  - SOC 2, ISO 27001 platform compliance
  - Customer audit support

DECISION HEURISTICS:
  H1: Append-only. Never modify, never delete.
  H2: Hash chain integrity is non-negotiable.
  H3: Evidence completeness over evidence prettiness.
  H4: Customer-requestable evidence anytime.
  H5: Internal compliance separate from customer compliance.

STAGES:
  Stage 1: RECEIVE — accept audit event from any agent
  Stage 2: VALIDATE — check event format, hash previous
  Stage 3: APPEND — write to immutable log
  Stage 4: INDEX — make searchable
  Stage 5: PACKAGE (on request) — generate evidence bundle

FAILURE TAXONOMY:
  F1: Hash chain mismatch → ESCALATE_TO_HUMAN immediately, possible tampering
  F2: Disk space exhausted → escalate, log to fallback storage
  F3: Evidence request too broad → narrow scope with requester

WHAT YOU NEVER DO:
  - Modify existing audit records
  - Delete audit records
  - Skip hash chain validation
  - Generate evidence without provenance
```

### Execution contract template

```yaml
contract:
  target_agent: audit
  task:
    type: record_action | generate_evidence | verify_integrity | generate_compliance_report
    scope:
      <varies by task>
  required_outputs:
    record_action:
      audit_id: <UUID>
      hash: string
      previous_hash: string
    generate_evidence:
      evidence_package: file path
      contents_manifest: array
      integrity_hash: string
    verify_integrity:
      verified: bool
      issues: array
      coverage: float
  budget: standard
  permitted_tools:
    - record_action
    - verify_log_integrity
    - generate_evidence_package
    - query_audit_log
    - generate_compliance_report
  workspace: /workspaces/<customer_id>/<delegation_id>/audit/
```

### File-backed state schema

```
/persistent/<customer_id>/audit/
  audit_log.jsonl                # append-only, hash-chained
  hash_chain_state.json          # current hash chain head
  evidence_packages/
    <package_id>.zip
  integrity_check_history.jsonl

/persistent/global/audit/
  platform_audit_log.jsonl       # platform-level events (SOC 2 evidence for us)
  audit_log_backups/             # off-site, signed
```

### Pattern usage

- **Prompt chaining** — strict pipeline (record → validate → append → index)

---

## CROSS-AGENT COORDINATION SUMMARY

### Communication primitives (charter-enforced)

All inter-agent communication flows through the supervisor except:
- Investigation Agent spawning sub-investigation agents (allowed by charter)
- Meta-Harness reading any agent's traces (read-only privilege)
- Audit Agent receiving events from all agents (write-only from agents to audit)

### Workspace conventions

Every agent invocation gets a workspace at `/workspaces/<customer_id>/<delegation_id>/<agent_name>/`. The workspace is created by supervisor before delegation, populated by the agent, and read by the next stage.

### Reasoning trace requirements

Every agent MUST write a `reasoning_trace.md` containing:
- Initial task understanding
- Decisions made and why
- Tool calls in order
- Confidence assessments
- Final synthesis

This is critical for Meta-Harness self-evolution — summarized traces drop optimization quality dramatically.

### Memory access patterns

| Memory Type | Read | Write |
|---|---|---|
| Customer context | All agents | Supervisor only |
| Agent private memory | Agent itself + Meta-Harness (read-only) | Agent itself |
| Knowledge graph | All agents (read-only) | Memory Curator workflow only |
| Audit log | Audit Agent + read-only by all | Append-only by all |

---

## EVAL INFRASTRUCTURE PER AGENT

Each agent has an eval suite at `/persistent/global/meta_harness/eval_suites/<agent_name>/` containing:

- 50-200 test cases per agent (curated by detection engineering team)
- Ground truth labels (severity, action, etc.)
- Synthetic edge cases
- Replay-from-production cases (anonymized)

Eval suite expansion:
- Phase 1: 50 cases per agent
- Phase 2: 100 cases per agent
- Phase 3: 150 cases per agent
- Phase 4: 200 cases per agent

---

## WHAT THIS SPEC ENABLES

With this specification:

1. **Each agent is independently buildable** — clear contract, clear NLAH, clear backend
2. **Each agent is independently testable** — eval suite per agent
3. **Each agent is independently improvable** — Meta-Harness operates on individual NLAHs
4. **Failures are isolatable** — workspace separation prevents cascade
5. **Coordination is auditable** — all flows through supervisor + audit
6. **Self-evolution is bounded** — narrow improvements, eval-gated
7. **Coverage is measurable** — 85% Wiz target maps to specific agent capabilities

The runtime charter (next document) defines the universal physics that makes all this work — how contracts are enforced, how files are addressed, how patterns are implemented as primitives, how self-evolution operates safely.

The architecture (third document) translates spec + charter into deployment topology, communication infrastructure, and engineering blueprint.

This is your blueprint. Build the runtime charter next.
