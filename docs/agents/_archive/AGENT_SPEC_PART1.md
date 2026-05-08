# DETAILED AGENT SPECIFICATION
## [Product Name] — Production Specification of Fourteen Agents

**Document Version:** 1.0
**Status:** Draft for review
**Authors:** Detection Engineering Team
**Date:** [Current]
**Classification:** Confidential — Engineering Distribution

---

## DOCUMENT CONTROL

This is the canonical engineering specification for every agent in the platform. It is the input to NLAH authoring, eval suite construction, and engineering implementation. Changes to this document require Principal Detection Engineer approval and version control.

The companion documents are:
- Product Requirements Document (PRD) — what we are building and for whom
- Vision Document — where we are going
- Runtime Charter — universal physics governing all agents
- Platform Architecture — engineered system, deployment, operations
- NLAH Authoring Guide — standards for writing production NLAH files
- Detection Engineering Methodology — how detection rules are written and validated
- Layer-specific documents — Detection, Prevention, Investigation, Remediation, Compliance, Threat Intelligence

This document specifies WHAT each agent does. The Runtime Charter specifies the universal rules they all operate under. The NLAH Authoring Guide specifies HOW production NLAHs are written. Together these form the complete specification stack.

---

## TABLE OF CONTENTS

1. Foundational Concepts
2. Agent Roster and Phase Roadmap
3. Cross-Cutting Specifications
4. Agent 0 — Supervisor Agent
5. Agent 1 — Cloud Posture Agent
6. Agent 2 — Vulnerability Agent
7. Agent 3 — Identity Agent
8. Agent 4 — Runtime Threat Agent
9. Agent 5 — Data Security Agent
10. Agent 6 — Network Threat Agent
11. Agent 7 — Compliance Agent
12. Agent 8 — Investigation Agent
13. Agent 9 — Threat Intel Agent
14. Agent 10 — Remediation Agent
15. Agent 11 — Curiosity Agent
16. Agent 12 — Synthesis Agent
17. Agent 13 — Meta-Harness Agent
18. Agent 14 — Audit Agent
19. Inter-Agent Coordination Patterns
20. Eval Infrastructure Per Agent
21. Production Readiness Checklist

---

## 1. FOUNDATIONAL CONCEPTS

### 1.1 What is an agent in this platform

An agent in this platform is the combination of:

**A model** — a specific large language model with version pinned. At launch, Claude Sonnet 4.5 for most reasoning, Claude Haiku 4 for high-volume triage, Claude Opus 4.5 for high-stakes synthesis decisions.

**A harness** — comprising:
- *Backend infrastructure*: the actual tools, APIs, runtime primitives the agent uses. Stable, rarely changes. Implementation in Python (matching the detection scanner ecosystem).
- *Charter participation*: which charter primitives the agent uses, what charter rules it is subject to, what privileges it has within the charter.
- *NLAH (Natural Language Agent Harness)*: task-specific control logic expressed in structured natural language. The actual behavior of this specific agent. Frequently iterated, swappable per task family.

An agent is NOT:
- A single LLM call
- A long-running process
- A microservice in the traditional sense

Agents are instantiated per invocation. Each invocation is a new agent instance with fresh context but access to persistent state through file-backed storage.

### 1.2 The five-layer specification

Every agent in this document is specified across five layers:

**Layer 1 — Three-layer description.** Backend infrastructure (the actual code), charter participation (which rules apply), NLAH (the structured natural language harness). This layer defines what the agent IS.

**Layer 2 — Execution contract template.** The function signature for invoking this agent. Required outputs with schemas, budget caps, permitted tools subset, completion conditions, escalation rules. This layer defines how the agent IS INVOKED.

**Layer 3 — File-backed state schema.** What files this agent reads and writes, both per-invocation workspaces and persistent customer-specific stores. This layer defines how the agent PERSISTS STATE.

**Layer 4 — Self-evolution criteria.** Failure signals that trigger Meta-Harness Agent to rewrite this agent's NLAH. Specific thresholds, specific triggers, specific eval gates. This layer defines how the agent IMPROVES.

**Layer 5 — Pattern usage declaration.** Which canonical patterns from the runtime charter this agent uses (Routing, Parallelization, Orchestrator-Workers, Prompt Chaining, Evaluator-Optimizer). This layer defines how the agent COMPOSES.

These five layers, together with the original specification dimensions (domain, hire test, detection scope, prevention level, resolution capability, tools, memory, coordination, mapping), form the complete agent specification.

### 1.3 Why the multi-agent architecture

The platform could theoretically be built as one monolithic agent with hundreds of tools. We have explicitly chosen multi-agent architecture for three reasons:

**Domain size.** Tool count above roughly fifteen to twenty causes degraded tool selection accuracy in current LLMs. Spreading the platform's two-hundred-plus tools across fourteen specialized agents keeps each agent within the cognitive sweet spot.

**Hire test.** If we would hire separate humans for cloud security analysis, vulnerability management, identity engineering, runtime threat hunting, compliance auditing, and incident response, the agent system should mirror that division. Mixing roles forces context-switching that humans struggle with and LLMs struggle with similarly.

**Specialized context.** Each domain requires deep, focused knowledge. The Cloud Posture Agent needs detailed CSPM patterns and CIS benchmark logic. The Runtime Threat Agent needs eBPF semantics and MITRE ATT&CK runtime techniques. Loading all that into one agent's context window wastes tokens and degrades reasoning. Specialization allows depth.

These reasons compound: better tool selection plus deeper domain reasoning plus more focused context produces more reliable agent behavior. The cost is multi-agent coordination overhead, which we manage through the runtime charter's communication primitives.

### 1.4 Agent versus tool versus orchestration distinction

Confusion in this distinction is common. We define it precisely:

**A tool** is a deterministic function with bounded inputs and outputs. Trivy is a tool. The AWS API is exposed through tools. Cloud Custodian execution is a tool. Tools do not reason — they execute defined logic.

**An agent** is an LLM-driven reasoning entity that uses tools to accomplish tasks. The Cloud Posture Agent reasons about which Prowler scans to run, interprets results, applies customer context, prioritizes findings. It uses tools but is not itself a tool.

**Orchestration** is the coordination layer above agents. The Supervisor Agent does pure orchestration — routing tasks to specialists. The Investigation Agent does orchestration plus reasoning, spawning sub-agents while also reasoning about findings.

The architecture composes: orchestration agents coordinate specialist agents that use tools.

### 1.5 What agents share versus what they specialize

All agents share:
- The runtime charter (universal physics)
- Common backend infrastructure (Anthropic SDK, file I/O, audit logging)
- Common state primitives (workspaces, persistent memory, knowledge graph access)
- Common contract format
- Common reasoning trace requirements

Each agent specializes:
- Its domain expertise (loaded into NLAH)
- Its toolset (subset of platform's total tools)
- Its persistent state schema (domain-specific memory)
- Its eval suite (domain-specific test cases)
- Its self-evolution criteria (domain-specific failure signals)

The shared substrate is the runtime charter. The specialized layer is each agent's NLAH plus tools plus memory.

### 1.6 The "agents.md" routing topology concept

Following the OpenClaw pattern, the supervisor's `agents.md` file defines the routing topology: which specialists exist, their domain entry conditions, their tools, their handoff protocols. This is the supervisor's map of its team. When supervisor receives work, it consults agents.md to determine which specialist to delegate to.

The agents.md is versioned and signed, like all NLAH artifacts. Adding a new specialist requires updating agents.md and re-deploying the supervisor with the new routing topology.

### 1.7 The "user.md" concept for customer-specific tuning

Each agent has an optional `user.md` per customer that captures customer-specific tuning. The Cloud Posture Agent's user.md for Customer X might note that public S3 buckets in the `marketing-assets-*` namespace are intentional and should not be flagged. The Identity Agent's user.md for Customer Y might note that `automation-*` service accounts are expected to have admin access.

The user.md captures:
- Customer-specific exceptions and known-good patterns
- Customer-specific severity adjustments
- Customer-specific tool preferences
- Customer-specific communication tone
- Customer-specific compliance focus areas

The user.md is read by the agent at invocation. Updates to user.md happen through customer-facing configuration (not through Meta-Harness self-evolution — these are customer choices, not agent improvements).

### 1.8 Complete document scope

This document specifies all fourteen agents at production depth. Each agent specification includes:

- Purpose and domain ownership
- Hire test analog
- Detection scope (for detection agents) or capability scope (for orchestration/support agents)
- Prevention level (where applicable)
- Resolution capability
- Three-layer description
- Execution contract template (full YAML)
- File-backed state schema
- Self-evolution criteria
- Pattern usage declaration
- Tool catalog with full specifications
- Memory architecture
- Inter-agent coordination protocols
- Wiz capability mapping
- Coverage progression by phase

The document is approximately 240 pages at production density.

---

## 2. AGENT ROSTER AND PHASE ROADMAP

### 2.1 Complete roster

Per Interpretation A (full Phase 1 at 85% capability), all fourteen agents ship in Phase 1. The phase roadmap reflects capability deepening rather than agent introduction.

| # | Agent | Type | Domain | Phase 1 Capability |
|---|---|---|---|---|
| 0 | Supervisor | Orchestration | Routing and synthesis | Production |
| 1 | Cloud Posture | Domain Specialist | CSPM across providers | Production multi-cloud |
| 2 | Vulnerability | Domain Specialist | CVE management, IaC, secrets | Production |
| 3 | Identity | Domain Specialist | CIEM, permissions, access | Production multi-cloud |
| 4 | Runtime Threat | Domain Specialist | CWPP, runtime detection | Production |
| 5 | Data Security | Domain Specialist | DSPM, data classification | Production |
| 6 | Network Threat | Domain Specialist | Network IDS, traffic analysis | Production |
| 7 | Compliance | Domain Specialist | Framework reporting | Production with 30+ frameworks |
| 8 | Investigation | Domain Specialist | Deep-dive analysis, RCA | Production |
| 9 | Threat Intel | Domain Specialist | External intelligence correlation | Production with 15+ feeds |
| 10 | Remediation | Domain Specialist | Action drafting and execution | Production with all three tiers |
| 11 | Curiosity | Support | Proactive hypothesis generation | Production |
| 12 | Synthesis | Support | Multi-specialist integration | Production |
| 13 | Meta-Harness | Support | Self-evolution engine | Production with manual deploy |
| 14 | Audit | Support | Compliance evidence and audit log | Production |

### 2.2 Capability progression beyond Phase 1

Phase 1 ships at production capability across all agents. Subsequent phases deepen capability:

**Phase 2 (Months 13-18):** Refinement of Tier 1 autonomous remediation across more action classes. Self-evolution moves from manual deploy to automated deploy with strict criteria. Vertical specialization rule packs (healthcare, manufacturing, financial). FedRAMP Moderate certification.

**Phase 3 (Months 19-24):** SideScanning equivalent shipped. Cloud-to-code correlation production. Air-gap deployment. Additional cloud providers (OCI, Alibaba). Tier 1 autonomous expanded to 25+ action classes.

**Phase 4 (Months 25-30):** International expansion (EU, APAC). Vertical-specific compliance certifications (HITRUST, NERC-CIP, FedRAMP High). Mobile applications. Marketplace presence.

The agent roster does not change. The capability per agent expands.

### 2.3 Why fourteen and not more or fewer

We considered alternative roster sizes:

**Smaller (5-7 agents):** Would force domain agents to have 30-50 tools each, exceeding the LLM tool selection sweet spot. Would conflate domains that are genuinely separate (e.g., CSPM and CIEM). Rejected as undermining the multi-agent architecture's core benefit.

**Larger (20-30 agents):** Would create excessive coordination overhead. Would split domains that have natural cohesion (e.g., separating "AWS Cloud Posture" from "Azure Cloud Posture" as distinct agents). Would require routing logic that approaches the complexity of the work itself. Rejected as over-engineering.

**Fourteen** is the size that gives each agent a coherent domain with manageable tool count, while keeping coordination overhead bounded and routing logic tractable.

This is calibrated for current LLM capability. As foundation models improve their ability to handle larger toolsets and longer context, future versions might consolidate. As they improve their reasoning depth, future versions might split for finer specialization. The runtime charter is designed to accommodate either direction.

---

## 3. CROSS-CUTTING SPECIFICATIONS

These specifications apply to all agents and are referenced from individual agent sections rather than repeated.

### 3.1 Standard execution contract structure

Every agent invocation requires a contract conforming to this structure:

```yaml
contract_version: 1.0
contract_id: <UUID>
identity:
  source_agent: <agent_instance_id>
  target_agent: <agent_name>
  delegation_chain: <array of upstream agents>
  customer_id: <customer_uuid>
  trace_id: <distributed trace id>
  
task:
  type: <agent-specific task type>
  scope: <task-specific scope parameters>
  priority: <emergency | urgent | normal | background>
  deadline: <ISO 8601 timestamp or null>

required_outputs:
  <field_name>:
    type: <type>
    schema: <reference to JSON Schema>
    constraints: <agent-specific constraints>

budget:
  max_llm_calls: <integer>
  max_tokens: <integer>
  max_wall_clock_seconds: <integer>
  max_external_api_calls: <integer>
  max_workspace_mb: <integer>
  max_concurrent_subtasks: <integer>

permitted_tools: <array of tool ids>
forbidden_tools: <array of tool ids, usually empty>
conditional_tools:
  - tool_id: <tool>
    condition: <runtime condition>

completion_condition: <natural language description>
escalation_rules:
  on_budget_exceeded: <action>
  on_tool_failure: <action>
  on_low_confidence: <action>
  on_timeout: <action>

workspace: /workspaces/<customer_id>/<contract_id>/<agent_name>/
parent_workspace: <optional parent workspace path>
```

Agent-specific contracts in subsequent sections override and specialize this structure.

### 3.2 Standard workspace structure

Every agent invocation gets a workspace at the standard path:

```
/workspaces/<customer_id>/<contract_id>/<agent_name>/
  task.yaml                   # the contract for this invocation
  inputs/                     # what came in (uploaded data, references)
  working/                    # intermediate work products
  outputs/                    # what's going out (final structured output)
  reasoning_trace.md          # raw reasoning log (REQUIRED for all agents)
  audit/                      # audit events for this invocation
  errors/                     # any errors encountered
```

The `reasoning_trace.md` is mandatory for all agents and follows the format specified in the Runtime Charter Article 9.2. Meta-Harness Agent reads these for self-evolution.

### 3.3 Standard reasoning trace format

Every agent writes `reasoning_trace.md` in this format:

```markdown
# Agent Reasoning Trace

## Identity
- agent_type: <name>
- agent_version: <NLAH version>
- instance_id: <UUID>
- model: <model name and version>
- contract_id: <UUID>
- customer_id: <UUID>
- timestamp: <ISO 8601>

## Initial Context
[Summary of what the agent received]

## Initial Understanding
[Agent's first interpretation of the task in its own words]

## Decision Sequence

### Decision 1: <descriptive name>
**Reasoning:** [Raw reasoning, not summarized]
**Alternatives considered:** [What else was considered and why rejected]
**Action taken:** tool_call(name, args) OR conclusion
**Result:** [Tool result summary plus reference to raw result]
**Confidence:** [0-1] with explanation

### Decision 2: <descriptive name>
[Same structure]

[...continues for all major decisions...]

## Synthesis
[How the agent combined its decisions into final output]

## Final Output
[Reference to outputs/ directory]

## Self-Assessment
[Agent's own assessment of confidence, completeness, uncertainty]

## Notes for Meta-Harness
[Optional: agent's observations about its own performance, useful patterns, struggling areas]
```

This format is non-negotiable. Meta-Harness optimization quality depends critically on raw reasoning being captured rather than summarized.

### 3.4 Standard memory access patterns

All agents follow these memory access rules per Runtime Charter Article 3:

**Customer context (semantic memory):**
- Read access: all agents
- Write access: Supervisor only (after Synthesis Agent recommendation)
- Path: `/persistent/<customer_id>/customer_context.md`

**Agent-private memory:**
- Read access: agent itself + Meta-Harness (read-only)
- Write access: agent itself
- Path: `/persistent/<customer_id>/<agent_name>/`

**Knowledge graph:**
- Read access: all agents
- Write access: Memory Curator workflow (background process), not direct agent writes
- Mechanism: graph database queries via charter primitives

**Audit log:**
- Read access: Audit Agent + read-only by all
- Write access: append-only by all (mediated by charter)
- Path: `/persistent/<customer_id>/audit/`

### 3.5 Standard inter-agent communication

All inter-agent communication flows through one of three channels per Runtime Charter Article 5:

**Channel 1 — Supervisor delegation (primary):** Supervisor calls specialist with contract. Specialist returns output. Synchronous or asynchronous.

**Channel 2 — Parent-child (Investigation only):** Investigation Agent spawns sub-investigation agents. Limited to depth 1.

**Channel 3 — Workspace coordination (asynchronous):** Agent A writes to workspace. Agent B (later, via supervisor) reads from workspace.

Direct agent-to-agent calls are forbidden. The charter rejects them.

### 3.6 Standard self-evolution gating

Every agent's self-evolution proposals flow through Meta-Harness Agent with these gates per Runtime Charter Article 7:

1. **Trigger validation** — did the trigger condition genuinely fire?
2. **Trace analysis** — read RAW traces (not summaries)
3. **Proposal generation** — Meta-Harness drafts new NLAH
4. **Eval execution** — run against agent's eval suite
5. **Acceptance evaluation** — improvement >5% AND no regression >2%
6. **Cross-model validation** — works across model versions
7. **Signing and deployment** — HSM-signed, canary rollout

### 3.7 Standard tool call format

Every tool call follows this format and is intercepted by the charter:

```python
result = tool.call(
    tool_id="run_prowler_scan",
    params={
        "account_id": "123456789",
        "regions": ["us-east-1", "us-west-2"],
        "check_categories": ["s3", "iam", "ec2"]
    },
    timeout_seconds=60,
    audit_context={
        "delegation_id": "...",
        "agent_instance_id": "...",
        "reasoning_excerpt": "..."
    }
)
```

The charter validates the call against permitted_tools, budget, and rate limits before execution.

### 3.8 Standard error handling

Every agent handles errors per the failure taxonomy in Runtime Charter Article 8:

- Recoverable failures: agent self-handles
- Bounded failures: agent decides between continuing partial vs escalating
- Unrecoverable failures: escalate to parent or supervisor
- Catastrophic failures: charter triggers immediate human escalation

Agents do not silently fail. Every error path produces audit events and reasoning trace entries.

---

## 4. AGENT 0 — SUPERVISOR AGENT

### 4.1 Purpose

The Supervisor Agent is the orchestration layer of the platform. It receives heartbeat triggers and customer queries, routes work to appropriate specialists, coordinates parallel and sequential delegation, and authorizes Tier 1 autonomous actions within customer-defined scope.

The Supervisor Agent does not perform detection. It does not perform remediation. It does not synthesize multi-specialist output (delegated to Synthesis Agent). It is intentionally lightweight, with the smallest tool count of any agent in the platform.

This minimalism is deliberate. Per the orchestrator-workers pattern principle, the orchestrator should delegate ~90% of compute to child agents. A heavyweight supervisor undermines this principle.

### 4.2 Hire test analog

Senior SOC dispatcher or operations manager. Knows which analyst handles which type of work. Knows when to fan-out work in parallel and when to sequence it. Does not do the analysis themselves. Maintains awareness of team capacity and individual specialist status.

The supervisor analog is NOT a senior security architect (that role is the customer's CISO and our Synthesis Agent). The supervisor analog is NOT an investigator (that role is the Investigation Agent). The supervisor analog is NOT a decision-maker on technical questions (those go to specialists).

### 4.3 Capability scope

**Triggering:**
- Heartbeat triggers (every 60 seconds during normal operation)
- Real-time event triggers (preempting heartbeat for critical events)
- Customer query triggers (conversational interface)
- Scheduled triggers (compliance reports, weekly briefings)
- Manual triggers (customer-initiated investigations)

**Routing decisions:**
- Determine which specialist or specialists handle each piece of work
- Determine whether work should be parallel or sequential
- Determine appropriate priority level
- Determine appropriate timeout deadlines
- Determine when to escalate to humans rather than delegate

**Coordination:**
- Manage parallel delegation fan-out
- Sequence dependent delegations
- Aggregate specialist outputs (then hand off to Synthesis Agent)
- Manage delegation timeouts
- Handle specialist failures gracefully

**Authorization:**
- Verify customer's Tier 1 authorization for proposed autonomous actions
- Authorize Synthesis Agent to update customer-facing context
- Authorize cross-specialist context sharing through workspace coordination

### 4.4 Three-layer description

#### 4.4.1 Backend infrastructure

The Supervisor Agent's backend infrastructure is intentionally minimal:

- **Heartbeat scheduler** (Kubernetes CronJob or equivalent) that triggers supervisor instances on regular intervals
- **Distributed lock service** (Redis or etcd) for per-customer concurrency control — only one supervisor instance per customer at a time
- **Message queue** (NATS or Redis Streams) for delegation messaging
- **Customer authorization service** for tier verification
- **Audit log writer** for recording all delegations
- **Routing table parser** for `agents.md` interpretation

The supervisor backend does not include:
- Detection scanners (specialist domain)
- Remediation execution (Remediation Agent domain)
- LLM reasoning beyond routing (delegated to specialists)
- Knowledge graph write capability (Memory Curator domain)

This minimalism keeps the supervisor reliable. The supervisor is on the critical path for every operation; failures here cascade. By keeping its responsibilities narrow, we keep its failure surface narrow.

#### 4.4.2 Charter participation

The Supervisor Agent has unique privileges within the runtime charter:

**Privileges:**
- Spawn parallel specialist invocations (other agents can only spawn sub-agents in the Investigation case)
- Update shared customer context memory (no other agent can write here)
- Authorize Tier 1 autonomous actions before Remediation Agent executes them
- Hand off to Synthesis Agent for customer-facing output integration
- Read all specialist workspaces in flight (for coordination)

**Restrictions:**
- Cannot itself call detection or remediation tools (must delegate)
- Cannot perform domain analysis (must delegate)
- Cannot execute against customer infrastructure (Remediation Agent only)
- Cannot modify NLAH or charter (Meta-Harness or engineering only)

**Subject to:**
- Maximum delegation depth: 2 (supervisor → specialist → at most one sub-agent for Investigation)
- Must record every delegation in audit log before specialist begins work
- Must respect specialist budget and timeout boundaries
- Must release distributed lock before instance termination

#### 4.4.3 NLAH

The Supervisor Agent's NLAH is structured natural language defining its role, decision-making heuristics, routing logic, parallelization rules, failure handling, and explicit prohibitions.

The full production NLAH is approximately 800-1200 lines. The outline structure below captures the major sections; full content is authored in Batch 3 of this document set.

```
ROLE
====
Security operations dispatcher. The orchestration layer between customer
events and specialist agents. The function is delegation and synthesis
coordination, not analysis or action.

EXPERTISE
=========
- Routing logic across security operations domains
- Specialist capabilities and their boundaries
- Customer authorization tiers and what they authorize
- Coordination patterns: when to parallelize, when to sequence
- Customer communication preferences (channel, tone, frequency)
- Escalation criteria for human involvement

DECISION HEURISTICS
===================
H1: Delegate. Do not analyze.
    The supervisor's job is routing, not reasoning about findings.
    When tempted to interpret a finding, route it to the relevant
    specialist instead.

H2: Match work to authorization tier.
    Tier 1 autonomous actions are pre-authorized by customer.
    Tier 2 approval-gated actions go through approval workflow.
    Tier 3 recommendations go to humans for execution.
    When tier is ambiguous, default to Tier 3.

H3: Parallel over sequential when possible.
    Independent findings should fan out to specialists in parallel.
    Sequence only when there are explicit dependencies.

H4: Time-box every delegation.
    No specialist invocation runs unbounded.
    If a specialist cannot complete in budget, force decision:
    return partial or escalate.

H5: Escalate to humans for ambiguous authorization.
    When you cannot determine the right tier, ask a human.
    Better to slow a remediation than authorize incorrectly.

H6: Customer context comes first.
    Always check customer_context.md before routing.
    Customer's authorization profile, change windows, compliance focus
    all affect routing decisions.

ROUTING TABLE (consulted in order)
==================================

Routing rules with priority order. Each rule has:
- condition: when this rule applies
- target: which specialist receives the work
- priority: rule precedence (lower number = higher priority)
- modifiers: additional handling instructions

[Routing table contents - approximately 200 lines of explicit rules
covering all delta types, query types, and edge cases. Generated
from agents.md routing topology and updated when specialists change.]

PARALLEL DELEGATION RULES
=========================

When to parallelize:
- Independent findings across different specialists
- Cross-cloud findings: parallel per cloud, then synthesize
- Multi-framework compliance reports
- Bulk asset analysis

When to sequence:
- Investigation handoffs (initial detection → deep investigation)
- Remediation drafting after detection
- Compliance reporting after specialist findings
- When specialist B needs specialist A's output

Concurrency limits:
- Maximum 5 parallel delegations per customer at any time
- Maximum 3 parallel delegations of the same specialist type
- Critical priority delegations bypass normal queue

FAILURE HANDLING
================

On specialist budget exceeded:
  Log the partial result.
  Decide: accept partial or retry with extended budget.
  Default: accept partial if findings present, retry if empty.
  Escalate to Investigation Agent if pattern recurs.

On specialist returns low confidence:
  Request second opinion from peer specialist if available.
  If still low confidence after second opinion, route to
  Investigation Agent for deeper analysis.

On specialist unavailable (down, errored, queue full):
  Use backup specialist if available.
  If no backup, defer the work and notify customer of degraded service.
  Critical work cannot be deferred — escalate immediately.

On specialist returns malformed output:
  Reject the output, request retry with explicit format guidance.
  After 2 retries, escalate to Investigation Agent.
  Log Meta-Harness trigger for the failing specialist.

WHAT YOU NEVER DO
=================

NEVER perform detection scans yourself.
NEVER make remediation decisions yourself.
NEVER synthesize multi-specialist outputs (delegate to Synthesis Agent).
NEVER skip audit logging for any delegation.
NEVER authorize Tier 1 action without explicit customer pre-authorization.
NEVER bypass the agents.md routing table even when "obvious" routing seems clear.
NEVER call specialists directly without contracts.
NEVER allow a specialist to spawn beyond depth 1 (only Investigation can spawn).

CUSTOMER COMMUNICATION
======================

For customer queries via conversational interface:
  Route to the most relevant specialist based on query content.
  For multi-domain queries, route to Synthesis Agent for integration.
  Always include customer's preferred communication style in delegation context.

For routine notifications (alerts, briefings):
  Route to Synthesis Agent for content preparation.
  Synthesis Agent handles tone matching to customer preferences.

For critical alerts:
  Bypass normal queue, prioritize delegation.
  Notify customer immediately even if specialist analysis incomplete.
```

The full NLAH includes detailed routing rules, edge case handling, customer-specific tuning patterns, and worked examples. The Batch 3 NLAH document provides the complete production specification.

### 4.5 Execution contract template

Supervisor Agent invocations come from three sources: heartbeat scheduler, real-time events, customer queries. The contract structure varies by source.

**Heartbeat invocation contract:**

```yaml
contract_version: 1.0
contract_id: <UUID>
identity:
  source_agent: heartbeat_scheduler
  target_agent: supervisor
  customer_id: <UUID>
  trace_id: <UUID>

task:
  type: heartbeat_cycle
  scope:
    cycle_number: <integer>
    last_cycle_timestamp: <ISO 8601>
    pending_findings_count: <integer>
    pending_approvals_count: <integer>
  priority: normal
  deadline: 60 seconds from invocation

required_outputs:
  cycle_summary:
    type: object
    schema: CycleSummary  # see schema definition
  delegations_initiated:
    type: array
    schema: array of DelegationRecord
  cycle_outcome:
    type: enum
    values: [completed, partial, failed]

budget:
  max_llm_calls: 5
  max_tokens: 4000
  max_wall_clock_seconds: 30
  max_concurrent_subtasks: 5

permitted_tools:
  - delegate_to
  - delegate_parallel
  - query_routing_table
  - read_customer_context
  - update_customer_context
  - check_tier1_authorization
  - escalate_to_human
  - request_synthesis
  - record_audit

completion_condition: |
  Cycle summary written to workspace
  AND all delegations initiated have audit records
  AND any escalations have been routed
  AND distributed lock released

escalation_rules:
  on_budget_exceeded: complete_with_partial_summary
  on_lock_unavailable: skip_cycle_log_reason
  on_systemic_failure: escalate_immediately

workspace: /workspaces/<customer_id>/heartbeat_<cycle_number>/supervisor/
```

**Real-time event contract:**

```yaml
identity:
  source_agent: event_dispatcher
  target_agent: supervisor
  customer_id: <UUID>
  trace_id: <UUID>

task:
  type: real_time_event
  scope:
    event_id: <UUID>
    event_type: enum [critical_finding, identity_anomaly, runtime_threat, network_threat]
    event_data: <structured event payload>
    severity_initial: enum
  priority: emergency
  deadline: 10 seconds from invocation

required_outputs:
  routing_decision:
    target_specialist: <agent name>
    rationale: text
  delegation_initiated: bool
  human_notification_sent: bool

budget:
  max_llm_calls: 2  # fast-path
  max_tokens: 2000
  max_wall_clock_seconds: 10

permitted_tools:
  - delegate_to
  - check_tier1_authorization
  - escalate_to_human
  - record_audit

completion_condition: |
  Specialist invoked OR human notified
  AND audit record created
```

**Customer query contract:**

```yaml
identity:
  source_agent: conversational_api
  target_agent: supervisor
  customer_id: <UUID>
  trace_id: <UUID>

task:
  type: customer_query
  scope:
    query_text: <customer natural language query>
    conversation_history: <recent context>
    user_id: <user identifier>
  priority: urgent  # customer is waiting
  deadline: 5 seconds for routing decision

required_outputs:
  query_classification:
    primary_domain: <agent name>
    secondary_domains: <array>
    requires_synthesis: bool
  delegations_initiated: array

budget:
  max_llm_calls: 3
  max_tokens: 3000
  max_wall_clock_seconds: 5

permitted_tools:
  - delegate_to
  - delegate_parallel
  - query_routing_table
  - read_customer_context
  - request_synthesis
  - record_audit

completion_condition: |
  Query routed to appropriate specialist(s)
  OR Synthesis Agent invoked for multi-domain query
```

### 4.6 File-backed state schema

```
/workspaces/<customer_id>/<contract_id>/supervisor/
  task.yaml                       # the contract
  routing_decision.yaml           # which specialists were chosen and why
  delegations_initiated/
    <delegation_id>_record.yaml   # one record per delegation
  cycle_summary.yaml              # for heartbeat invocations
  reasoning_trace.md              # raw reasoning
  errors/                         # any errors encountered
  audit_events.jsonl              # audit events generated

/persistent/<customer_id>/supervisor/
  routing_history.jsonl           # append-only history of all routing decisions
  routing_effectiveness.json      # which routing rules work well
  specialist_health.json          # current specialist availability and performance
  customer_communication_style.yaml  # customer's preferred tone/channel
  escalation_history.jsonl        # when human was escalated to and why
  cycle_metrics.jsonl             # heartbeat cycle performance metrics

/persistent/global/supervisor/
  agents.md                       # the routing topology (versioned, signed)
  routing_rules.yaml              # parsed routing table
  pattern_library.md              # parallelization vs sequencing patterns
```

### 4.7 Self-evolution criteria

Supervisor harness rewrite triggered when:

**Routing accuracy degradation:**
- Routing accuracy < 90% over rolling 1000 heartbeats (specialists return "wrong domain" or "task not in my scope")
- Trigger: log analysis weekly, escalate to Meta-Harness if threshold breached

**Over-delegation:**
- Average delegation depth > 1.5 (supervisor invoking too many sub-paths per heartbeat)
- Suggests routing logic is over-decomposing work

**Specialist failure cascade:**
- Specialist failure rate > 5% (suggests routing too-complex tasks to underpowered specialists)
- Or routing tasks beyond specialist's scope

**Customer dissatisfaction signal:**
- Manual review escalations increasing
- Customer overrides of routing decisions
- Customer complaints about "wrong agent answered"

**Performance degradation:**
- Heartbeat cycles consistently approaching deadline
- Decision latency P95 increasing over time

When triggered, Meta-Harness Agent:
1. Reads supervisor's recent reasoning traces (not summaries)
2. Identifies patterns in routing failures
3. Proposes new agents.md routing rules and/or new supervisor NLAH
4. Runs proposal against supervisor eval suite (200 routing test cases)
5. Accepts if eval improvement > 5% with no regression > 2%
6. Signs and deploys new version via canary rollout

### 4.8 Pattern usage declaration

**Primary patterns:**
- **Routing** — the supervisor's entire purpose
- **Parallelization** — when independent findings fan out

**Secondary patterns:**
- None directly used (synthesis delegated, eval-optimizer delegated to Meta-Harness, prompt chaining only within decision flow)

**Forbidden patterns:**
- **Orchestrator-Workers** — supervisor does not directly orchestrate sub-agents (Investigation Agent does for its sub-investigations)
- **Evaluator-Optimizer** — supervisor does not optimize its own NLAH (Meta-Harness does)
- **Prompt Chaining** within domain analysis (no domain analysis happens in supervisor)

### 4.9 Tools

The supervisor has nine tools, deliberately minimal:

| Tool ID | Purpose | Returns | Charter Validation |
|---|---|---|---|
| `delegate_to` | Synchronously invoke a specialist with contract | Specialist output or error | Validates target_agent in agents.md |
| `delegate_parallel` | Fan out to multiple specialists | Array of outputs/errors | Validates concurrency limits |
| `query_routing_table` | Read agents.md routing rules | Structured routing rules | Read-only |
| `read_customer_context` | Read customer_context.md | Customer context structured | Read-only |
| `update_customer_context` | Update customer_context.md (supervisor-only privilege) | Confirmation | Validates write authority |
| `check_tier1_authorization` | Verify customer authorized this Tier 1 action class | bool with reasoning | Validates against authorization profile |
| `escalate_to_human` | Send notification to human responder | Notification ID | Validates escalation criteria |
| `request_synthesis` | Invoke Synthesis Agent with specialist outputs | Synthesized output | Validates Synthesis Agent availability |
| `record_audit` | Write to audit log | Audit ID with hash chain | Mandatory for every delegation |

Each tool's full specification (parameters, returns, error modes, audit requirements) is in the Tool Specification document.

### 4.10 Memory architecture

**Episodic memory (recent, detailed):**
- Recent routing decisions (last 24 hours)
- Recent specialist response times
- Recent escalations
- Stored in `/persistent/<customer_id>/supervisor/routing_history.jsonl`
- Used for: detecting patterns in routing effectiveness

**Semantic memory (long-term, distilled):**
- Customer's communication preferences
- Customer's authorization profile
- Customer's typical work patterns
- Stored in customer context (read-only) and `customer_communication_style.yaml`
- Used for: tailoring routing and communication

**Procedural memory (learned playbooks):**
- Routing rule effectiveness scores
- Successful escalation patterns
- Stored in `/persistent/<customer_id>/supervisor/routing_effectiveness.json`
- Used for: improving routing decisions over time

The supervisor's memory is shallow compared to specialists — it does not need deep domain expertise stored over time.

### 4.11 Inter-agent coordination

**The supervisor coordinates with all specialists.** It is the only agent that does so directly.

Coordination patterns:

**Delegation pattern (most common):**
1. Supervisor receives trigger
2. Consults agents.md for routing
3. Builds contract for target specialist
4. Calls `delegate_to` (synchronous) or `delegate_parallel` (fan-out)
5. Receives specialist output
6. Records audit, updates customer context if needed
7. Hands off to Synthesis Agent for customer-facing integration

**Escalation pattern:**
1. Supervisor receives ambiguous case
2. Routes to Investigation Agent for deeper analysis
3. Investigation Agent may spawn sub-agents
4. Investigation result returns to supervisor
5. Supervisor routes follow-up actions to relevant specialists

**Customer query pattern:**
1. Customer asks question via conversational interface
2. Supervisor classifies query domain
3. Routes to specialist (single domain) or Synthesis Agent (multi-domain)
4. Output returns through Synthesis Agent for customer-facing format
5. Conversational interface delivers to customer

### 4.12 Wiz capability mapping

The Supervisor Agent has no direct Wiz analog. Wiz uses traditional UI as the primary customer surface; we use a supervisor agent. This is a category difference, not a feature comparison.

What Wiz handles in their UI dashboard layer (filtering findings, presenting prioritization, suggesting remediation), our supervisor handles by routing to specialists who do the actual analysis. Wiz's UI is a presentation layer; our supervisor is an operational layer.

### 4.13 Coverage

Supervisor ships at production capability in Phase 1. Subsequent improvements come through Meta-Harness self-evolution rather than capability expansion.

---

## 5. AGENT 1 — CLOUD POSTURE AGENT

### 5.1 Purpose

The Cloud Posture Agent owns Cloud Security Posture Management (CSPM). It detects misconfigurations across cloud infrastructure that violate security baselines, compliance frameworks, or customer-defined policies. It produces context-rich findings including business impact, attack path implications, and remediation guidance for handoff to the Remediation Agent.

This is the most frequently invoked agent in the platform. It runs every six hours per cloud account during normal operation and on-demand for customer queries about cloud posture. Its quality directly determines whether the platform is perceived as accurate or noisy.

### 5.2 Hire test analog

Cloud security analyst with deep expertise in CIS Benchmarks, NIST cloud security frameworks, and common misconfiguration patterns. Five-plus years of experience reviewing cloud configurations. Has experience with multi-cloud environments. Understands how attackers exploit misconfigurations. Can distinguish high-context findings (S3 bucket public + contains PII + accessible by over-privileged identity) from low-context noise.

### 5.3 Detection scope

The Cloud Posture Agent's detection scope is comprehensive across AWS, Azure, GCP, and Kubernetes from launch. The full pattern catalog is approximately 3,000 distinct misconfiguration patterns at production:

#### 5.3.1 AWS coverage (1,200+ patterns)

**S3 storage:**
- Public bucket ACLs (BucketPolicy-based, ACL-based, Block Public Access disabled)
- Buckets without encryption at rest (SSE-S3, SSE-KMS, SSE-C, SSE-DSSE)
- Buckets without server access logging
- Buckets without versioning where required by compliance
- Buckets without MFA Delete on production data
- Cross-account access misconfigurations (overly permissive bucket policies)
- Lifecycle policy gaps (no transition to cheaper storage, no deletion of old data)
- Block Public Access settings disabled at account level
- Cross-region replication misconfigurations
- Missing CloudFront distribution origin access identity
- Buckets exposed via Transfer Family or DataSync
- Storage class misconfigurations (using STANDARD when IA appropriate)

**EC2 compute:**
- Instances with public IPs in subnets that should be private
- Security groups with 0.0.0.0/0 ingress on sensitive ports (22, 3389, 445, 1433, 3306, 5432, 5984, 6379, 9200, 9300, 27017)
- Default VPC usage in production
- Instances without IMDSv2 enforced (IMDSv1 abuse vector)
- Unencrypted EBS volumes
- Unencrypted EBS snapshots
- Public AMIs from non-trusted sources
- Outdated AMIs (>180 days from release)
- Missing instance profile for required access
- Detailed monitoring disabled
- Termination protection missing on critical instances
- Stop hibernation enabled for sensitive workloads
- User data containing secrets

**RDS database:**
- Publicly accessible databases
- Missing encryption at rest
- Missing encryption in transit (require_secure_transport)
- Weak password policies
- Default master username (admin, root)
- Missing automated backups
- Backup retention < 7 days
- Public snapshots
- Cross-region snapshot copies to non-approved regions
- Missing deletion protection on production databases
- Missing performance insights
- Missing CloudWatch logs export
- Multi-AZ disabled on production databases

**IAM (basic, deep analysis to Identity Agent):**
- Root account usage
- Missing MFA on root and privileged accounts
- IAM access keys older than 90 days
- IAM password policy below minimum requirements
- Cross-account trust relationships without external ID
- Federation misconfigurations (missing audience claim, wide audience)
- Service-linked role abuse
- Inline policies on users (should be group/role policies)

**CloudTrail and logging:**
- CloudTrail not enabled in all regions
- CloudTrail logs not encrypted with customer-managed KMS keys
- CloudTrail log file validation disabled
- CloudTrail multi-region trail missing
- VPC flow logs disabled
- DNS query logs disabled
- Config not enabled
- Config delivery channel misconfigured
- CloudWatch alarms missing for critical events

**KMS encryption:**
- Customer-managed keys with rotation disabled
- Key policies overly permissive (allowing cross-account abuse)
- Default encryption keys where customer keys required by compliance
- Key sharing with non-authorized accounts
- Symmetric keys used where asymmetric required
- Missing key alias

**Lambda serverless:**
- Functions with public invocation permissions (resource-based policies allowing *)
- Functions with old runtime versions (Python 2.7, Node 14, etc.)
- Functions with secrets in environment variables
- Functions without VPC configuration where required
- Functions with overly permissive execution roles
- Layer permissions overly broad
- Provisioned concurrency on non-critical functions (cost)
- Reserved concurrency missing on critical functions

**ECS/EKS containers:**
- Cluster API server publicly accessible
- ECS task definitions with privileged containers
- ECS task definitions with host networking
- EKS cluster logging disabled
- EKS without OIDC provider for IAM Roles for Service Accounts
- Container insights disabled
- Service mesh not configured for east-west traffic encryption
- Image scanning disabled on ECR repositories
- Image pull policy not "Always" for production

**VPC and networking:**
- Default VPC usage
- VPC peering with overly permissive routes
- NACL rules overly permissive
- Route tables routing to deprecated/unused gateways
- Internet Gateway attached where not needed
- NAT Gateway redundancy missing
- VPC endpoints missing for AWS services (forcing internet routing)
- Transit Gateway misconfigurations
- Direct Connect misconfigurations

**API Gateway:**
- API endpoints without authentication
- API endpoints without rate limiting
- API endpoints with permissive CORS
- API logging disabled
- API access logging not encrypted
- WebSocket APIs without authorizers

**Secrets Manager and Parameter Store:**
- Secrets without rotation enabled
- Secret rotation older than required (30/60/90 days)
- Secrets shared cross-account inappropriately
- Parameter Store SecureString not used where appropriate

**Application services:**
- ELB without HTTPS listeners
- ELB with permissive security groups
- CloudFront with missing WAF
- CloudFront origins exposed directly
- SES configuration sets without event publishing
- SQS queues with overly permissive policies
- SNS topics without encryption
- DynamoDB tables without encryption
- DynamoDB tables without point-in-time recovery
- ElastiCache without encryption in transit
- ElastiCache without encryption at rest
- Kinesis streams without encryption

**Newer/specialized services:**
- AppRunner services with public access where not intended
- Bedrock models with overly broad permissions
- SageMaker notebooks with default IAM roles
- Glue jobs with overly broad S3 access
- Athena results buckets misconfigured
- QuickSight datasets with overly broad permissions

The full AWS catalog covers all CIS AWS Foundations Benchmark v3.0 controls plus extensions for newer services and customer-driven additions.

#### 5.3.2 Azure coverage (1,000+ patterns)

(Equivalent depth across Azure services. Full enumeration follows similar structure.)

**Storage accounts:**
- Public blob access enabled
- Storage accounts without secure transfer required
- Storage account keys not rotated
- Soft delete not enabled
- Versioning disabled where required
- Cross-tenant access misconfigurations

**Compute (VMs):**
- VMs with public IPs
- Network Security Groups with overly permissive rules
- Just-In-Time access not configured
- Disk encryption not enabled
- Boot diagnostics with secrets

**Azure SQL Database:**
- Public network access enabled
- Transparent Data Encryption disabled
- Auditing disabled
- Vulnerability assessment disabled
- Advanced threat protection disabled
- Geo-replication misconfigurations

**Azure Active Directory / Entra ID (basic):**
- Conditional Access policies missing
- MFA enforcement gaps
- Privileged Identity Management not used for admin roles
- Guest user permissions too broad
- Application registrations with overly permissive consent

**Key Vault:**
- Public network access enabled
- Soft delete disabled
- Purge protection disabled
- Access policies overly broad
- Logging not configured
- Firewall rules permissive

**App Services:**
- HTTPS not required
- TLS version below 1.2
- FTP enabled
- Authentication disabled where required
- App Insights not configured
- Backup not configured

**Azure Monitor:**
- Diagnostic settings missing on critical resources
- Log Analytics workspace not configured
- Activity Log alerts missing for critical events
- Network Watcher not enabled

**Azure Container services:**
- AKS cluster with default Kubernetes RBAC settings
- AKS without Azure AD integration
- AKS without network policies
- AKS without pod security standards
- ACR with admin user enabled
- ACR without geo-replication for production

**Azure Networking:**
- NSGs with overly permissive rules
- Application Gateway without WAF
- DDoS protection disabled on critical applications
- VPN gateway with weak protocols
- ExpressRoute misconfigurations

(Continues for all Azure services in scope.)

#### 5.3.3 GCP coverage (800+ patterns)

(Equivalent depth across GCP services.)

**Cloud Storage:**
- Public buckets
- Buckets without uniform bucket-level access
- Buckets with IAM members allUsers/allAuthenticatedUsers
- Buckets without versioning where required
- Buckets without retention policies for compliance

**Compute Engine:**
- Instances with default service accounts
- Instances with project-wide SSH keys enabled
- Instances with serial console enabled
- Disk encryption with default service-managed keys (when CMEK required)

**Cloud SQL:**
- Public IP enabled
- Authorized networks too broad
- SSL not required
- Backup not enabled
- Point-in-time recovery disabled

**IAM (basic, deep to Identity Agent):**
- Service account keys not rotated
- Default service account usage
- Cross-project IAM misconfigurations
- Workload Identity Federation misconfigurations
- Conditional IAM bindings missing where required

**Logging and monitoring:**
- Cloud Audit Logs not configured
- VPC Flow Logs disabled
- DNS audit logging disabled
- Log sinks without proper destinations

**BigQuery:**
- Datasets publicly accessible
- Tables without column-level security
- Authorized views misconfigurations
- Cross-project access too broad

**GKE:**
- Cluster public endpoints
- Workload Identity not enabled
- Network policies disabled
- Binary Authorization not enforced
- Private cluster not configured for production

**KMS:**
- Keys without rotation
- Keys with overly broad bindings
- Default keys used where customer keys required

**Cloud Functions / Cloud Run:**
- Functions with public invocation
- Functions without VPC connector when required
- Cloud Run services with overly broad service accounts
- Cloud Run with allUsers invoker role

(Continues for all GCP services in scope.)

#### 5.3.4 Kubernetes coverage (600+ patterns)

This applies to managed Kubernetes (EKS, AKS, GKE) and self-managed Kubernetes:

**Cluster-level:**
- API server publicly accessible
- API server without RBAC
- Audit logging disabled
- Pod Security Standards not enforced
- Network policies missing
- Admission controllers misconfigured
- Kubernetes version more than 2 minor versions behind
- etcd not encrypted at rest
- kubelet authentication disabled
- API server not using mutual TLS

**Workload-level (Pods, Deployments, StatefulSets):**
- Privileged containers
- hostNetwork: true
- hostPID: true
- hostIPC: true
- runAsRoot: true (without explicit justification)
- allowPrivilegeEscalation: true
- readOnlyRootFilesystem: false
- capabilities being added (NET_ADMIN, SYS_ADMIN, etc.)
- Missing resource limits
- Missing resource requests
- imagePullPolicy: Never (for production)
- Latest image tag used (no version pinning)
- automountServiceAccountToken: true (when not needed)

**RBAC:**
- ClusterRoleBindings with cluster-admin granted broadly
- Wildcard verbs in roles (*)
- Wildcard resources in roles (*)
- Service accounts with cluster-admin
- Default service accounts used in production namespaces
- Aggregated cluster roles overly broad

**Network:**
- Services with type LoadBalancer in non-internet-facing contexts
- Services exposed via NodePort without justification
- Ingress without TLS
- Ingress without WAF (where applicable)
- NetworkPolicies missing or default-allow

**Storage:**
- PersistentVolumes without encryption
- StorageClasses without encryption requirement
- ConfigMaps containing secrets
- Secrets stored unencrypted in etcd

**CI/CD and supply chain:**
- ImagePullSecrets not configured properly
- Image signing not verified
- Pod Security Policies (deprecated) still in use
- OPA/Gatekeeper / Kyverno policies missing for org standards

#### 5.3.5 Microsoft 365 coverage (200+ patterns)

For customers with M365:
- Exchange Online configuration issues
- SharePoint sharing settings too broad
- Teams external access policies
- OneDrive sharing policies
- Conditional Access gaps
- Compliance policies missing

#### 5.3.6 OCI and Alibaba coverage (200+ patterns each)

Targeted coverage of common patterns across OCI and Alibaba Cloud for customers operating in those environments. Full coverage in subsequent phases.

### 5.4 Prevention level

The CSPM domain is fundamentally **detective** — it finds misconfigurations after they exist. Prevention happens through three mechanisms:

**Pre-deployment (delegated to IaC scanning):**
The Cloud Posture Agent does not directly scan IaC. The Vulnerability Agent handles IaC scanning via Checkov. Findings from IaC scan that overlap with CSPM rules are correlated.

**Drift detection (continuous):**
The agent detects when configurations drift from baseline immediately. Customer's baseline established during onboarding (first 7 days). Subsequent drift triggers detection.

**Remediation handoff:**
Every CSPM finding includes remediation hint. The Remediation Agent receives this hint and drafts the actual remediation action (Cloud Custodian policy, Terraform diff, etc.).

The Cloud Posture Agent does not itself prevent in real-time. Real-time blocking of changes is handled by Kubernetes admission controllers (Kyverno, OPA Gatekeeper) at the Runtime Threat Agent's coordination level, or by IaC scanning at deployment time.

### 5.5 Resolution capability

The Cloud Posture Agent does not execute remediations directly. Per the agent design principle of separation of concerns, all remediation execution flows through the Remediation Agent.

The Cloud Posture Agent's resolution capability is:

**Producing structured findings:**
Each finding includes finding identifier, asset, misconfiguration type, severity, business impact reasoning, suggested remediation type (handoff to Remediation Agent), compliance frameworks affected (handoff to Compliance Agent), confidence score, related findings.

**Recommending remediation type:**
The agent classifies the appropriate remediation approach: Cloud Custodian policy, Terraform diff, IaC fix PR, manual runbook, CloudFormation change. The Remediation Agent then drafts the specific action.

**Identifying compliance impact:**
Each finding maps to applicable compliance controls. The Compliance Agent uses this for framework reporting.

**Surfacing attack path implications:**
For findings that are part of multi-condition attack paths (toxic combinations), the agent flags this for Investigation Agent attention.

### 5.6 Three-layer description

#### 5.6.1 Backend infrastructure

The Cloud Posture Agent's backend infrastructure includes:

**Detection scanners:**
- Prowler 5.x (primary scanner, multi-cloud)
- Steampipe with all relevant cloud plugins
- Cloud Custodian in read-only mode (for policy queries, not execution)
- ScoutSuite as backup multi-cloud scanner
- AWS Config / Azure Policy / GCP Security Command Center API clients
- AWS Security Hub API client
- Microsoft Defender for Cloud API client
- GCP Security Command Center API client

**Cloud provider SDKs:**
- boto3 (AWS) with all relevant service clients
- azure-sdk-for-python with all relevant resource clients
- google-cloud-* libraries
- oci-python-sdk
- aliyun-python-sdk

**Graph access:**
- Neo4j read connection (posture subgraph queries)
- Cartography read access for asset relationship queries

**Memory access:**
- TimescaleDB connection for episodic memory
- PostgreSQL connection for procedural memory
- File system access for workspace and persistent state

#### 5.6.2 Charter participation

The Cloud Posture Agent operates under standard charter rules with these specifics:

**Privileges:**
- May invoke parallel cloud API calls (within budget)
- May write findings directly to findings store (high-volume, low-risk writes)
- May read all relevant customer cloud accounts via assumed roles

**Restrictions:**
- Cannot write to knowledge graph directly (must go through Memory Curator workflow)
- Cannot execute remediations (handoff to Remediation Agent)
- Cannot directly modify customer cloud resources
- Must respect cloud API rate limits (charter enforces)
- Must log every cloud API call to workspace audit

**Subject to:**
- Standard contract enforcement
- Standard budget caps
- Standard tool permission model
- Mandatory `reasoning_trace.md` per invocation

#### 5.6.3 NLAH

The Cloud Posture Agent's NLAH is structured natural language defining role, expertise, decision heuristics, stages, failure taxonomy, contracts required, and explicit prohibitions. The full production NLAH is approximately 1,000-1,500 lines.

```
ROLE
====
Cloud security posture analyst. Detect misconfigurations across
AWS, Azure, GCP, Kubernetes, and other cloud infrastructure.
Produce context-rich findings with business impact, attack path
implications, and remediation guidance.

EXPERTISE
=========

Frameworks and standards:
- AWS Well-Architected Framework (all six pillars)
- Azure Cloud Adoption Framework
- Google Cloud Architecture Framework
- CIS Benchmarks (AWS, Azure, GCP, Kubernetes — current versions)
- NIST Cybersecurity Framework 2.0
- NIST 800-53 Rev 5 cloud-relevant controls
- CSA Cloud Controls Matrix
- PCI-DSS 4.0 cloud-relevant controls
- HIPAA Security Rule cloud implementation
- FedRAMP cloud security baselines

Common misconfiguration categories:
- Storage exposure (public buckets, missing encryption)
- Network exposure (overly permissive security groups, missing VPC endpoints)
- Identity weaknesses (missing MFA, old keys, overly broad roles)
- Logging gaps (disabled trails, missing flow logs)
- Encryption gaps (default keys when CMK required, unencrypted volumes)
- Compute weaknesses (default VPC, IMDSv1, unpatched AMIs)
- Database exposure (public access, weak auth, missing backups)

Attacker abuse patterns:
- Public S3 bucket → data exfiltration
- IMDS abuse → credential theft → lateral movement
- Over-privileged IAM roles → privilege escalation
- Disabled CloudTrail → attack obfuscation
- Default VPC + public IP → direct attack surface
- Cross-account trust without external ID → cross-tenant compromise

Cloud-specific considerations:
- AWS: assume-role chains, SCPs, organizations boundaries
- Azure: management group inheritance, Conditional Access scopes
- GCP: project hierarchies, organization policies, IAM bindings
- Multi-cloud: identity federation, data movement boundaries

DECISION HEURISTICS
===================

H1: Severity is contextual.
    A public S3 bucket in marketing-assets is not the same as
    a public bucket in customer-data. Always check customer_context.md
    for asset criticality before scoring severity.

H2: Always check for customer exceptions before flagging.
    Customer's user.md contains known-good patterns and intentional
    exceptions. Do not flag these as findings even if they match
    detection rules.

H3: Group findings by root cause.
    One alert per misconfiguration pattern, not per affected resource.
    If 50 EC2 instances all lack IMDSv2 enforcement, that is one finding
    with 50 affected assets, not 50 findings.

H4: Provide business impact reasoning, not just technical detail.
    "S3 bucket has public ACL" is technical.
    "Customer data may be accessible to anonymous internet users,
     creating GDPR exposure and reputational risk" is business impact.

H5: When uncertain about severity, lean conservative.
    Lower severity, recommend rather than autonomous.
    Better to under-prioritize than over-alert.

H6: Production-versus-non-production matters enormously.
    Same misconfiguration in dev versus prod is different severity.
    Use customer_context.md asset_criticality_map.

H7: Regulated data drives severity.
    Healthcare data triggers HIPAA-specific severity escalation.
    Payment data triggers PCI escalation.
    Regulated data inventory comes from Data Security Agent.

H8: Attack path implications elevate severity.
    A finding that enables a multi-step attack chain to crown jewels
    is more severe than the same finding in isolation.
    Query knowledge graph for attack path implications.

STAGES (Prompt Chaining pattern)
================================

Stage 1: SCAN
  Determine appropriate scanner invocation based on task scope:
    - For full scans: Prowler with all check categories
    - For targeted scans: Prowler with specific check_categories
    - For rapid checks: Steampipe SQL queries
    - For known-issue investigations: AWS Config / Azure Policy / GCP SCC queries
  
  Choose between primary (Prowler) and backup (ScoutSuite) based on:
    - Primary unavailable
    - Primary timeout patterns
    - Specific check coverage gaps
  
  Execute scan with budget enforcement:
    - Track cloud API call count
    - Track wall clock time
    - Stop and return partial if approaching budget

Stage 2: ENRICH
  For each raw finding, query asset context from graph:
    - Asset metadata (criticality, environment, owner)
    - Compliance scope (which frameworks apply)
    - Related findings (graph relationships)
  
  Query customer context:
    - Asset criticality from customer_context.md
    - Exceptions from user.md
    - Compliance focus areas
  
  Filter exceptions:
    - If finding matches user.md exception, mark as filtered with reason
    - Filtered findings still recorded in audit but not in output

Stage 3: ASSESS SEVERITY
  Apply severity heuristics:
    - Base severity from rule definition
    - Asset criticality multiplier
    - Compliance impact multiplier
    - Attack path multiplier
    - Production status multiplier
  
  Calculate composite severity:
    info | low | medium | high | critical
  
  Assign confidence:
    - High confidence: rule clearly matches, context clear
    - Medium confidence: rule matches but context unclear
    - Low confidence: rule partially matches or evidence weak

Stage 4: BUSINESS IMPACT REASONING
  For each finding above filter threshold, generate business impact:
    - Why does this matter for THIS customer?
    - What's the worst-case outcome?
    - What's the realistic outcome?
    - What's the regulatory/compliance impact?
    - What's the business operational impact?
  
  Output: 200-500 character business impact reasoning per finding.

Stage 5: REMEDIATION RECOMMENDATION
  Classify the appropriate remediation approach:
    - Cloud Custodian policy (most cloud config issues)
    - Terraform diff (for IaC-managed infrastructure)
    - IaC fix PR (for source-of-truth IaC)
    - CloudFormation change set (CFN-managed infrastructure)
    - Manual runbook (complex multi-step changes)
    - Configuration via console (one-off changes)
  
  Provide remediation hint:
    - What change is needed (high-level)
    - What blast radius (which resources affected)
    - What prerequisites (what must be in place first)
    - What rollback strategy
  
  Pass to Remediation Agent for actual draft generation.

Stage 6: COMPLIANCE MAPPING
  For each finding, identify applicable compliance controls:
    - CIS Benchmark control IDs
    - NIST 800-53 control IDs
    - PCI-DSS requirements
    - HIPAA Security Rule sections
    - SOC 2 Trust Services Criteria
    - ISO 27001 controls
    - Vertical-specific (HITRUST, NERC-CIP, FFIEC)
  
  Pass compliance mapping to Compliance Agent.

Stage 7: HANDOFF
  Construct structured output:
    - findings array with all required fields
    - aggregated_severity_summary
    - compliance_impact_summary
    - recommended_actions
    - confidence_summary
  
  Write to workspace outputs/.
  Update reasoning_trace.md with synthesis.
  Return to supervisor.

FAILURE TAXONOMY
================

F1: Cloud API rate limit hit
    Recovery: exponential backoff with jitter, retry up to 3 times
    Escalation: if persistent, log Meta-Harness trigger, return partial
    Customer impact: scan may be incomplete, flagged in output

F2: Scanner returns malformed output
    Recovery: log raw output, fall back to backup scanner
    Escalation: if backup also fails, escalate to Investigation Agent
    Customer impact: degraded scan, flagged in output

F3: Finding cannot be enriched (asset not in graph)
    Recovery: query asset directly from cloud API for context
    Escalation: if cloud API also lacks data, mark finding low confidence
    Note: trigger graph refresh task for asset

F4: Severity assessment ambiguous
    Recovery: do not guess; mark medium confidence with explicit reasoning
    Escalation: if pattern recurs, escalate to Investigation Agent
    Customer impact: customer sees uncertainty flagged

F5: Customer exception list malformed (user.md errors)
    Recovery: log error, treat as no exceptions until customer fixes
    Escalation: notify customer of user.md syntax error
    Customer impact: may see findings they intended to suppress

F6: Compliance framework not loaded
    Recovery: skip compliance mapping for that framework, flag
    Escalation: log to Compliance Agent for framework loading
    Customer impact: compliance impact may be incomplete

F7: Budget exceeded mid-scan
    Recovery: complete current asset, return findings collected so far
    Escalation: log budget pattern; if recurring, propose budget increase
    Customer impact: scan flagged as incomplete with details

CONTRACTS YOU REQUIRE
=====================

Pre-conditions for invocation:

- Customer cloud credentials available in customer_context.md
- Cloud account scope defined in task
- Asset inventory in graph less than 24 hours old (else trigger refresh)
- Prowler scanner binary version >= 5.0
- Customer exceptions (user.md) parsable
- Compliance framework definitions loaded for relevant frameworks

If any pre-condition fails, escalate to supervisor with specific reason.

WHAT YOU NEVER DO
=================

NEVER execute remediations directly. Handoff to Remediation Agent.
NEVER make decisions outside posture domain. Delegate to peer specialists.
NEVER skip the customer exception check.
NEVER alert on findings without business context.
NEVER trust raw scanner output without enrichment.
NEVER write to knowledge graph directly.
NEVER modify customer cloud resources.
NEVER guess at severity when context is missing.
NEVER mark findings high confidence without strong evidence.

CUSTOMER COMMUNICATION STYLE
============================

Findings are written for security analysts and operations engineers.
Avoid:
- Marketing language
- Hand-wavy descriptions
- Vendor-specific jargon without explanation

Include:
- Specific affected resources (with identifiers)
- Specific misconfiguration (with technical detail)
- Specific business impact (in operational terms)
- Specific recommendation (handoff to Remediation Agent)
- Specific compliance impact (control IDs)

Tone:
- Direct
- Factual
- Helpful (toward solution, not toward alarm)

PEER SPECIALIST HANDOFFS
========================

To Identity Agent:
  When finding involves IAM beyond basic patterns:
  - Cross-account trust analysis
  - Effective permissions calculation
  - Privilege escalation path detection
  Pass: principal_arns, role_arns, policy_documents

To Vulnerability Agent:
  When finding involves vulnerable component:
  - Outdated AMI with CVEs
  - Container image vulnerabilities
  - Vulnerable runtime versions
  Pass: asset_id, vulnerability_indicator

To Data Security Agent:
  When finding involves data exposure:
  - Storage with sensitive data
  - Database with PII/PHI/PCI
  Pass: storage_id, exposure_type

To Runtime Threat Agent:
  When finding suggests active threat:
  - Disabled logging during attack window
  - Unauthorized configuration changes
  Pass: time_range, asset_ids

To Compliance Agent:
  Always for compliance mapping enrichment.
  Pass: finding_ids, applicable_frameworks

To Remediation Agent:
  Always for findings requiring action.
  Pass: finding_id, remediation_recommendation, target_tier

To Investigation Agent:
  When finding suggests broader incident:
  - Pattern of similar findings appearing rapidly
  - Findings with attack path implications
  - Findings disputed by multiple data sources
  Pass: finding_ids, hypothesis, urgency
```

The full production NLAH includes worked examples for each stage, detailed failure recovery procedures, agent-specific routing logic, customer-tuning patterns, and case studies of complex multi-cloud findings.

### 5.7 Execution contract template

The Cloud Posture Agent contract:

```yaml
contract_version: 1.0
contract_id: <UUID>
identity:
  source_agent: <delegating agent, usually supervisor>
  target_agent: cloud_posture
  delegation_chain: [supervisor:abc, cloud_posture:def]
  customer_id: <UUID>
  trace_id: <UUID>

task:
  type: scan_findings | assess_finding | enrich_finding | targeted_check
  scope:
    cloud_provider: aws | azure | gcp | kubernetes | multicloud
    account_id: <id>  # for AWS
    subscription_id: <id>  # for Azure
    project_id: <id>  # for GCP
    cluster_id: <id>  # for Kubernetes
    regions: [<list>] | all
    check_categories: [<list>] | all
    scope_filter: <optional asset filter>
    incremental: bool  # true for delta-only scans
    last_scan_timestamp: <ISO 8601>  # for incremental scans
  priority: emergency | urgent | normal | background

required_outputs:
  findings:
    type: array
    item_schema: PostureFinding
    constraints:
      max_count: 1000
      grouping: by_root_cause
  scan_summary:
    type: object
    fields:
      total_assets_scanned: int
      total_findings: int
      findings_by_severity: object
      scan_duration_seconds: int
      partial_scan: bool
      partial_reason: text (if partial)
  compliance_impact_summary:
    type: object
    fields:
      frameworks_affected: array
      controls_violated: array
  recommended_actions:
    type: array
    item_schema: RemediationRecommendation

PostureFinding schema:
  finding_id: UUID
  rule_id: string  # references detection rule catalog
  category: string  # e.g., "S3-PUBLIC-ACL", "EC2-IMDSV1"
  severity: enum [info, low, medium, high, critical]
  affected_assets:
    - asset_id: string
      asset_type: string
      asset_arn_or_id: string
      criticality: enum [low, medium, high, critical]
  business_impact: text (200-500 chars)
  remediation_hint:
    type: enum [cloud_custodian, terraform_diff, iac_pr, cfn_change, runbook, console]
    summary: text
    blast_radius: enum [single_resource, multi_resource, account_wide, multi_account]
    rollback_strategy: text
  compliance_impact:
    - framework_id: string
      control_id: string
      severity_in_framework: enum
  confidence: float [0, 1]
  evidence:
    - evidence_type: string
      source: string  # which scanner, which API
      data: object
  related_findings: array of finding_ids
  attack_path_indicator: bool
  customer_exception_status: enum [no_exception, exception_applied, exception_overridden]
  first_seen: ISO 8601
  last_seen: ISO 8601

RemediationRecommendation schema:
  finding_id: UUID
  remediation_type: enum
  proposed_target_tier: enum [tier_1, tier_2, tier_3]
  estimated_blast_radius: object
  estimated_rollback_time_seconds: int

budget:
  max_llm_calls: 12
  max_tokens: 16000
  max_wall_clock_seconds: 120
  max_cloud_api_calls: 500
  max_workspace_mb: 100

permitted_tools:
  - run_prowler_scan
  - run_steampipe_query
  - run_scoutsuite_scan
  - query_aws_config
  - query_azure_policy
  - query_gcp_scc
  - query_aws_security_hub
  - aws_describe_resource
  - azure_describe_resource
  - gcp_describe_resource
  - query_posture_graph
  - recall_similar_findings
  - check_customer_exception
  - get_customer_baseline
  - get_asset_criticality
  - request_compliance_mapping
  - request_remediation_draft
  - escalate_to_supervisor
  - record_audit

forbidden_tools:
  - any execute_* tool
  - any tools belonging to peer specialists
  - any tools that modify cloud resources

completion_condition: |
  All findings have populated severity, business_impact, remediation_hint, confidence
  AND each finding has compliance_impact (or empty if no compliance impact)
  AND scan_summary populated
  AND confidence >= 0.6 for each finding OR escalate_with_reason flagged

escalation_rules:
  on_budget_exceeded: return_partial_with_flag
  on_tool_failure: retry_once_then_use_backup_then_escalate
  on_low_confidence: continue_with_low_confidence_flagged
  on_severity_ambiguous: escalate_to_investigation_agent

workspace: /workspaces/<customer_id>/<contract_id>/cloud_posture/
```

### 5.8 File-backed state schema

```
/workspaces/<customer_id>/<contract_id>/cloud_posture/
  task.yaml                       # the contract
  scan_inputs.json                # what we're scanning, parameters
  scan_outputs/
    prowler_raw.json              # raw Prowler output
    steampipe_results.json        # Steampipe SQL query results
    cloud_api_calls.jsonl         # every cloud API call made
    enrichment.json               # asset context lookups
  findings/
    <finding_id>.yaml             # one file per finding
    finding_index.json            # finding catalog with metadata
  compliance_mappings/
    <finding_id>_mappings.json    # compliance impact per finding
  reasoning_trace.md              # raw reasoning log
  errors/                         # any errors encountered
  audit_events.jsonl              # audit events generated
  output.yaml                     # final structured output

/persistent/<customer_id>/cloud_posture/
  customer_baseline.yaml          # what's normal for this customer
  exceptions.yaml                 # known-good patterns (user.md)
  finding_history.jsonl           # episodic memory (last 90 days)
  remediation_effectiveness.json  # procedural memory
  recurring_patterns.yaml         # patterns seen repeatedly
  asset_criticality_overrides.yaml # customer overrides of default criticality
  custom_rules.yaml               # customer-defined detection rules
```

### 5.9 Self-evolution criteria

Cloud Posture Agent harness rewrite triggered when:

**False positive rate too high:**
- FP rate > 15% over rolling 500 findings
- Customer marks findings as "not applicable" repeatedly for similar patterns

**Severity assessment disputed:**
- Compliance Agent cross-check disputes severity > 10%
- Customer overrides severity > 15%

**Coverage gaps detected:**
- Findings missed (validated by spot checks or after-the-fact discovery)
- New cloud services or features not yet covered

**Performance degradation:**
- Time-to-completion exceeds budget on > 20% of invocations
- Scan failures due to API rate limits > 5%

**Confidence quality issues:**
- Confidence scores cluster < 0.7 (suggests model uncertain about domain)
- High-confidence findings disputed > 5%

When triggered, Meta-Harness Agent:
1. Reads Cloud Posture Agent's reasoning traces from triggered period
2. Identifies failure patterns (e.g., "agent consistently misses business context for K8s findings")
3. Proposes refinement to NLAH (e.g., "add explicit K8s asset criticality lookup to Stage 2")
4. Tests against eval suite (curated set of 500 historical findings with ground truth)
5. Validates no regression on existing tests
6. Cross-model tests (Sonnet + Haiku at minimum)
7. Accepts and signs new NLAH version
8. Deploys via canary rollout

### 5.10 Pattern usage declaration

**Primary patterns:**
- **Prompt chaining** — Stage 1 (scan) → Stage 2 (enrich) → Stage 3 (assess) → Stage 4 (impact) → Stage 5 (remediate) → Stage 6 (compliance) → Stage 7 (handoff)
- **Evaluator-optimizer loop** — self-evolution via Meta-Harness reading raw traces

**Secondary patterns:**
- **Routing** — when multi-domain finding, route enrichment to peer specialist (Identity for IAM, Vulnerability for CVEs)

**Not used:**
- **Parallelization** — internal stages are sequential by design
- **Orchestrator-workers** — this agent IS a worker, not an orchestrator

### 5.11 Tools

The Cloud Posture Agent has 19 tools, within the sweet spot for tool selection accuracy:

**Detection tools (8):**

`run_prowler_scan(account_id, regions[], check_types[], depth)` — Execute Prowler against specified scope. Returns structured findings.

`run_steampipe_query(query, mod, account_id)` — Execute SQL query against cloud state via Steampipe. Returns query results.

`run_scoutsuite_scan(account_id, regions)` — Run ScoutSuite as backup multi-cloud scanner. Returns ScoutSuite-format findings.

`query_aws_config(account_id, resource_type, filters)` — Query AWS Config rules for compliance state. Returns Config rule evaluations.

`query_azure_policy(subscription, definitions)` — Query Azure Policy compliance state. Returns policy compliance results.

`query_gcp_scc(project, finding_categories)` — Query Google Cloud Security Command Center. Returns SCC findings.

`query_aws_security_hub(account_id, finding_filters)` — Query AWS Security Hub for findings. Returns hub findings.

`aws_describe_resource(service, resource_type, resource_id)` — Direct AWS API call to describe specific resource. Returns resource details.

**Cross-cloud equivalents (2):**

`azure_describe_resource(subscription, resource_id)` — Direct Azure API for resource description.

`gcp_describe_resource(project, resource_id)` — Direct GCP API for resource description.

**Graph and memory tools (5):**

`query_posture_graph(cypher_query)` — Query posture-specific subgraph in Neo4j.

`recall_similar_findings(finding_signature)` — Episodic memory lookup for similar past findings.

`check_customer_exception(asset_id, finding_type)` — Check user.md for matching exception.

`get_customer_baseline(asset_type)` — Get semantic memory baseline for asset type.

`get_asset_criticality(asset_id)` — Get customer-defined or default criticality.

**Coordination tools (4):**

`request_compliance_mapping(finding_id)` — Request Compliance Agent map this finding.

`request_remediation_draft(finding_id, severity)` — Request Remediation Agent draft fix.

`escalate_to_supervisor(finding_id, reason)` — Flag for supervisor attention.

`record_audit(action, context)` — Standard audit logging.

Each tool's full specification is in the Tool Specification document.

### 5.12 Memory architecture

**Episodic memory:**
Last 30-90 days of posture findings per customer. Indexed by asset, finding type, severity, status. Stored in TimescaleDB. Used for: "have I seen this finding before? Is this recurring?"

**Procedural memory:**
- Effectiveness of suggested remediations (which suggestions humans approved)
- False positive patterns by customer
- Tuning thresholds learned over time
- Stored in PostgreSQL.

**Semantic memory (read from shared):**
- Customer asset inventory
- Customer business context (production vs dev mappings)
- Customer compliance requirements
- Read-only for this agent.

**Knowledge graph (read-only):**
- MisconfigurationPattern nodes
- ComplianceControl nodes
- Active TechniqueNodes (what attackers are doing now)
- Read-only.

### 5.13 Inter-agent coordination

**Calls (via supervisor):**
- Compliance Agent — for framework mapping enrichment
- Remediation Agent — for fix drafting
- Identity Agent — when finding involves IAM
- Vulnerability Agent — when finding involves CVEs
- Data Security Agent — when finding involves data exposure
- Investigation Agent — when finding suggests broader incident

**Called by:**
- Supervisor — primary delegation
- Investigation Agent — when investigating an incident with posture component
- Curiosity Agent — when proactively checking for posture drift

### 5.14 Wiz capability mapping

Maps to Wiz's CSPM module. Wiz's CSPM coverage:
- 1,000+ AWS checks
- 800+ Azure checks
- 700+ GCP checks
- 500+ Kubernetes checks
- ~150 OCI checks
- ~100 Alibaba checks

Our Cloud Posture Agent at Phase 1 production:
- 1,200+ AWS checks (slight superset due to different coverage prioritization)
- 1,000+ Azure checks
- 800+ GCP checks
- 600+ Kubernetes checks
- 200+ OCI checks
- 200+ Alibaba checks

Coverage parity: approximately 90% of Wiz CSPM at Phase 1 launch, growing through detection rule additions.

### 5.15 Coverage progression

| Phase | Coverage | Notes |
|---|---|---|
| 1 | 90% Wiz CSPM | Production launch with comprehensive coverage |
| 2 | 92% | Refinement and additional newer cloud services |
| 3 | 95% | + advanced toxic combinations |
| 4 | 97% | Mature with vertical-specific rule packs |

(Document continues with Vulnerability Agent, Identity Agent, and remaining eleven agents in same depth. Due to length, full document is part 1 of 2; part 2 follows in subsequent file.)

---

## 6. AGENT 2 — VULNERABILITY AGENT

### 6.1 Purpose

The Vulnerability Agent owns vulnerability management across cloud workloads, container images, infrastructure-as-code, software dependencies, and secrets. It detects known vulnerabilities (CVEs), generates Software Bills of Materials (SBOMs), and prioritizes by actual exploitability for the specific customer environment rather than just CVSS scores.

This agent is the second-most frequently invoked agent in the platform, running every four to six hours per customer environment depending on configuration. It is the strongest agent on Day One in terms of Wiz capability parity (approximately 95%) because vulnerability detection is among the most commoditized security capabilities.

### 6.2 Hire test analog

Vulnerability manager or Software Composition Analysis (SCA) engineer. Five-plus years of experience managing CVE remediation programs. Understands CVSS, EPSS, KEV, and exploitation context. Knows when a "critical" CVE is actually low-priority for the specific environment and vice versa. Has experience with CI/CD integration and shift-left security.

### 6.3 Detection scope

#### 6.3.1 Operating system vulnerabilities

**Linux distributions:**
- RHEL/CentOS/Rocky/AlmaLinux (current and EOL versions)
- Ubuntu (LTS and non-LTS)
- Debian (current and oldstable)
- Amazon Linux (1 and 2023)
- SUSE Enterprise Linux
- Alpine Linux
- Photon OS
- BottleRocket
- CoreOS

**Windows:**
- Windows Server 2019, 2022, 2025
- Windows 10, 11 (where running as workloads)
- Windows Subsystem for Linux

**Detection categories:**
- Kernel CVEs
- System library CVEs (glibc, openssl, etc.)
- Package CVEs across distributions
- End-of-life OS versions
- Security patch lag
- Configuration drift from hardened images

#### 6.3.2 Application dependency vulnerabilities

**Package ecosystems:**
- npm (Node.js)
- pip (Python)
- Maven (Java)
- NuGet (.NET)
- Go modules
- RubyGems
- Cargo (Rust)
- Composer (PHP)
- Pub (Dart/Flutter)
- Conan (C/C++)
- Hex (Elixir)
- Mix (Erlang)

**Detection categories:**
- Direct dependency CVEs
- Transitive dependency CVEs
- Vulnerable application frameworks (Express, Django, Spring, Rails, Laravel, etc.)
- Database engine CVEs (PostgreSQL, MySQL, MongoDB, Redis, etc.)
- Web server CVEs (nginx, Apache, IIS)
- Application server CVEs (Tomcat, JBoss, Jetty)
- Runtime version vulnerabilities (Java, Python, Node.js, Go, Ruby versions)

#### 6.3.3 Container image vulnerabilities

**Image sources scanned:**
- AWS ECR (public and private)
- Azure Container Registry (ACR)
- Google Artifact Registry / GCR
- Docker Hub
- Quay.io
- Harbor
- GitHub Container Registry
- GitLab Container Registry
- JFrog Artifactory
- Self-hosted registries

**Detection categories:**
- OS package vulnerabilities in image layers
- Application dependency vulnerabilities
- Vulnerable base images
- Image layer scanning depth (all layers, not just top)
- Multi-stage build security
- Distroless image recommendations
- Image signing verification (Cosign, Notation)
- SBOM generation per image
- License compliance per image
- Image age and freshness

#### 6.3.4 Serverless function vulnerabilities

**Coverage:**
- AWS Lambda runtime versions
- AWS Lambda layer vulnerabilities
- Azure Functions runtime versions
- GCP Cloud Functions runtime versions
- Lambda function package dependencies
- Function permission contributions to vuln impact

#### 6.3.5 Infrastructure-as-Code vulnerabilities

**IaC formats covered:**
- Terraform (HCL across all major providers)
- CloudFormation (YAML/JSON)
- Kubernetes manifests (YAML)
- Helm charts
- ARM templates (Azure)
- Pulumi (TypeScript, Python, Go)
- AWS CDK (TypeScript, Python, Java)
- Serverless Framework
- Ansible playbooks (limited)
- Chef cookbooks (limited)
- Puppet manifests (limited)

**Detection categories:**
- Misconfigurations declared in IaC (overlap with CSPM)
- Hardcoded secrets in IaC
- Hardcoded credentials in module variables
- Insecure module sources (untrusted Terraform Registry sources)
- Missing required security configurations
- Drift between IaC and production state

#### 6.3.6 Supply chain vulnerabilities

**Detection categories:**
- Suspicious package patterns (typosquatting, dependency confusion)
- Malicious package detection (known bad packages)
- License compliance issues (GPL contamination, restrictive licenses)
- Package signing verification gaps
- SBOM completeness assessment
- Open-source license attribution gaps
- Package provenance verification

#### 6.3.7 Secrets in code and infrastructure

**Detection categories:**

(See Secrets Detection in section 7.1.6 of PRD. The Vulnerability Agent owns secrets detection with these specific patterns:)

**Cloud credentials:**
- AWS access keys (`AKIA[0-9A-Z]{16}`)
- AWS secret keys (entropy + length patterns)
- AWS session tokens
- Azure service principal credentials
- Azure SAS tokens
- GCP service account keys (JSON format)
- Cloud provider session tokens

**API keys and tokens:**
- 800+ service-specific API key patterns (Stripe, Twilio, SendGrid, Slack, GitHub, etc.)
- OAuth access and refresh tokens
- JWT tokens with sensitive claims
- Webhook secrets
- Internal service API keys

**Authentication credentials:**
- Database connection strings with embedded credentials
- LDAP/AD bind credentials
- SSH keys (RSA, ED25519, DSA, ECDSA)
- TLS private keys
- API keys from internal services

**Cryptographic material:**
- Private keys (PEM, PKCS#8, PKCS#12 formats)
- HMAC keys
- Encryption keys
- Signing keys
- PGP private keys

**Generic patterns:**
- High-entropy strings in code
- Suspicious base64-encoded values
- Patterns matching credential formats with insufficient context

**Validation:**
For detected secrets, the agent attempts validation where possible:
- AWS keys: STS GetCallerIdentity (read-only test)
- Azure tokens: limited scope validation against Microsoft Graph
- API keys: provider-specific validation endpoints
- Database connections: connection test (read-only, may be skipped if connection requires VPN)

Validation produces three states (per PRD specification): valid, invalid, unvalidated.

#### 6.3.8 Exploit prioritization

The Vulnerability Agent does not just detect — it prioritizes based on actual exploitability:

**Prioritization signals:**
- CVSS v3 base score
- EPSS (Exploit Prediction Scoring System) score
- CISA KEV (Known Exploited Vulnerabilities) status
- Public exploit availability (Exploit-DB, Metasploit modules)
- Active exploitation in customer's industry vertical (from Threat Intel Agent)
- Asset criticality (from customer context)
- Network exposure (is vulnerable component reachable?)
- Whether vulnerable component is actually executed at runtime (correlation with Runtime Threat Agent)
- Patch availability and stability

**Composite priority score:**
Combines all signals into a single priority ranking that often differs significantly from CVSS-only ranking.

### 6.4 Prevention level

The Vulnerability Agent is the most preventive agent in the platform because it operates **shift-left**:

**Pre-commit (with developer integration):**
- Pre-commit hooks running Trufflehog/Gitleaks
- Developer machine secret detection before commit
- Local Checkov runs for IaC

**CI/CD pre-deployment:**
- Pull request scanning integration
- Pipeline-stage scanning
- Build failure for critical issues (configurable)
- SBOM generation in pipeline

**Pre-deployment registry:**
- Container registry scanning before image push
- Image signing verification before deployment
- Block deployment of images with critical CVEs (if customer enables)

**Runtime detection:**
- Continuous CVE matching against running workloads
- Detection of new CVEs against existing fleet (when CVE published, identify affected assets)

**Patch deployment guidance:**
- Patch deployment runbooks (handoff to Remediation Agent)
- Phased patch rollout recommendations
- Rollback strategies if patches cause issues

### 6.5 Resolution capability

**Findings include structured remediation hints:**

For each vulnerability:
- CVE details, CVSS, EPSS, KEV status
- Affected packages and versions
- Fix availability (patched version, workaround)
- Suggested remediation type (handoff to Remediation Agent)
- Patch deployment urgency based on exploitability
- Estimated patch impact

For IaC issues:
- Specific code fix (handoff to Remediation Agent for PR generation)
- Equivalent secure pattern
- Reference to fixed examples

For container images:
- Recommended base image upgrade
- Patched image version
- Rebuild guidance

For VMs:
- Specific package patches via OS package manager
- Reboot requirements
- Patch group assignment recommendations

For secrets:
- Rotate vs revoke recommendation
- Validation status
- Estimated blast radius if compromised
- Specific rotation procedure (handoff to Remediation Agent for Tier 1 if authorized)

### 6.6 Three-layer description

#### 6.6.1 Backend infrastructure

**Detection scanners:**
- Trivy (primary): containers, VMs, IaC, secrets, K8s manifests
- Grype (backup container scanner)
- Syft (SBOM generator)
- Checkov (primary IaC scanner)
- KICS (backup IaC scanner)
- tfsec (Terraform-specific deep scanning)
- terrascan (multi-IaC alternative)
- Trufflehog (primary secret scanner with 800+ detectors)
- Gitleaks (backup secret scanner)
- detect-secrets (Yelp, for pre-commit)
- OWASP Dependency-Check (SCA validation)
- OSV-Scanner (OSV database integration)
- Dependency-Track (continuous SCA monitoring)

**Database clients:**
- NVD API client
- OSV API client
- CISA KEV catalog (cached locally)
- EPSS API client
- GitHub Advisory Database client
- npm Advisory Database
- PyPI vulnerability data
- RubyGems advisory database

**Cloud integration clients:**
- ECR, ACR, GCR, Artifact Registry clients
- Lambda inventory clients
- VM inventory across clouds
- Container orchestration clients

**Secret validation infrastructure:**
- AWS STS validation
- Azure validation endpoints
- GCP validation
- Custom validation per service

#### 6.6.2 Charter participation

Standard charter rules with these specifics:

**Privileges:**
- High-volume parallel scanning (within budget)
- Direct write access to vulnerability findings store
- Ability to trigger CVE feed refresh for critical CVE publications
- May invoke parallel scans across multiple targets

**Restrictions:**
- Cannot execute patches (handoff to Remediation Agent)
- Cannot block production deployments directly (advisory only; CI/CD integration handles enforcement)
- Cannot modify customer source code
- Must respect cloud API rate limits

#### 6.6.3 NLAH

The Vulnerability Agent's NLAH structure (full version approximately 1,000-1,400 lines):

```
ROLE
====
Vulnerability management specialist. Detect known vulnerabilities,
generate SBOMs, and prioritize by actual exploitability for THIS customer.
Operate across containers, VMs, serverless, IaC, supply chain, and secrets.

EXPERTISE
=========

CVE landscape:
- CVSS v3 scoring methodology and limitations
- EPSS scoring and predictive value
- CISA KEV catalog and exploitation patterns
- Exploit code availability databases
- Vulnerability research conferences and disclosure patterns

Software Composition Analysis:
- Direct vs transitive dependencies
- Dependency resolution algorithms per ecosystem
- Lock file interpretation
- License compatibility
- Supply chain attack patterns

IaC security patterns:
- Terraform best practices
- CloudFormation security patterns
- Kubernetes manifest security
- Helm chart security
- ARM template security

Secrets:
- Secret pattern recognition
- Validation methodologies per service
- Rotation procedures per credential type
- Blast radius assessment

Exploitation context:
- Active exploitation reports per CVE
- Threat actor preferences
- Exploitation difficulty assessment
- Industry-vertical targeting patterns

DECISION HEURISTICS
===================

H1: CVSS alone is insufficient.
    Always check KEV, EPSS, customer asset criticality.
    A CVSS 9.0 in dev environment is less critical than
    a CVSS 7.0 in production database.

H2: Active exploitation (KEV) elevates severity regardless of CVSS.
    A KEV-listed CVE is critical even if CVSS is medium.
    Adversaries are actively using it.

H3: Vulnerable code that's not actually executed is lower priority.
    Coordinate with Runtime Threat Agent to determine if
    vulnerable component is in active execution path.

H4: Validate detected secrets — invalid secrets are noise.
    Always attempt validation before high-priority alerting.
    Mark unvalidated as if valid (conservative).

H5: Group CVEs by affected component and fix availability.
    Don't generate 50 CVE alerts for the same vulnerable library
    affecting 50 services. One alert with affected scope.

H6: Patch availability matters.
    A critical CVE without a patch is different from one with
    a patch ready. Coordinate with patching cadence.

H7: Customer's patching capability shapes urgency.
    Mature customers patch quickly. Slower customers need
    more lead time. Calibrate alert urgency accordingly.

H8: Supply chain risk is asymmetric.
    A compromised package in production code is catastrophic.
    Lean toward over-flagging supply chain anomalies.

STAGES (Prompt Chaining + Parallelization)
==========================================

Stage 1: ENUMERATE
  List all scan targets in scope:
    - Container images (from registries)
    - Running containers (from runtime)
    - VMs (from cloud inventory)
    - Serverless functions
    - IaC files (from source control)
    - Repositories (for secret scanning)
  
  Build target list with metadata.

Stage 2: SCAN (Parallel Execution)
  For each target, dispatch appropriate scanner:
    - Containers: Trivy primary, Grype backup
    - VMs: Trivy primary, OSQuery for runtime correlation
    - Serverless: Trivy on package, function metadata
    - IaC: Checkov primary, KICS backup
    - Secrets: Trufflehog with validation, Gitleaks backup
  
  Execute scans in parallel up to concurrency limit (default: 10 concurrent).
  Track scan progress and timeout per scan.
  
  Stop conditions:
    - All scans complete
    - Budget exhausted (return partial)
    - Critical errors (escalate)

Stage 3: ENRICH
  For each detected CVE:
    - Lookup KEV status (CISA Known Exploited Vulnerabilities)
    - Lookup EPSS score (Exploit Prediction Scoring System)
    - Lookup public exploit availability
    - Query GitHub Advisory for additional context
    - Query OSV for OSS-specific advisory
  
  For each detected secret:
    - Run validation if applicable
    - Determine secret type and blast radius
    - Check if secret matches known revoked patterns

Stage 4: ASSESS EXPLOITABILITY
  For each finding, determine actual exploitability:
    - Is the vulnerable component reachable from internet?
    - Is the vulnerable component actually executed?
      (Coordinate with Runtime Threat Agent for execution context)
    - Is there a working public exploit?
    - Is this CVE actively exploited per CISA KEV?
    - Is the vulnerable component in customer's critical assets?
  
  Compute composite exploitability score.

Stage 5: PRIORITIZE
  Order findings by:
    composite_priority = exploitability_score
                       × asset_criticality_multiplier
                       × business_impact_multiplier
                       × patching_urgency
  
  Group findings by:
    - Common root cause (same vulnerable library affecting multiple targets)
    - Common fix (single patch fixes multiple findings)
    - Common deployment unit (findings within same service)

Stage 6: RECOMMEND
  For each finding or finding group, recommend:
    - Patch availability (specific patched version)
    - Workaround if patch unavailable
    - Configuration mitigation if applicable
    - Compensating controls
    - Patch deployment approach (rolling, canary, immediate)
    - Rollback strategy if patch causes issues

Stage 7: HANDOFF
  Construct structured output.
  Pass remediation recommendations to Remediation Agent.
  Pass compliance impact to Compliance Agent.
  Return to supervisor.

FAILURE TAXONOMY
================

F1: NVD/OSV/KEV API timeout
    Recovery: use cached data (max 24 hours old)
    Mark confidence lower if cache > 6 hours
    Escalation: if cache > 24 hours, log for ops attention

F2: Image too large to scan in budget
    Recovery: scan top layers only with explicit incomplete flag
    Escalation: log Meta-Harness trigger for budget review

F3: Cannot determine if CVE applies (configuration-dependent)
    Recovery: mark as "potentially affected" with explicit reasoning
    Note: lower confidence, recommend manual investigation

F4: Secret validation fails (network/auth issues)
    Recovery: mark as "unvalidated", treat as if valid (conservative)
    Note: log validation failure pattern

F5: Container registry credentials expired
    Recovery: log specific registry, escalate immediately
    Customer impact: scans will be incomplete until credentials refreshed

F6: IaC scanner fails on syntax
    Recovery: log syntax error, attempt backup scanner
    Note: customer's IaC may have issues separate from security

F7: Runtime correlation unavailable (Runtime Threat Agent down)
    Recovery: proceed with conservative assumption (component is executing)
    Note: severity may be higher than actual until correlation possible

CONTRACTS YOU REQUIRE
=====================

- Container images accessible from edge agent (registry credentials)
- Cloud workload inventory in graph
- NVD API key (for higher rate limit, customer-provided or vendor)
- CISA KEV catalog refreshed within 24 hours
- Customer's patching cadence in customer_context.md
- Asset criticality map current

WHAT YOU NEVER DO
=================

NEVER execute patches directly. Handoff to Remediation Agent.
NEVER block production deployments. Advisory only.
NEVER trust raw CVSS without exploitability context.
NEVER skip secret validation when validation is possible.
NEVER guess at exploitability — when uncertain, mark uncertain.
NEVER generate findings for confirmed-invalid secrets.
NEVER scan customer source code without authorization.

PEER COORDINATION
=================

To Threat Intel Agent:
  When CVE matches active campaign:
    Pass CVE ID, request threat actor mapping
  When new CVE published with high CVSS:
    Request exploitation context

To Cloud Posture Agent:
  When patch requires configuration change:
    Pass configuration recommendation

To Runtime Threat Agent:
  Always for active execution context:
    Pass component identifier, request execution status

To Identity Agent:
  When secret rotation needed:
    Pass secret type, principal context

To Remediation Agent:
  Always for actionable findings:
    Pass finding, remediation_recommendation, target_tier

To Compliance Agent:
  Always for compliance mapping:
    Pass finding_id, applicable_frameworks
```

### 6.7 Execution contract template

```yaml
contract_version: 1.0
contract_id: <UUID>
identity:
  source_agent: <delegating agent>
  target_agent: vulnerability
  customer_id: <UUID>
  trace_id: <UUID>

task:
  type: scan_targets | assess_cve | validate_secret | scan_iac | scan_supply_chain
  scope:
    target_type: container_image | vm | function | iac_file | repo | sbom
    targets: array of target identifiers
    scan_depth: shallow | deep
    incremental: bool
    last_scan_timestamp: ISO 8601
  priority: emergency | urgent | normal | background

required_outputs:
  vulnerabilities:
    type: array
    item_schema: VulnerabilityFinding
  secrets:
    type: array
    item_schema: SecretFinding
  iac_findings:
    type: array
    item_schema: IaCFinding
  supply_chain_findings:
    type: array
    item_schema: SupplyChainFinding
  sbom:
    type: object
    schema: SPDX or CycloneDX
  scan_summary:
    type: object

VulnerabilityFinding schema:
  cve_id: string
  affected_assets: array
  cvss_v3: float
  cvss_vector: string
  epss_score: float
  cisa_kev: bool
  exploit_available: bool
  exploit_difficulty: enum [trivial, easy, moderate, hard]
  active_exploitation: bool
  actual_severity: enum (composite priority)
  fix_available: bool
  fix_version: string | null
  workaround_available: bool
  remediation_recommendation: structured
  customer_patching_urgency: enum [immediate, high, medium, low, deferred]
  business_impact: text
  evidence: array
  confidence: float

SecretFinding schema:
  secret_type: enum
  location:
    file_path: string
    line_number: int | null
    container_layer: int | null
    repository: string | null
  validation_status: valid | invalid | unvalidated
  blast_radius: structured
  recommended_action: rotate | revoke | investigate | acknowledge
  business_impact: text
  confidence: float

(IaCFinding and SupplyChainFinding schemas similar structure)

budget:
  max_llm_calls: 15
  max_tokens: 24000
  max_wall_clock_seconds: 240
  max_external_api_calls: 1000
  max_concurrent_subtasks: 10
  max_workspace_mb: 500

permitted_tools:
  - run_trivy_scan
  - run_grype_scan
  - run_syft_sbom
  - run_checkov_scan
  - run_kics_scan
  - run_tfsec_scan
  - run_trufflehog_scan
  - run_gitleaks_scan
  - run_dependency_check
  - query_nvd
  - query_osv
  - query_cisa_kev
  - query_epss
  - query_github_advisory
  - validate_secret
  - list_container_images
  - list_vms
  - list_serverless_functions
  - get_lambda_layers
  - recall_vulnerability_history
  - check_patching_cadence
  - get_asset_criticality
  - query_runtime_execution_context
  - request_threat_actor_mapping
  - request_remediation_draft
  - notify_runtime_threat_agent
  - notify_compliance_agent
  - record_audit

completion_condition: |
  All targets scanned (or partial with explicit incomplete flag)
  AND all CVEs enriched with KEV/EPSS data (or noted as unavailable)
  AND all secrets have validation_status determined
  AND all findings have actual_severity computed
  AND remediation recommendations populated for actionable findings

workspace: /workspaces/<customer_id>/<contract_id>/vulnerability/
```

### 6.8 File-backed state schema

```
/workspaces/<customer_id>/<contract_id>/vulnerability/
  task.yaml
  scan_targets.json
  scans/
    <target_id>/
      trivy_raw.json
      grype_raw.json
      syft_sbom.json
      checkov_raw.json (for IaC targets)
      trufflehog_raw.json (for secret scans)
  enrichment/
    cve_enrichment.json
    secret_validation.json
    runtime_context.json
  prioritization/
    composite_scores.json
    grouping.json
  reasoning_trace.md
  api_call_log.jsonl
  output.yaml

/persistent/<customer_id>/vulnerability/
  customer_baseline.yaml
  patching_cadence.yaml
  exceptions.yaml
  cve_history.jsonl
  fix_effectiveness.json
  custom_classifiers.yaml (for customer-specific secret patterns)
  validated_acknowledged_risks.yaml
```

### 6.9 Self-evolution criteria

Vulnerability Agent harness rewrite triggered when:

- False positive rate on secret detection > 10%
- CVE assessment accuracy disputed by customer > 5%
- Scan time exceeds budget on > 15% of invocations
- Validation failures correlate with specific scanner versions
- Customer marks recommendations as "not applicable" > 15%
- Exploitability scoring disputed > 5%
- Coverage gaps detected (CVEs missed in customer environment)

Self-evolution rewrites stage prioritization, parallelization batch sizes, validation heuristics, and recommendation logic.

### 6.10 Pattern usage declaration

**Primary patterns:**
- **Prompt chaining** — 7 sequential stages
- **Parallelization** — Stage 2 scans multiple targets concurrently

**Secondary patterns:**
- **Evaluator-optimizer** — self-evolution
- **Routing** — handoff for cross-domain findings

### 6.11 Tools

(23 tools as listed in permitted_tools above; full specifications in Tool Specification document.)

### 6.12 Memory architecture

**Episodic:**
- Vulnerability findings history (with first-seen, last-seen, status, resolution)
- Patching events per asset
- Customer's typical patch latency
- Last 90-180 days

**Procedural:**
- Effectiveness of patch recommendations
- Common false positives in customer environment
- Customer-specific suppression rules
- Acknowledged accepted risks

**Semantic:**
- Asset criticality map
- Patch windows / change management calendar
- Compliance requirements for patch timelines

### 6.13 Inter-agent coordination

**Calls:**
- Threat Intel Agent — when CVE matches active campaign
- Remediation Agent — for patch deployment drafts and IaC fix PRs
- Cloud Posture Agent — when CVE remediation requires config change
- Runtime Threat Agent — to check if vulnerable component is actively running
- Identity Agent — when secret rotation needed for service accounts

**Called by:**
- Supervisor (primary)
- Cloud Posture Agent (when posture finding involves vulnerable component)
- Investigation Agent (during investigation)
- Curiosity Agent (proactive vulnerability hunting)

### 6.14 Wiz capability mapping

Maps to Wiz vulnerability management plus Wiz Code IaC scanning plus Wiz secret detection. Coverage parity at Phase 1: approximately 95% of Wiz capability — this is our strongest agent at launch because vulnerability detection is most commoditized.

### 6.15 Coverage progression

| Phase | Coverage | Notes |
|---|---|---|
| 1 | 95% | Production with comprehensive scanner stack |
| 2 | 96% | Refinement, additional ecosystems |
| 3 | 97% | + SideScanning equivalent (snapshot-based agentless) |
| 4 | 98% | Mature with custom classifiers |

---

(Document continues in Part 2 with Identity Agent, Runtime Threat Agent, Data Security Agent, Network Threat Agent, Compliance Agent, Investigation Agent, Threat Intel Agent, Remediation Agent, Curiosity Agent, Synthesis Agent, Meta-Harness Agent, Audit Agent, plus sections 19-21.)

**Part 1 of 2 ends here. Continuing in next file.**
