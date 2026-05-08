# RUNTIME CHARTER
## Universal Physics Governing All Agents

The runtime charter defines the laws every agent operates under. It is the operating system of the agent ecosystem. While the agent specification defines what each agent does, the charter defines how the world works for every agent.

This document is the most important engineering specification in the platform because:
1. It's shared across every agent — write once, applies to all
2. It's the primary defensibility moat — detection rules can be copied; a runtime charter cannot
3. It determines whether agents reliably succeed or unreliably fail in production

---

## CHARTER STRUCTURE

The charter has nine articles, each defining a domain of agent physics:

1. **Identity and Lifecycle** — what an agent is, how it's instantiated, how it terminates
2. **Contracts** — how invocations are bound, validated, enforced
3. **State and Memory** — how persistence works, where state lives
4. **Tools and Permissions** — how tool access is governed
5. **Communication** — how agents talk to each other
6. **Canonical Patterns** — how the five patterns are implemented as primitives
7. **Self-Evolution** — how agents improve safely
8. **Failure Handling** — what happens when things go wrong
9. **Observability** — how the system is observed and audited

---

## ARTICLE 1 — IDENTITY AND LIFECYCLE

### 1.1 What is an agent

An agent is the combination of:
- A model (LLM with specific version pinned)
- A harness comprising backend infrastructure, charter participation, and NLAH

An agent is NOT:
- A single LLM call
- A long-running process
- A service

Agents are instantiated per invocation. Each invocation is a new agent instance with fresh context but access to persistent state through file-backed storage.

### 1.2 Agent identity

Every agent instance has:
- `agent_type` — which agent specification it implements (e.g., `cloud_posture`)
- `agent_version` — specific NLAH version (e.g., `cloud_posture@v3.2.1`)
- `instance_id` — unique UUID for this invocation
- `model_pin` — exact model used (e.g., `claude-sonnet-4-5`)
- `customer_id` — which customer this instance serves
- `delegation_id` — which delegation chain this is part of
- `parent_instance_id` — null for supervisor invocations, set for delegated calls

This identity is captured in every audit event, every workspace path, every reasoning trace. Reproducibility for compliance depends on this.

### 1.3 Lifecycle stages

Every agent invocation passes through these stages, charter-enforced:

```
[INSTANTIATE]
  - Charter validates contract is well-formed
  - Workspace directory created
  - NLAH and soul.md loaded into model context
  - Permitted tools registered
  - Budget tracker initialized
  - Audit event: instance_started

[EXECUTE]
  - Agent reasons and acts
  - Charter monitors budget consumption
  - Charter enforces permission boundaries
  - Charter validates each tool call
  - Audit events: tool_called, state_written

[VALIDATE]
  - Charter checks completion conditions met
  - Required outputs populated
  - Confidence thresholds met or escalation triggered

[FINALIZE]
  - Output written to workspace
  - State persisted if applicable
  - Audit event: instance_completed
  - Workspace marked complete

[TERMINATE]
  - Resources released
  - Distributed lock released (if held)
  - Memory cleared
```

If any stage fails, the charter triggers failure handling per Article 8.

### 1.4 Instance limits

Per customer, charter enforces:
- Max concurrent agent instances: configurable, default 50
- Max delegation depth: 3 (supervisor → specialist → sub-agent → forbidden)
- Max parallel sub-agents per parent: 5
- Max instance lifetime: agent-specific (defined in contract budget)

These limits prevent runaway agent creation and resource exhaustion.

### 1.5 Special instance types

**Heartbeat instances:** Supervisor instances triggered by the heartbeat scheduler. Run on a schedule, not on demand.

**Reactive instances:** Triggered by events (real-time alert from Falco, customer query). Preempt normal scheduling.

**Sub-agent instances:** Spawned by parent agents (only Investigation and Supervisor can spawn). Inherit subset of parent's budget and permissions.

**Background instances:** Long-running ingestion (Threat Intel feed pulling). Different lifecycle — continuous, not per-invocation.

---

## ARTICLE 2 — CONTRACTS

### 2.1 What is a contract

Every agent invocation requires a contract. The contract is the function signature for the agent call. It is parsed and enforced by the charter, not by the agent.

A contract has six required components:

1. **Identity** — source agent, target agent, delegation chain
2. **Task** — what the agent should accomplish (structured)
3. **Required outputs** — what fields must be present, with schemas
4. **Budget** — resource caps the agent must respect
5. **Permitted tools** — subset of agent's full toolset for this task
6. **Completion conditions** — explicit "done" criteria

Optionally:
- Escalation rules — what to do on specific failure types
- Forbidden tools — explicit denylist (rare but used for safety)
- Workspace path — where state goes
- Conditional tools — tools only permitted if specific conditions hold

### 2.2 Contract format

Contracts are YAML, validated against JSON Schema before agent instantiation:

```yaml
contract_version: 1.0
contract_id: <UUID>
identity:
  source_agent: supervisor
  target_agent: cloud_posture
  delegation_chain: [supervisor:abc, cloud_posture:def]
  customer_id: <id>
task:
  type: scan_findings
  scope:
    cloud_provider: aws
    account_id: 123456789
    regions: [us-east-1, us-west-2]
required_outputs:
  findings:
    type: array
    item_schema: <reference to schema>
    min_count: 0
    max_count: 100
budget:
  max_llm_calls: 8
  max_tokens: 12000
  max_wall_clock_seconds: 90
  max_cloud_api_calls: 200
  max_workspace_mb: 50
permitted_tools:
  - run_prowler_scan
  - query_aws_config
  - recall_similar_findings
forbidden_tools: []  # explicit empty if none
completion_condition: |
  all findings have severity, business_impact, confidence populated
  AND each confidence >= 0.6 OR escalate_with_reason
escalation_rules:
  on_budget_exceeded: return_partial_with_flag
  on_tool_failure: retry_once_then_escalate
  on_low_confidence: request_peer_review
workspace: /workspaces/<customer_id>/<contract_id>/
```

### 2.3 Contract enforcement

The charter is the contract enforcer. Specifically:

**Pre-execution:**
- JSON Schema validation of contract structure
- Permission check: does target agent have permission to use all permitted_tools?
- Budget validation: are budget caps within agent's maximum allowed?
- Workspace creation: does the workspace path resolve?

**During execution:**
- Tool call interceptor: every tool call passes through charter
  - Is this tool in permitted_tools?
  - Have we hit max_llm_calls? max_tokens? max_cloud_api_calls?
  - Is wall_clock under max_wall_clock_seconds?
- Workspace write interceptor: writes go through charter
  - Path under workspace root?
  - Total size under max_workspace_mb?

**Post-execution:**
- Output validation: required_outputs all present?
- Schema validation: do outputs match declared schemas?
- Completion condition evaluation: did the agent actually complete?

### 2.4 Contract violation responses

| Violation | Charter response |
|---|---|
| Tool not in permitted_tools | Tool call rejected with error, agent decides next step |
| Budget exceeded (any dimension) | Agent receives budget_exceeded signal, must finalize or escalate |
| Wall clock exceeded | Hard termination, partial state preserved, escalation triggered |
| Output schema violation | Validation error returned to agent for correction |
| Completion condition not met | Agent receives incomplete signal, must escalate |
| Workspace size exceeded | Write rejected, agent must reduce state |

Critical principle: **the agent never silently fails contract violations.** The charter always surfaces violations and gives the agent a chance to recover or escalate.

### 2.5 Contract templates and inheritance

Common contract patterns are templates. Agents can inherit from templates and override specifics:

```yaml
contract_template: standard_specialist_invocation
overrides:
  task: <specific>
  budget:
    max_llm_calls: 12  # override default 8
```

Templates live in `/persistent/global/contracts/templates/`.

### 2.6 Multi-stage contracts

For long-running tasks (Investigation Agent's deep dives), contracts can declare stages:

```yaml
stages:
  - stage_id: scope
    budget: {max_llm_calls: 3, max_wall_clock_seconds: 30}
    outputs: [scope_definition]
  - stage_id: spawn
    budget: {max_llm_calls: 2, max_wall_clock_seconds: 15}
    outputs: [sub_agent_assignments]
  - stage_id: synthesize
    budget: {max_llm_calls: 10, max_wall_clock_seconds: 120}
    outputs: [investigation_report]
```

Each stage gets its own budget. Stage transitions are charter-validated.

---

## ARTICLE 3 — STATE AND MEMORY

### 3.1 The principle of file-backed state

All agent state is path-addressable. Agents do not maintain state in memory across calls. State lives in files; agents read and write files.

This principle exists because:
- Context windows are finite — file-backed state survives truncation
- Agents may restart — file-backed state survives restarts
- Delegation requires handoff — files are how state passes
- Auditability requires durability — files are the audit substrate

### 3.2 Workspace structure

Every agent invocation gets a workspace. Workspaces are organized hierarchically:

```
/workspaces/
  <customer_id>/
    <delegation_id>/
      <agent_name>/
        task.yaml          # the contract
        inputs/            # what came in
        working/           # intermediate work
        outputs/           # what's going out
        reasoning_trace.md # raw reasoning log
        audit/             # audit events for this invocation
        
/persistent/
  <customer_id>/
    <agent_name>/
      <persistent state for that agent>
  global/
    <shared global state>
```

### 3.3 Workspace lifecycle

Workspaces are created at instantiation, populated during execution, sealed at finalization, and retained for the configured retention period (default: 30 days).

Sealed workspaces are read-only. They cannot be modified after the agent invocation completes. This is enforced by filesystem permissions plus charter validation.

After retention period, workspaces are archived (compressed and moved to cold storage) then eventually deleted. Audit metadata about the workspace is retained even after deletion.

### 3.4 Persistent state

Persistent state lives outside workspaces in `/persistent/`. This is where customer-specific learning, baselines, and history live.

Charter rules for persistent state:
- Reads: agent can read its own persistent state and global state freely
- Writes: agent can only write to its own persistent state
- Deletes: never permitted by agents (only by data retention background process)
- Schema: persistent state must conform to declared schemas in agent specification

Persistent state is replicated and backed up per the platform's data durability requirements.

### 3.5 Memory tiers (recap from spec, governed here)

**Tier 1 — Episodic Memory:**
- Storage: TimescaleDB (per customer)
- Path: `/persistent/<customer_id>/<agent_name>/<memory_type>.timescale/`
- Retention: 30-90 days configurable
- Access: agent's read/write own; Meta-Harness reads all (read-only)

**Tier 2 — Semantic Memory:**
- Storage: Neo4j (per customer subgraph)
- Path: graph database, namespaced by customer
- Retention: indefinite with consolidation
- Access: agent's read/write own; agents read shared portions; Memory Curator workflow consolidates

**Tier 3 — Procedural Memory:**
- Storage: PostgreSQL (versioned playbooks)
- Path: `/persistent/<customer_id>/<agent_name>/procedural.pgschema/`
- Retention: indefinite
- Access: agent reads/writes; Meta-Harness can propose updates (signed)

### 3.6 State synchronization

When sub-agents spawn from parent agents, state synchronization is governed by:

- Parent's workspace contains pointers to sub-agent workspaces
- Sub-agent inherits read access to parent's workspace
- Sub-agent has its own writable workspace
- On sub-agent finalization, parent reads outputs; charter ensures consistency

Cross-agent state access (e.g., Compliance Agent reading Cloud Posture findings) goes through the supervisor's workspace coordination, not direct agent-to-agent.

### 3.7 State integrity

All persistent state writes are checksummed. Critical state (audit logs, authorization profiles, signed rules) uses hash chains for tamper detection.

The charter validates checksums on read. Tampered state triggers immediate human escalation and freezes the affected agent.

---

## ARTICLE 4 — TOOLS AND PERMISSIONS

### 4.1 Tool registration

Every tool used by any agent is registered in `/persistent/global/tools/registry.yaml`:

```yaml
- tool_id: run_prowler_scan
  description: Execute Prowler scanner against AWS account
  parameters:
    schema: <JSON Schema>
  permissions_required:
    - aws_read_credentials
    - prowler_binary
  cost_class: medium
  rate_limit: 10_per_minute
  audit_required: true
```

Tools cannot be invoked by agents unless registered.

### 4.2 Permission model

Permissions are layered:

**Layer 1 — Agent-level permissions:**
The full set of tools an agent CAN use, defined in the agent's specification.

**Layer 2 — Contract-level permissions:**
The subset of tools permitted for THIS specific invocation, declared in `permitted_tools` in the contract.

**Layer 3 — Conditional permissions:**
Tools whose permission depends on runtime conditions (e.g., `kill_process` requires customer's Tier 1 authorization for the action class).

A tool call must pass all three layers. Charter validates at call time.

### 4.3 Tool call interception

Every tool call is intercepted by the charter:

```
Agent calls: tool_call("run_prowler_scan", {...})

Charter:
  1. Is this tool registered? (Layer 0)
  2. Is it in agent's full permissions? (Layer 1)
  3. Is it in contract's permitted_tools? (Layer 2)
  4. Are conditional permissions satisfied? (Layer 3)
  5. Is rate limit satisfied?
  6. Have we hit budget caps?
  7. Audit log: tool_call_attempted

If all pass:
  Charter executes tool
  Charter intercepts result
  Charter validates result schema
  Charter audit: tool_call_completed
  Returns result to agent

If any fail:
  Charter audit: tool_call_rejected
  Returns error to agent
  Agent decides next step (retry? escalate? alternative tool?)
```

### 4.4 Action tools (special category)

Tools that modify customer state (execute_remediation, kill_process, block_ip) are "action tools" with extra requirements:

- Mandatory dry-run if available
- Mandatory rollback plan computed before execution
- Mandatory authorization tier check
- Mandatory audit log with full context
- Mandatory verification after execution

Action tools can never be in `permitted_tools` unless the agent's contract is explicitly authorized for actions (typically only Remediation Agent, with conditional permissions per Tier 1 action class).

### 4.5 Tool versioning

Tools are versioned. Agents can pin specific tool versions in their backend infrastructure spec. The charter ensures tool version availability before agent instantiation.

When tools are upgraded:
- New version registered alongside old
- Agents migrate one at a time
- Old version retired only when no agents reference it
- Deprecation period minimum 30 days

### 4.6 External tool integration (cloud APIs, etc.)

External tools (AWS API, Azure API, GCP API) are wrapped in charter-aware adapters. The adapter:
- Manages authentication
- Enforces rate limits per cloud account
- Captures call/response for audit
- Handles retries with exponential backoff
- Surfaces errors to agent in structured form

Adapters are themselves versioned and registered.

---

## ARTICLE 5 — COMMUNICATION

### 5.1 Communication topology

Agents do not call each other directly. All communication flows through one of three channels:

**Channel 1 — Supervisor delegation:**
Supervisor → Specialist (one-to-one)
This is the primary communication pattern.

**Channel 2 — Parent-child (Investigation only):**
Investigation Agent → Sub-investigation Agent (one-to-many)
Limited to depth 1 — sub-agents cannot spawn further.

**Channel 3 — Workspace coordination:**
Agent A writes to workspace, Agent B (later, via supervisor) reads from workspace.
Asynchronous, mediated by supervisor.

Direct agent-to-agent calls are forbidden by charter. This prevents hidden coupling and makes the system testable.

### 5.2 Message format

All inter-agent messages are structured YAML:

```yaml
message_id: <UUID>
message_type: delegation_request | delegation_response | workspace_handoff | escalation
timestamp: <ISO 8601>
sender: <agent_instance_id>
recipient: <agent_instance_id or "supervisor">
correlation_id: <UUID>  # for matching request to response
payload: <type-specific>
auth_token: <signed token>
```

Messages are signed (HMAC) so the charter can verify authenticity.

### 5.3 Synchronous vs asynchronous

Delegations can be synchronous (caller waits for response) or asynchronous (caller continues, response comes later).

**Synchronous delegations:**
- Used for fast specialists (Cloud Posture quick check)
- Caller blocks up to delegation timeout
- Charter enforces timeout

**Asynchronous delegations:**
- Used for long-running tasks (Investigation Agent deep dives)
- Caller registers callback or polling location
- Charter manages task lifecycle independently

### 5.4 Delegation patterns

The five canonical patterns map to specific delegation patterns:

**Routing (Supervisor only):**
- Single delegation per task
- Supervisor decides which specialist
- Synchronous or async based on specialist

**Parallelization:**
- Supervisor fans out to multiple specialists simultaneously
- Charter manages parallel execution
- Synthesis Agent integrates results

**Orchestrator-Workers (Investigation):**
- Investigation Agent spawns sub-agents
- Sub-agents execute in parallel
- Investigation Agent synthesizes

**Prompt Chaining:**
- Within a single agent invocation
- Stages declared in NLAH
- Charter validates stage transitions

**Evaluator-Optimizer:**
- Meta-Harness reads traces
- Proposes new NLAH
- Eval suite runs against proposal
- Charter gates deployment

### 5.5 Backpressure and queuing

When supervisor delegates faster than specialists can process, the charter applies backpressure:

- Per-customer queue with bounded size
- Per-agent-type concurrency limits
- Priority levels (critical > urgent > normal > background)
- Aged tasks escalate (priority increases over time)
- Queue depth metrics emitted continuously

If queues overflow:
- Critical tasks get scheduling priority
- Background tasks deferred
- Customer notified of degraded service
- Auto-scaling triggered if configured

---

## ARTICLE 6 — CANONICAL PATTERNS AS PRIMITIVES

The five patterns are first-class charter primitives, not hand-coded per agent.

### 6.1 Routing primitive

```python
charter.route(
  task: Task,
  routing_table: agents.md,
  fallback: agent_name = "investigation"
) -> AgentName
```

Routing logic implemented once in the charter, used by Supervisor.

Routing table format:
```yaml
routes:
  - condition: delta_type == "S3_misconfiguration"
    target: cloud_posture
    priority: 1
  - condition: delta_type == "CVE_detected"
    target: vulnerability
    priority: 1
  - condition: customer_query.has_natural_language
    target: synthesis  # for multi-domain queries
    priority: 2
fallback: investigation
```

### 6.2 Parallelization primitive

```python
charter.parallel(
  tasks: List[Task],
  max_concurrent: int,
  timeout_per_task: int,
  failure_mode: "fail_fast" | "best_effort"
) -> List[Result]
```

Implementations details (thread pool, async runtime, error aggregation) handled by charter.

### 6.3 Orchestrator-Workers primitive

```python
charter.orchestrate(
  parent_agent: AgentInstance,
  sub_tasks: List[Task],
  spawn_limits: SpawnConfig,
  synthesis_callback: Callable
) -> OrchestrationResult
```

Used by Investigation Agent. Charter ensures sub-agents inherit appropriate parent context, enforces spawn limits, manages sub-agent lifecycle.

### 6.4 Prompt Chaining primitive

```python
charter.chain(
  agent_instance: AgentInstance,
  stages: List[Stage],
  state_handoff: "workspace" | "context"
) -> ChainResult
```

Stages declared in NLAH. Charter validates each stage's outputs before proceeding to next stage. State passes via workspace files (preferred) or context (for small state).

### 6.5 Evaluator-Optimizer primitive

```python
charter.evaluate_and_optimize(
  target_agent: AgentName,
  current_nlah_version: str,
  proposed_nlah_version: str,
  eval_suite: EvalSuite,
  acceptance_criteria: AcceptanceCriteria
) -> OptimizationResult
```

Used by Meta-Harness Agent. Charter runs eval suite, compares results, applies acceptance gating.

### 6.6 Pattern composition

Patterns compose. Investigation Agent uses orchestrator-workers (spawning sub-agents) where each sub-agent uses chaining (multi-stage execution). Meta-Harness uses chaining (collect → diagnose → propose → eval → decide → deploy) where the eval stage uses parallelization (running multiple test cases concurrently).

The charter enforces composition rules — sub-agents cannot spawn sub-agents (depth limit), parallelization batches respect concurrency limits, etc.

---

## ARTICLE 7 — SELF-EVOLUTION

### 7.1 What can self-evolve

The charter governs what aspects of the system can change automatically:

**Can self-evolve:**
- Agent NLAH (with eval gating + signing)
- Customer-specific tunings (with customer consent)
- Suppression rules (with FP rate validation)
- Procedural memory (with outcome verification)

**Cannot self-evolve:**
- Charter itself (engineering team only)
- Backend infrastructure (engineering team only)
- Authorization tiers (customer only)
- Compliance frameworks (compliance team only)
- Audit log structure (compliance team only)

### 7.2 Self-evolution gating

Every self-evolution proposal goes through gating:

**Stage 1 — Trigger validation:**
Did the trigger condition genuinely fire? (e.g., FP rate truly > 15% over 500 findings, not 5 findings)

**Stage 2 — Trace analysis:**
Meta-Harness reads RAW traces (not summaries). Pattern detection on failures.

**Stage 3 — Proposal generation:**
New NLAH version drafted. Diff captured.

**Stage 4 — Eval execution:**
Run proposed NLAH against agent's eval suite (50-200 test cases).
Run on multiple model versions for cross-model validation.

**Stage 5 — Acceptance evaluation:**
- Eval score must improve by >5% on relevant metrics
- No regression on existing test cases (>2% drop fails)
- Cross-model compatibility maintained
- Human review required for major rewrites (>30% diff)

**Stage 6 — Signing and deployment:**
- New NLAH signed with HSM-backed key
- Versioned, deployed via canary rollout
- Monitoring for production regression
- Auto-rollback on regression detected

### 7.3 Self-evolution limits

The charter prevents self-evolution from spiraling:

- Max evolution attempts per agent per week: 3
- Mandatory cooldown after acceptance: 7 days before next evolution
- Mandatory cooldown after rejection: 24 hours
- Lifetime version limit: 100 (after which manual review required)
- Diff size limit: 50% of NLAH (larger requires human review)

These limits exist because over-evolution can drift agent behavior in unintended directions.

### 7.4 Cross-model transferability

When proposing new NLAH, Meta-Harness tests across multiple models:

```yaml
cross_model_eval:
  primary_model: claude-sonnet-4-5
  secondary_models:
    - claude-opus-4-5
    - claude-haiku-4
  test_cases: <full eval suite>
  acceptance: improvement_on_primary AND no_regression_on_others
```

Cross-model failure means the NLAH change works for one model but not others. This usually indicates over-fitting and the proposal is rejected.

### 7.5 Rollback mechanism

If a deployed NLAH causes production issues:

1. Auto-detection: monitoring catches regression in production metrics
2. Charter triggers rollback: reverts to previous NLAH version
3. Audit event: nlah_rollback_triggered with diagnostic data
4. Meta-Harness reviews trace, may propose alternative
5. Affected NLAH version blacklisted from re-deployment without human review

---

## ARTICLE 8 — FAILURE HANDLING

### 8.1 Failure taxonomy

Charter recognizes these failure types:

**Recoverable failures:**
- Tool call timeout (retry with backoff)
- API rate limit (back off, retry)
- Transient network issue (retry)
- Single LLM call failure (retry once)

**Bounded failures:**
- Budget exceeded (return partial, escalate)
- Tool unavailable (use backup, log)
- Schema validation error (request correction from agent)

**Unrecoverable failures:**
- Authorization missing (cannot proceed)
- Required dependency offline (escalate immediately)
- Hash chain integrity violated (freeze, human required)
- Repeated retries exhausted (escalate)

**Catastrophic failures:**
- Data corruption detected (freeze affected systems, human required)
- Tampering detected (freeze, security incident)
- Charter integrity violated (full system halt)

### 8.2 Escalation paths

Each failure type has a defined escalation path:

```yaml
escalation_paths:
  recoverable:
    primary: agent_self_handle
    if_repeated: log_and_continue
  bounded:
    primary: agent_decides
    fallback: parent_agent
    timeout: 30s
  unrecoverable:
    primary: parent_agent_or_supervisor
    escalation: customer_notification
    timeout: 5min
  catastrophic:
    primary: human_engineer_oncall
    escalation: incident_response
    timeout: 0  # immediate
```

### 8.3 Circuit breakers

The charter implements circuit breakers per:

- Per-tool: too many failures → temporarily disable tool
- Per-agent: too many failed invocations → quarantine agent
- Per-customer: cascading failures → enter degraded mode
- Per-cloud-account: rate limit detected → throttle

Circuit breakers auto-reset on success after cool-down period.

### 8.4 Cascade prevention

Multi-agent systems can cascade failures (Agent A fails → calls Agent B → which fails → calls Agent C → ...).

Charter prevents cascades through:

- Delegation depth limit (max 3)
- Time budget propagation (sub-agents inherit shrinking budget)
- Failure attribution (failures attributed to root cause, not propagation)
- Cascade detection: >3 cascading failures in 60 seconds triggers customer-wide circuit breaker

### 8.5 Graceful degradation

When failures occur, charter prefers graceful degradation over hard failure:

- Specialist unavailable → fall back to alternative specialist (Vulnerability Agent backup with Grype if Trivy fails)
- LLM API issue → reduce reasoning depth, use cached responses
- Cloud API rate limit → defer non-critical scans
- Memory tier unavailable → operate with available tiers, flag degraded

Degradation is signaled to customer in real-time activity feed.

---

## ARTICLE 9 — OBSERVABILITY

### 9.1 What is observed

Every agent invocation produces:

**Structured events:**
- instance_started
- contract_validated
- tool_called (with args)
- tool_completed (with result hash)
- workspace_written
- stage_transitioned
- failure_occurred
- escalation_triggered
- instance_completed

**Reasoning traces:**
- Raw LLM input/output (not summarized — critical for Meta-Harness)
- Decision points and rationale
- Confidence assessments

**Performance metrics:**
- Latency per stage
- Token usage
- Tool call counts
- Workspace size

**Audit records:**
- Per Article 1.4 (instance lifecycle)
- Plus all action tools with full context
- Plus all authorization checks

### 9.2 Trace storage

Reasoning traces stored in workspace `reasoning_trace.md`. Format:

```markdown
# Agent Trace: <agent_name>:<instance_id>

## Contract
[full contract YAML]

## Initial Understanding
[agent's first interpretation of task]

## Decision: <decision_id>
**Reasoning:** [raw reasoning]
**Action:** tool_call(name, args)
**Result:** [tool result, summarized but with raw available]

## Decision: <decision_id>
...

## Final Synthesis
[output reasoning]

## Reflection
[any self-assessment]
```

Traces are critical for:
- Debugging when things go wrong
- Meta-Harness optimization (raw traces, not summaries)
- Compliance reproducibility (auditor reconstruction)
- Customer transparency (real-time activity feed)

### 9.3 Metric emission

Charter emits structured metrics to time-series store:

```
agent_invocations_total{agent="cloud_posture", customer="X", outcome="success"} 12453
agent_invocation_duration_seconds{agent="cloud_posture", percentile="0.95"} 23.4
tool_calls_total{tool="run_prowler_scan", outcome="success"} 8932
contract_violations_total{type="budget_exceeded", agent="vulnerability"} 47
self_evolution_attempts_total{agent="cloud_posture", outcome="accepted"} 3
```

Metrics power:
- Operations dashboards
- SLO monitoring
- Capacity planning
- Customer health scoring

### 9.4 Audit log

Audit log is append-only, hash-chained, and stored separately from operational data:

```
/persistent/<customer_id>/audit/audit_log.jsonl

{
  "audit_id": "uuid",
  "timestamp": "ISO8601",
  "previous_hash": "sha256...",
  "current_hash": "sha256...",
  "event_type": "tool_call",
  "actor": "agent_instance_id",
  "context": {...}
}
```

Hash chain integrity verified continuously. Tampering detection triggers immediate human escalation.

Audit log retention: 7 years (compliance requirement for most frameworks).

### 9.5 Customer-facing observability

Customers see (via dashboard and API):

- Real-time activity feed: what agents are doing right now
- Decision history: what decisions were made, why
- Action history: what actions were taken, with outcomes
- Health metrics: agent uptime, scan freshness, finding latency
- Authorization usage: how often Tier 1 actions taken

This transparency is genuinely differentiating. Wiz shows you findings; you show customers the reasoning behind every decision.

---

## CHARTER VERSIONING

The charter itself is versioned. Charter version: 1.0 at platform launch.

Charter changes require:
- Engineering review (all senior engineers)
- Eval against ALL agents (no agent regression allowed)
- Compliance review (audit log and authorization model unchanged in incompatible ways)
- Customer notification (30-day notice for breaking changes)
- Migration plan for any breaking changes

Charter is the most stable component of the system. NLAHs change weekly; charter changes quarterly at most.

---

## CHARTER ENFORCEMENT IMPLEMENTATION

The charter is implemented as a runtime library that:

1. Loads at agent instantiation
2. Wraps every tool call
3. Wraps every workspace write
4. Wraps every state read
5. Validates every contract
6. Emits all metrics and audit events

Implementation language: Python (matches detection scanner ecosystem) with strict typing (mypy strict mode).

Performance targets:
- Charter overhead per tool call: <5ms
- Charter overhead per agent invocation: <50ms
- Audit log write latency: <10ms

The charter is itself open-sourceable in part. Some elements (specific routing logic, eval gates) remain proprietary, but the core contract enforcement, file-backed state, and pattern primitives could be released as open infrastructure. This contributes to community while keeping competitive advantages internal.

---

## WHAT THE CHARTER ENABLES

With this charter implemented:

1. **Reliability** — agents fail predictably, recover gracefully
2. **Auditability** — every decision reconstructible
3. **Testability** — eval suites work because behavior is bounded
4. **Improvability** — self-evolution operates safely
5. **Composability** — patterns compose without coordination chaos
6. **Defensibility** — competitors copying detection rules face years of charter engineering to match

The charter is your moat. The agents are interchangeable; the charter is not.

The architecture document (next) translates spec + charter into deployment topology, infrastructure, and the engineering blueprint your team builds from.
