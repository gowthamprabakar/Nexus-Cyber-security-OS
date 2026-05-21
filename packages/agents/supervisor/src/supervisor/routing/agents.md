---
# Supervisor routing table — v0.1 happy-path rules
# (10 rules, one per existing v0.1 specialist named in the plan).
#
# Format: YAML frontmatter + operator-readable prose below.
# Supervisor reads the YAML; operators read the prose.
#
# Each rule entry: rule_id + target_agent + at least one of
# (target_agent_declared / task_type_pattern / delta_type_pattern)
# + permitted_tools allowlist + optional priority (default 0).
#
# Per Q-ARCH-2: permitted_tools is operator-curated here — Supervisor
# does NOT introspect A.4's parse_nlah_dir output to discover them.
# This keeps the introspection coupling out of v0.1.

rules:
  - rule_id: cloud_posture_explicit
    target_agent: cloud_posture
    target_agent_declared: cloud_posture
    permitted_tools:
      - prowler_scan
      - aws_s3_describe
      - aws_iam_list_users_without_mfa
      - aws_iam_list_admin_policies
      - kg_upsert_asset
    priority: 10

  - rule_id: vulnerability_explicit
    target_agent: vulnerability
    target_agent_declared: vulnerability
    permitted_tools:
      - trivy_scan
      - osv_query
    priority: 10

  - rule_id: identity_explicit
    target_agent: identity
    target_agent_declared: identity
    permitted_tools:
      - okta_users_list
      - okta_roles_audit
    priority: 10

  - rule_id: runtime_threat_explicit
    target_agent: runtime_threat
    target_agent_declared: runtime_threat
    permitted_tools:
      - falco_query
      - process_tree_inspect
    priority: 10

  - rule_id: audit_explicit
    target_agent: audit
    target_agent_declared: audit
    permitted_tools:
      - audit_chain_query
      - audit_chain_verify
    priority: 10

  - rule_id: investigation_explicit
    target_agent: investigation
    target_agent_declared: investigation
    permitted_tools:
      - graph_traverse
      - finding_context_lookup
    priority: 10

  - rule_id: network_threat_explicit
    target_agent: network_threat
    target_agent_declared: network_threat
    permitted_tools:
      - flow_logs_query
      - dns_anomaly_detect
    priority: 10

  - rule_id: multi_cloud_posture_explicit
    target_agent: multi_cloud_posture
    target_agent_declared: multi_cloud_posture
    permitted_tools:
      - gcp_scc_query
      - azure_defender_query
    priority: 10

  - rule_id: k8s_posture_explicit
    target_agent: k8s_posture
    target_agent_declared: k8s_posture
    permitted_tools:
      - kube_bench_scan
      - kube_hunter_scan
    priority: 10

  - rule_id: remediation_explicit
    target_agent: remediation
    target_agent_declared: remediation
    permitted_tools:
      - apply_remediation
      - rollback_remediation
    priority: 10
---

# Supervisor routing table (v0.1)

This file is the **declarative routing table** Supervisor consults at every
heartbeat tick. The YAML frontmatter above is parsed via
`supervisor.routing.parser.load_routing_rules`; the prose below is for
operator readability only and is ignored by the parser.

## How routing works (v0.1)

Per Q2 of the [Supervisor v0.1 plan](../../../../../docs/superpowers/plans/2026-05-21-supervisor-v0-1.md),
Supervisor matches an `IncomingTask` against this rule set using a pure-function
rule engine (`supervisor.routing.router`). Match precedence:

1. **`target_agent_declared`** — explicit routing wins when the incoming task
   names a target_agent.
2. **`task_type_pattern`** — pattern-match fallback on `task_type`.
3. **`delta_type_pattern`** — pattern-match fallback on `delta_type`.

`priority` breaks ties when multiple rules match the same task; higher wins.
Equal priority + multiple matches → `Ambiguous` decision → escalate (operator
notified via `escalation_<run_id>.md` markdown).

## Coverage (v0.1)

Ten happy-path rules — one per existing v0.1 specialist. The 6 additional v0.1
agents (`data_security`, `threat_intel`, `compliance`, `synthesis`, `curiosity`,
`meta_harness`) are not currently routable via Supervisor — they ship with
their own CLI/event triggers in v0.1, and routing-table coverage extends in
**Supervisor v0.2** alongside the LLM-assisted routing surface.

## What Supervisor does NOT do (v0.1)

- **NO LLM-driven routing.** Match decisions come from this YAML, not from
  any persona-context inference. Deferred to v0.2.
- **NO multi-agent planning.** Supervisor never decides which agents to invoke
  beyond what the rules + incoming task declare.
- **NO `claims.>` subscription.** Structurally fenced in Task 8.

See the [Supervisor v0.1 plan](../../../../../docs/superpowers/plans/2026-05-21-supervisor-v0-1.md)
for the full scope + deferral list.
