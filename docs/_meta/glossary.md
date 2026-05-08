# Glossary

## Charter

The runtime physics every agent obeys: budget envelopes, tool whitelists, escalation rules, audit hash chain, depth/parallelism caps. Implemented in `packages/charter/`. The charter is what makes an LLM into a _production agent_.

## NLAH (Natural Language Agent Harness)

The agent's domain brain — a structured markdown document defining how a single agent thinks. Lives at `packages/agents/<agent-name>/nlah/`. NLAH = the prompt + playbook + tool descriptions + escalation policies for one agent.

## Execution contract

A signed YAML object created at every invocation specifying: identity, task, required outputs, budget, permitted tools, completion conditions, workspace path. Validated by the charter before the agent runs.

## Workspace

The per-invocation file directory at `/workspaces/<customer>/<agent>/<run_id>/`. Ephemeral by default. All in-flight state is path-addressable here.

## Persistent memory

The per-customer-per-agent long-term store at `/persistent/<customer>/<agent>/{episodic,procedural,semantic}/`. Backed by TimescaleDB (episodic), PostgreSQL (procedural), Neo4j Aura (semantic).

## Tier 1 / 2 / 3 remediation

Three levels of agent action authority:

- Tier 3 — recommend only (artifact, no execution)
- Tier 2 — execute after human approval (Slack/Teams/email)
- Tier 1 — autonomous, with auto-rollback timer and post-validation

## Meta-Harness

Agent #13. Reads execution traces, proposes NLAH rewrites for other agents, validates against eval suite, deploys if accepted.

## Eval suite

Per-agent set of test cases (input → expected behavior). Used to gate NLAH changes (≥5% improvement, ≤2% regression).

## Edge plane

Single-tenant runtime deployed inside the customer's environment (Helm chart for EKS/AKS/GKE in Phase 1; bare-metal/air-gap in later phases).

## Control plane

Multi-tenant SaaS we operate on AWS (us-east-1 + us-west-2 DR). Coordinates the edge fleet.

## Synthesis Agent

Agent #12. Combines findings from multiple specialist agents into customer-facing narratives.

## Curiosity Agent

Agent #11. Background "wonder" agent — explores customer environment for unknown patterns when system has idle capacity.

## Investigation Agent

Agent #8. Spawns sub-agents using the Orchestrator-Workers pattern (depth ≤ 3, parallel ≤ 5) for forensic analysis.

## Audit Agent

Agent #14. Append-only hash-chained log writer. The only agent the others cannot disable.

## Vertical content pack

A bundle of NLAH tunings, detection rules, compliance mappings, and integration depth specific to one industry (tech, healthcare, financial, manufacturing, defense). Layered on top of the horizontal platform.
