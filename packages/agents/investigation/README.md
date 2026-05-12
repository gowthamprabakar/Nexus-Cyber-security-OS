# `nexus-investigation-agent`

Investigation Agent — agent **#8 of 18** for Nexus Cyber OS. **Opens Phase 1b.** The first agent to consume the full [Phase-1a substrate](../../../README.md#status-snapshot) end-to-end: [F.5 memory engines](../../charter/src/charter/memory/) + [F.6 audit query](../audit/) + [F.4 tenant context](../../control-plane/) + [F.1 charter](../../charter/) under the [ADR-007](../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) reference NLAH template.

## What it does

Implements the **Orchestrator-Workers pattern** (depth ≤ 3, parallel ≤ 5) for forensic incident analysis. Given an `ExecutionContract` requesting an investigation, D.7 runs a six-stage pipeline:

```
SCOPE → SPAWN → SYNTHESIZE → VALIDATE → PLAN → HANDOFF
```

Stage 2 spawns up to four parallel **sub-investigations** under their own Charters:

- `timeline` — reconstructs event sequence across audit chains + findings
- `ioc_pivot` — extracts and pivots indicators of compromise
- `asset_enum` — enumerates affected resources via semantic-memory neighbor walks
- `attribution` — maps to known threat actors (MITRE ATT&CK 14.x bundled)

Output: an `incident_report.json` (OCSF 2004 Detection Finding with `types[0]="incident"`) + a timeline + hypotheses + a containment / eradication / recovery plan. The Audit Agent (F.6) records every hypothesis with `evidence_refs` pointing back at the source audit_event_ids and finding_ids — so a future auditor can replay the investigation.

## Quick start

```bash
# Run evals (10/10 expected once Task 14 lands)
uv run investigation-agent eval packages/agents/investigation/eval/cases

# Triage mode (fast assessment)
uv run investigation-agent triage --contract path/to/contract.yaml

# Deep investigation
uv run investigation-agent run \
    --contract path/to/contract.yaml \
    --sibling-workspace /workspaces/cust_acme/run_001/cloud_posture \
    --sibling-workspace /workspaces/cust_acme/run_001/runtime_threat
```

## ADR-007 conformance

D.7 is the **sixth** agent under the reference NLAH template (F.3 / D.1 / D.2 / D.3 / F.6 / **D.7**). Inherits v1.1 (LLM adapter via `charter.llm_adapter`) and v1.2 (NLAH loader via `charter.nlah_loader`). **Not** in the v1.3 always-on class — D.7 honours every budget axis including `wall_clock_sec` (extended cap of 600s for deep investigations).

Potential **ADR-007 v1.4** amendment evaluated at Task 16: if the sub-agent spawning primitive (Task 8) duplicates in Supervisor's eventual plan, hoist to `charter.subagent`. v0.1 ships the primitive locally with allowlist enforcement (one entry: `investigation`).

## Architecture

See [the D.7 plan](../../../docs/superpowers/plans/2026-05-13-d-7-investigation-agent.md) for the full architecture diagram, six resolved questions (OCSF class, sub-agent primitive, cross-agent reads, budget allocation, LLM fallback, evidence preservation), and the 16-task execution roadmap.

## License

BSL 1.1 per [ADR-001](../../../docs/_meta/decisions/ADR-001-monorepo-bootstrap.md).
