# `nexus-investigation-agent`

Investigation Agent — agent **#8 of 18** for Nexus Cyber OS. **First Phase-1b agent** and the first to consume the full [Phase-1a substrate](../../../README.md#status-snapshot) end-to-end: [F.5 memory engines](../../charter/src/charter/memory/) + [F.6 audit query](../audit/) + [F.4 tenant context](../../control-plane/) + [F.1 charter](../../charter/) under the [ADR-007](../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) reference NLAH template (v1.1 + v1.2).

## What it does

Forensic incident correlation. Given an `ExecutionContract` requesting an investigation, D.7 runs a **six-stage pipeline** under the Orchestrator-Workers pattern (depth ≤ 3, parallel ≤ 5):

```
SCOPE → SPAWN → SYNTHESIZE → VALIDATE → PLAN → HANDOFF
```

Stage 2 fans out four parallel **sub-investigations** under one shared parent Charter:

- `timeline` — reconstructs event sequence across audit chains + sibling-agent findings
- `ioc_pivot` — extracts and pivots indicators of compromise
- `asset_enum` — enumerates affected resources via F.5 semantic-memory neighbour walks
- `attribution` — maps to MITRE ATT&CK v14.1 (10 bundled techniques covering the shipped agents' evidence shapes)

Four artifacts land in the charter-managed workspace:

| File                    | Format                                          | Purpose                                                   |
| ----------------------- | ----------------------------------------------- | --------------------------------------------------------- |
| `incident_report.json`  | OCSF v1.3 `class_uid` **2005** Incident Finding | Wire shape for Meta-Harness and downstream tools.         |
| `timeline.json`         | `Timeline.model_dump_json()`                    | Sorted event sequence across audit + findings.            |
| `hypotheses.md`         | Markdown                                        | Operator-readable hypothesis tracking with evidence refs. |
| `containment_plan.yaml` | YAML                                            | Steps + eradication + recovery-validation criteria.       |

Every hypothesis carries an `evidence_refs` array pointing at real `audit_event:<hash16>` or `finding:<uid>` values. The synthesizer + driver both validate every ref — hallucinated refs drop the entire hypothesis (the **"evidence is sacred" invariant**). See [`runbooks/investigation_workflow.md`](runbooks/investigation_workflow.md) for the operator workflow.

## ADR-007 conformance

D.7 is the **sixth** agent under the reference NLAH template (F.3 / D.1 / D.2 / D.3 / F.6 / **D.7**). Inherits v1.1 (LLM adapter via `charter.llm_adapter`; no per-agent `llm.py`) and v1.2 (NLAH loader is a 21-LOC shim over `charter.nlah_loader`). **Not** in the v1.3 always-on class — D.7 honours every budget axis including `wall_clock_sec` (extended cap of 600s for deep investigations).

**Sub-agent spawning primitive** (Task 8) lands locally in `investigation/orchestrator.py` with allowlist enforcement (one entry: `investigation`). Hoists to `charter.subagent` as **ADR-007 v1.4** when the third duplicate appears — most likely from Supervisor (S.1) once that ships. Today, the local primitive is the explicit policy surface.

**Load-bearing LLM use** (first such agent). D.1–D.3, F.3, and F.6 treat the LLM as a UX nicety with non-LLM fallbacks. D.7 promotes the LLM to a load-bearing call: hypothesis-generation is where the LLM's reasoning value lives. Compliance correctness is preserved by the deterministic fallback path (one hypothesis per finding, confidence 0.5) — every Stage 1–6 artifact is still emitted when the provider is unavailable.

## Quick start

```bash
# 1. Run the local eval suite (10/10)
uv run investigation-agent eval packages/agents/investigation/eval/cases

# 2. Run via the eval-framework (resolves through nexus_eval_runners entry-point)
uv run eval-framework run --runner investigation --cases packages/agents/investigation/eval/cases

# 3. Triage mode (Mode A: concise summary for PagerDuty / Slack)
uv run investigation-agent triage \
    --contract path/to/contract.yaml \
    --sibling-workspace /workspaces/cust_acme/run_001/runtime_threat

# 4. Full investigation (Mode B: writes all four artifacts)
uv run investigation-agent run \
    --contract path/to/contract.yaml \
    --sibling-workspace /workspaces/cust_acme/run_001/cloud_posture \
    --sibling-workspace /workspaces/cust_acme/run_001/runtime_threat \
    --since 2026-05-12T00:00:00Z \
    --until 2026-05-13T23:59:59Z
```

See [`runbooks/investigation_workflow.md`](runbooks/investigation_workflow.md) for the full operator workflow (prerequisites · run + triage commands · artifact reading guide · troubleshooting).

## Architecture

```
F.5 SemanticStore ──→ memory_neighbors_walk ──┐
F.6 AuditStore ─────→ audit_trail_query ──────┼──→ SCOPE → SPAWN ──→ 4 sub-investigations (TaskGroup, depth≤3, parallel≤5)
sibling findings.json → find_related_findings ┘                          │
                                                                         ▼
                                                            ┌────────────┴────────────┐
                                                            │  extract_iocs           │
                                                            │  map_to_mitre           │
                                                            │  reconstruct_timeline   │
                                                            └────────────┬────────────┘
                                                                         │
                                                synthesize_hypotheses ◄──┘
                                          (charter.llm_adapter; load-bearing;
                                          evidence_refs validation mandatory)
                                                                         │
                                                                         ▼
                                                              VALIDATE → PLAN → HANDOFF
                                                                         │
                                                                         ▼
                                              4 artifacts: incident_report.json
                                                          + timeline.json
                                                          + hypotheses.md
                                                          + containment_plan.yaml
```

Five tool wrappers feed the orchestrator: two consume the F.5/F.6 substrate (`memory_neighbors_walk`, `audit_trail_query`), one reads sibling-agent workspaces (`find_related_findings`), two run pure-function analysis (`extract_iocs`, `map_to_mitre`). The synthesizer is the load-bearing LLM call — gated by a deterministic fallback that emits one hypothesis per finding when the provider is unavailable.

The OCSF v1.3 Incident Finding (`class_uid 2005`) was **plan-corrected** at Task 2: the plan opened with `2004 Detection Finding + types[0]="incident"` but 2005 exists in OCSF v1.3 as the purpose-built class. This mirrors F.6's `2007→6003` correction — verify the class against the published OCSF spec before pinning.

## Output contract — the four artifacts

```python
# incident_report.json  (OCSF 2005)
{
    "class_uid": 2005,
    "category_uid": 2,
    "activity_id": 1,
    "finding_info": {"uid": "01J7N5...XYZ", "confidence_score": 75, ...},
    "unmapped": {
        "timeline":              [...],   # sorted ascending by emitted_at
        "hypotheses":            [...],   # validated against evidence_refs
        "iocs":                  [...],   # 9 IOC types
        "mitre_techniques":      [...],   # ranked by keyword hits desc, technique_id asc
        "containment_summary":   "..."    # human-readable plan
    }
}
```

`hypotheses.md` carries the LLM-unavailable banner when the synthesizer falls back; operators see this as a heads-up that hypothesis narrative is degraded (audit chain, timeline, IOCs, MITRE attribution are unchanged). `containment_plan.yaml` has one step per finding with a class-specific template (2002 → patch, 2003 → re-run remediation, 2004 → quarantine, 2005 → escalate, 6003 → review audit record).

## Tests

```bash
uv run pytest packages/agents/investigation -q
```

172 tests, **94% coverage** on `investigation/*`. Uncovered branches are the eval-runner's LLM-stub null-response paths and a few defensive guards on the IOC extractor (exercised by integration cases). Substrate integration is exercised through `MemoryService` + `AuditStore` factories the CLI bootstraps per invocation.

## License

BSL 1.1 per [ADR-001](../../../docs/_meta/decisions/ADR-001-monorepo-bootstrap.md). Substrate this agent consumes (`charter`, `audit`, `eval-framework`) is Apache 2.0; the agent itself is BSL.
