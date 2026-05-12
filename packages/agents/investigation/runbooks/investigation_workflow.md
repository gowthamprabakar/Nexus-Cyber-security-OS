# Investigation workflow — operator runbook

Owner: investigation on-call · Audience: a compliance operator or SRE running a forensic investigation · Last reviewed: 2026-05-13.

This runbook is the **operator-facing workflow** for the Investigation Agent. After the substrate is up (F.5 memory + F.6 audit), this runbook covers running an actual investigation against an incident, interpreting the four output artifacts, and reacting to the LLM-unavailable fallback.

> **Status:** v0.1. Phase 1c adds real-time triage (event-driven invocation by Supervisor), threat-intel APIs (VirusTotal, OTX), and per-sub-Charter spawning. Today the workflow is run-on-demand + structured-output-only.

---

## Prerequisites

- F.5 substrate up (`charter.memory` alembic upgraded; see [`memory_bootstrap.md`](../../charter/runbooks/memory_bootstrap.md)).
- F.6 Audit Agent has ingested audit chains for the time window of interest (operator already ran `audit-agent run --contract … --source …`).
- One or more **sibling-agent workspaces** with `findings.json` files (operator pins these via the contract).
- This monorepo checkout with `uv sync` clean.
- Optional: LLM provider configured via `NEXUS_LLM_*` env vars. Without one, D.7 falls back to deterministic hypothesis enumeration (compliance-correctness preserved).

---

## 1. Identify the incident scope

D.7 needs three things from the operator at scope time:

1. **Contract YAML** — names the tenant, correlation_id (delegation_id), task description, and the budget envelope (extended caps: 30 LLM calls, 60k tokens, 600s wall clock).
2. **Sibling workspaces** — paths to other agents' `findings.json` files. Each agent's run produces `<workspace>/findings.json`; D.7 reads each and merges.
3. **Optional time window** — `--since` / `--until` (ISO-8601). Defaults to "all time" if omitted.

Typical incident scope: a supervisor flagged a CRITICAL finding from D.3 Runtime Threat (shell-in-container) and wants to know what else is connected to that container.

---

## 2. Run the investigation

### 2a. Full investigation (Mode B)

```bash
uv run investigation-agent run \
    --contract /workspaces/cust_acme/inc_20260513/contract.yaml \
    --sibling-workspace /workspaces/cust_acme/run_001/runtime_threat \
    --sibling-workspace /workspaces/cust_acme/run_001/cloud_posture \
    --since 2026-05-12T00:00:00Z \
    --until 2026-05-13T23:59:59Z
```

Output to stdout:

```
agent: investigation (v0.1.0)
incident_id: 01J7N5...XYZ
tenant: 01HV0T...TENA
correlation_id: 01J7M3...DBHFZ
confidence: 0.75
hypotheses: 2
timeline events: 8
iocs: 3
mitre techniques: 2
Hypotheses:
  - H-001 (0.85): The IAM key was compromised during the shell-in-container event...
  - H-002 (0.65): The S3 bucket was accessed via the compromised IAM key...
```

Artifacts in `<workspace>/`:

| File                    | Format        | Purpose                                                   |
| ----------------------- | ------------- | --------------------------------------------------------- |
| `incident_report.json`  | OCSF 2005     | Wire shape for Meta-Harness / downstream tools.           |
| `timeline.json`         | Timeline JSON | Sorted event sequence across audit + findings.            |
| `hypotheses.md`         | Markdown      | Operator-readable hypothesis tracking with evidence refs. |
| `containment_plan.yaml` | YAML          | Steps + eradication + recovery-validation criteria.       |

### 2b. Triage (Mode A)

For on-call paging — same pipeline, concise summary:

```bash
uv run investigation-agent triage \
    --contract /workspaces/cust_acme/inc_20260513/contract.yaml \
    --sibling-workspace /workspaces/cust_acme/run_001/runtime_threat
```

Output:

```
Triage summary — incident 01J7N5...XYZ
  tenant: 01HV0T...TENA
  confidence: 0.75
  hypotheses: 2
  timeline events: 8
  top hypothesis: The IAM key was compromised during the shell-in-container event...
```

This is the suitable form for a PagerDuty payload or a Slack alert. The full artifacts are still on disk in the workspace.

---

## 3. Read the four artifacts

### `incident_report.json` (OCSF 2005)

The wire shape every downstream consumer reads. Key fields:

- `class_uid: 2005` (Incident Finding — added in OCSF v1.2)
- `finding_info.uid` — your `incident_id` (ULID)
- `finding_info.confidence_score` — 0-100 derived from mean hypothesis confidence
- `unmapped.timeline` — full timeline array
- `unmapped.hypotheses` — every validated hypothesis with `evidence_refs`
- `unmapped.iocs` — extracted indicators
- `unmapped.mitre_techniques` — ranked ATT&CK mappings
- `unmapped.containment_summary` — human-readable plan summary

### `timeline.json` (Timeline pydantic)

Sorted ascending by `emitted_at`. Each event carries:

- `source` ∈ {`audit`, `finding`, `sub_agent`}
- `actor` (which agent / sub-agent)
- `action`
- `evidence_ref` (links back to source: `audit_event:<hash16>` or `finding:<uid>`)
- `description`

### `hypotheses.md` (Markdown)

Operator-readable. Each hypothesis has its confidence + statement + evidence-ref bullets. **When LLM is unavailable, a banner at the top reads:**

> Note: this report was generated without LLM synthesis. Hypotheses are enumerated from collected findings; an operator should re-run with LLM enabled for richer correlation.

If you see this banner, the artifacts are still compliance-correct — the audit chain, timeline, IOCs, MITRE attribution are all real. Only the _narrative_ hypothesis quality is degraded.

### `containment_plan.yaml`

Three sections:

- `steps`: one per finding, with a class-specific template:
  - 2002 → patch per CVE advisory
  - 2003 → re-run remediation playbook
  - 2004 → quarantine resource pending review
  - 2005 → escalate to IR (recursive — this finding is itself an incident)
  - 6003 → review the API audit record
- `eradication`: list of step actions (derived from steps).
- `recovery_validation`: re-run sibling agents over the affected scope; confirm zero new findings.

---

## 4. Hypothesis validation and the "evidence is sacred" invariant

D.7 enforces an absolute invariant: **every hypothesis's `evidence_refs` must resolve against the collected corpus.** A hypothesis that cites an audit_event or finding that wasn't ingested gets dropped — never makes it to the report.

Two paths trigger validation:

1. **Synthesizer-side validation** (`audit.synthesizer`) — LLM-generated hypotheses get validated immediately. Drops happen with a structlog warning naming the bad ref.
2. **Driver-side re-validation** (Stage 4 VALIDATE) — defence-in-depth against any Phase 1c filtering that might prune findings between Stage 3 and Stage 4.

This invariant is what makes D.7 audit-compliant. Operators reading `hypotheses.md` know that **every statement is backed by a real audit_event or finding** — not a hallucination.

---

## 5. Sub-agent depth + parallel caps

D.7 spawns up to 4 sub-investigations (timeline / ioc_pivot / asset_enum / attribution) in parallel under the orchestrator. The orchestrator enforces:

- **Depth ≤ 3** — a sub-agent can spawn its own sub-sub-agents up to depth 3. v0.1 only spawns at depth 0→1 (one level).
- **Parallel ≤ 5** per batch — a parent can spawn at most 5 children in one `spawn_batch` call.

If you see `SubAgentDepthExceeded` or `SubAgentParallelExceeded` in production logs, something has tried to recursively over-spawn. Both are fail-fast — no workers run, no partial state.

---

## 6. Troubleshooting

| Symptom                                              | Likely cause                                                                | Fix                                                                                               |
| ---------------------------------------------------- | --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `hypotheses.md` has the LLM-unavailable banner       | `llm_provider=None` reached the synthesizer.                                | Set `NEXUS_LLM_*` env vars; re-run.                                                               |
| Hypothesis count is 0 but findings are present       | LLM emitted only hallucinated refs (all dropped); fallback also produced 0. | Check structlog warnings for "dropping hypothesis"; re-run with better prompt or different model. |
| `IncidentReport.timeline.events` is empty            | No audit events in the window AND no sibling findings.                      | Widen `--since` / `--until`; verify `--sibling-workspace` paths.                                  |
| `containment_plan.yaml` `steps` is empty             | No sibling findings ingested — investigation ran on audit-only.             | Verify `--sibling-workspace` paths point at directories with `findings.json`.                     |
| Run fails with `SubAgentDepthExceeded` or `Parallel` | An upstream caller (Phase 1c Supervisor?) tried to spawn D.7 from too deep. | Reduce the recursion depth in the caller.                                                         |
| Exit code 1 with `Source not found` (run subcommand) | `--sibling-workspace` path doesn't exist.                                   | Verify the operator's path and re-run.                                                            |

---

## 7. Production deployment notes

- **Substrate prerequisite**: F.5 + F.6 must be up before D.7 runs. The CLI bootstraps a temporary aiosqlite substrate per invocation; production wires through the live Postgres via `MemoryService` + `AuditStore` constructors.
- **LLM cost**: each D.7 run makes ~1 LLM call (the synthesizer). The bundled `max_tokens=2048` ceiling caps cost per call.
- **Wall-clock budget**: 600s (10 minutes) per the agent spec. D.7 is **not** in the v1.3 always-on class — wall-clock overflow raises `BudgetExhausted`.
- **Sub-agent budgets** are NOT proportionally divided in v0.1 (per Q4 of the D.7 plan). Each sub-investigation runs under its own scope but shares the parent's budget envelope. Phase 1c introduces proper budget transfer.

---

## Cross-references

- D.7 plan: [`docs/superpowers/plans/2026-05-13-d-7-investigation-agent.md`](../../../../docs/superpowers/plans/2026-05-13-d-7-investigation-agent.md)
- F.5 bootstrap (prerequisite): [`packages/charter/runbooks/memory_bootstrap.md`](../../charter/runbooks/memory_bootstrap.md)
- F.6 audit query (prerequisite): [`packages/agents/audit/runbooks/audit_query_operator.md`](../../audit/runbooks/audit_query_operator.md)
- ADR-007 (reference NLAH; D.7 is the 6th agent): [`docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md`](../../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)
