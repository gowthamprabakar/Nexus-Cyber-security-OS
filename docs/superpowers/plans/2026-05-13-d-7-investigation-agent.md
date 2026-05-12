# D.7 — Investigation Agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Pause for review after each numbered task.

**Goal:** Ship the **Investigation Agent** (`packages/agents/investigation/`), **Agent #8** per the [glossary](../../_meta/glossary.md) ("Spawns sub-agents using the Orchestrator-Workers pattern, depth ≤ 3, parallel ≤ 5, for forensic analysis"). The first Phase-1b agent and the **first agent to consume the full Phase-1a substrate** end-to-end:

- **F.5 memory engines** — reads the semantic-memory knowledge graph to chain findings into incidents; writes hypotheses into procedural memory for cross-incident pattern detection.
- **F.6 audit query** — queries the audit chain for what happened across the five shipped agents during the investigation window.
- **F.4 control-plane.auth** — runs under a tenant-scoped Charter; sub-agents inherit the tenant context.
- **F.1 charter** — extended budget caps (10 minutes wall clock vs. the 60s default); sub-agent spawning capability.
- **F.2 eval framework** — 10 evaluation cases via the canonical EvalRunner shape.

D.7 is the **first compounding capability** after the substrate: each new detection agent's findings flow through D.7 automatically. Once D.7 ships, every D.4–D.18 agent gains incident-correlation for free.

**Strategic role.** Opens Phase 1b. The substrate is locked; D.7 is the first agent to validate the substrate from the consumer side. Closes the **eval-framework gap** (D.7 is the first agent whose evals depend on other agents' artifacts, exercising the cross-agent reading pattern). Unblocks A.4 Meta-Harness (needs D.7's hypothesis history to score NLAH rewrites), D.12 Curiosity (needs D.7's incident clusters to pick idle-time queries), and any future investigation-as-a-service customer surface.

**Q1 (to resolve up-front).** OCSF class selection. The F.6 plan-correction taught us to verify class_uid against the OCSF v1.3 spec, not the plan's first guess. D.7 emits "incident findings" — a synthesis of multiple agent findings, a timeline, hypotheses, and a remediation plan. Candidate classes:

- **OCSF 2004 Detection Finding** — D.2 + D.3 already use this; D.7's output is a meta-finding over their findings.
- **OCSF 2005 Incident Finding** — purpose-built for incident records (OCSF v1.3 reference).
- **Nexus extension** — none of the OCSF 2000-series classes models the orchestrator-workers' sub-investigation outputs cleanly.

**Resolution: ship under 2004 Detection Finding (matches D.2/D.3) with `finding_info.types[0] = "incident"` as the discriminator.** Two reasons: (1) consistency with existing fabric routing; (2) avoids inventing a Nexus extension when an existing class fits. If OCSF 2005 is the better fit on closer reading (verified during Task 4), the plan amends as it did with F.6 (2007 → 6003).

**Q2 (to resolve up-front).** Sub-agent spawning policy. The charter currently doesn't have a sub-agent primitive — only Investigation and Supervisor are _intended_ to spawn sub-agents per the agent spec, but the runtime charter doesn't enforce or expose that capability. D.7 needs it.

**Resolution: ship the sub-agent primitive as part of D.7 Task 8 in this plan**, with allowlist enforcement (currently one entry: `investigation`). Promote to `charter.subagent` in a future hoist if Supervisor (when it ships) needs the same pattern. This mirrors F.6 v1.3 (always-on agent class): land the new pattern in the consumer first, hoist later if the pattern is duplicated.

**Q3.** Cross-agent finding reads. D.7 reads `findings.json` from sibling-agent workspaces. Three sub-questions: where do siblings' workspaces live? how does D.7 know which agents to read? does charter authorize cross-agent filesystem reads?

**Resolution.**

1. **Workspace discovery** — Charter exposes `ctx.persistent_root / "<agent_id>" / "<delegation_id>"` as the read path. Sibling workspaces live at `ctx.persistent_root.parent / "<sibling_agent>" / "<sibling_delegation>"`. D.7 takes an explicit `sibling_workspaces: tuple[Path, ...]` parameter — no autodiscovery in v0.1; operators pin the relevant siblings via the contract.
2. **Authorization** — the contract's `permitted_tools` includes `find_related_findings`; that tool is allowed to read the listed sibling workspaces. RLS for cross-agent reads is workspace-level, not DB-level.
3. **Schema** — siblings emit `findings.json` per their OCSF schemas. D.7 reads them, deserialises via `OcsfFinding.model_validate_json`, and feeds into the correlation engine.

**Architecture:**

```
ExecutionContract (signed)
        │
        ▼
┌──────────────────────────────────────────────────────────────────┐
│ Investigation Agent driver (Orchestrator)                        │
│                                                                  │
│  Stage 1: SCOPE      — define investigation boundaries            │
│  Stage 2: SPAWN      — create sub-investigations in parallel      │
│                       (TaskGroup, depth ≤ 3, parallel ≤ 5)        │
│  Stage 3: SYNTHESIZE — integrate sub-investigation outputs        │
│  Stage 4: VALIDATE   — cross-check hypotheses against evidence    │
│  Stage 5: PLAN       — containment, eradication, recovery         │
│  Stage 6: HANDOFF    — emit `incident_report.json`               │
└─────────┬────────────────────────────────────────────────────────┘
          │ spawn_sub_investigation(kind=...)
          ▼
┌──────────────────────────────────────────────────────────────────┐
│ Sub-investigations (4 flavors)                                   │
│  • timeline         — reconstruct event sequence                  │
│  • ioc_pivot        — extract and pivot indicators                │
│  • asset_enum       — enumerate affected resources                │
│  • attribution      — map to known threat actors                  │
│                                                                  │
│ Each sub-agent runs under its own Charter, narrower scope, 5-min  │
│ wall clock, parallel by default, results merged at Stage 3.      │
└──────────────────────────────────────────────────────────────────┘
          │
          ▼
┌──────────────────────────────────────────────────────────────────┐
│ Tools (per-stage)                                                │
│  audit_trail_query     ─→ F.6 AuditStore.query                    │
│  memory_neighbors_walk ─→ F.5 SemanticStore.neighbors (BFS ≤ 3)   │
│  find_related_findings ─→ read findings.json from siblings       │
│  extract_iocs          ─→ regex + heuristic IOC extraction       │
│  map_to_mitre          ─→ bundled tactics+techniques table       │
│  reconstruct_timeline  ─→ deterministic event sorter             │
│  synthesize_report     ─→ charter.llm_adapter (hypothesis gen)   │
└──────────────────────────────────────────────────────────────────┘
```

**Tech stack:** Python 3.12 · BSL 1.1 (per-agent licensing per ADR-001) · OCSF v1.3 Detection Finding (`class_uid 2004`, `types[0]="incident"`; subject to verification at Task 4) · pydantic 2.9 · click 8 · `charter.llm_adapter` (ADR-007 v1.1) · `charter.nlah_loader` (ADR-007 v1.2) · `charter.memory.SemanticStore` (F.5) · F.6 `AuditStore`.

**Depends on:**

- F.1 charter — extended budget caps for sub-agent flows; sub-agent primitive landed in Task 8.
- F.4 control-plane — tenant context propagates through sub-agent spawning.
- F.5 memory engines — `SemanticStore` for entity-relationship traversal; `ProceduralStore` for hypothesis persistence.
- F.6 Audit Agent — `AuditStore` for cross-agent action history.
- D.1 + D.2 + D.3 + F.3 — D.7 reads their findings.json artifacts.
- ADR-007 v1.1 + v1.2 + v1.3 — reference NLAH template. D.7 is the **sixth** agent under it.

**Defers (Phase 1c / Phase 2):**

- **Threat-intel APIs** (VirusTotal, OTX, internal feeds) — Phase 1c. v0.1 uses bundled static intel only.
- **Forensic snapshot infrastructure** (memory dump, disk image) — Phase 2. v0.1 reads only what's already in workspaces.
- **Cross-tenant investigations** (Phase 2; v0.1 is tenant-scoped per F.5 RLS).
- **Real-time triage** (event-driven invocation by supervisor) — Phase 1c. v0.1 is run-on-demand.
- **Sub-agent budget transfer markup** (the spec's "max_sub_agents: 4" with proportional budget split) — Phase 1c. v0.1 caps parallel sub-agents at 4 but doesn't divide budgets.

**Reference template:** F.6 Audit Agent (most recent ADR-007-conformant agent). D.7 is structurally F.6 with: (a) `class_uid 2004` instead of 6003; (b) **NEW: sub-agent spawning** (Task 8, Q2 resolution); (c) extended budget caps (`wall_clock_sec` raised to 600); (d) cross-agent filesystem reads (Q3 resolution); (e) LLM use is load-bearing (hypothesis generation); (f) consumes both F.5 + F.6 stores (first such consumer).

---

## Execution status

```
1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12 → 13 → 14 → 15 → 16
```

| Task | Status     | Commit    | Notes                                                                                                                                                                                                                                                                  |
| ---- | ---------- | --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | ✅ done    | `b5bf875` | Bootstrap — pyproject (BSL 1.1, depends on `nexus-audit-agent`), entry-point, README. 8-test smoke gate covers ADR-007 v1.1/v1.2 + F.5/F.6 imports + anti-pattern guard. Repo-wide 1176 passed / 11 skipped.                                                           |
| 2    | ✅ done    | `e56b332` | OCSF schemas — 6 pydantic models. **Plan-corrected Q1**: class_uid 2004→2005 (Incident Finding exists in OCSF v1.3, mirrors F.6's 2007→6003 correction). 38 tests; mypy strict clean (122 source files); repo-wide 1214 passed / 11 skipped.                           |
| 3    | ✅ done    | `4a5c154` | `audit_trail_query(*, audit_store, tenant_id, since, until, ...)` async wrapper around F.6 `AuditStore.query`. 500-event default cap for sub-agent fan-out memory bounding. 8 tests; repo-wide 1222 passed / 11 skipped.                                               |
| 4    | ✅ done    | `e6dd0c5` | `memory_neighbors_walk(*, semantic_store, tenant_id, entity_id, depth, edge_types)` async wrapper around F.5 `SemanticStore.neighbors`. Depth cap pass-through (F.5's `MAX_TRAVERSAL_DEPTH = 3`). 8 tests. Repo-wide 1230 passed / 11 skipped.                         |
| 5    | ✅ done    | `f8f0055` | `find_related_findings(sibling_workspaces)` async cross-agent reader. Returns `tuple[RelatedFinding, ...]` carrying source_agent / source_run_id / class_uid / payload. Forgiving on every failure mode. 8 tests. Repo-wide 1238 passed / 11 skipped.                  |
| 6    | ✅ done    | `e045a81` | `extract_iocs(content)` regex+heuristic IOC extractor. 9 IOC types; URL→domain suppression; loopback/zero IPv4 drop; hash-length discrimination; CVE uppercase strictness; nested-structure walk. 15 tests. Repo-wide 1253 passed / 11 skipped.                        |
| 7    | ⬜ pending | —         | `map_to_mitre(evidence)` — bundled MITRE ATT&CK 14.x table; returns ranked `tuple[MitreTechnique, ...]`. Heuristic in v0.1; ML mapping deferred to Phase 1c.                                                                                                           |
| 8    | ⬜ pending | —         | **Sub-agent orchestrator** — `spawn_sub_investigation(scope, kind)` returns a `TaskGroup`-backed handle. Enforces depth ≤ 3, parallel ≤ 5. **Q2 resolution.** Allowlist for which agents can spawn sub-agents (one entry in v0.1: `investigation`).                    |
| 9    | ⬜ pending | —         | `reconstruct_timeline(events)` deterministic sorter — merges audit events + findings + IOC pivots into a single `Timeline` keyed by emitted_at. Tolerant of missing timestamps (drops with warning).                                                                   |
| 10   | ⬜ pending | —         | NLAH bundle + 25-LOC shim per ADR-007 v1.2. NLAH text covers the 6-stage pipeline + sub-agent spawning policy + hypothesis-generation phrasing.                                                                                                                        |
| 11   | ⬜ pending | —         | Charter `llm_adapter` consumption per ADR-007 v1.1. LLM use is **load-bearing** in D.7 (first agent for which this is true): hypothesis generation + synthesis. Falls back to template-only output when LLM unavailable.                                               |
| 12   | ⬜ pending | —         | Agent driver `run()` — implements 6-stage pipeline (SCOPE → SPAWN → SYNTHESIZE → VALIDATE → PLAN → HANDOFF). Writes `incident_report.json` + `timeline.json` + `hypotheses.md` + `containment_plan.yaml` to workspace.                                                 |
| 13   | ⬜ pending | —         | 10 representative YAML eval cases: triage-only / deep-investigation / hypothesis-confirmed / hypothesis-contradicted / cross-agent merge / IOC pivot / asset enumeration / attribution lookup / sub-agent budget overrun / evidence preservation                       |
| 14   | ⬜ pending | —         | `InvestigationEvalRunner` + entry-point + 10/10 acceptance via `eval-framework run --runner investigation`                                                                                                                                                             |
| 15   | ⬜ pending | —         | CLI (`investigation-agent eval` / `investigation-agent run` / `investigation-agent triage`). The `triage` subcommand exposes the Mode-A fast-path for operators.                                                                                                       |
| 16   | ⬜ pending | —         | README + operator runbook (`runbooks/investigation_workflow.md`). ADR-007 amendment (if surfaced — likely **v1.4** for the sub-agent spawning primitive if pattern duplicates in Supervisor's plan). Final verification record `docs/_meta/d7-verification-<date>.md`. |

ADR references: [ADR-001](../../_meta/decisions/ADR-001-monorepo-bootstrap.md) · [ADR-002](../../_meta/decisions/ADR-002-charter-as-context-manager.md) · [ADR-004](../../_meta/decisions/ADR-004-fabric-layer.md) · [ADR-005](../../_meta/decisions/ADR-005-async-tool-wrapper-convention.md) · [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) · [ADR-008](../../_meta/decisions/ADR-008-eval-framework.md) · [ADR-009](../../_meta/decisions/ADR-009-memory-architecture.md) · [potential **ADR-007 v1.4**](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) — sub-agent spawning primitive, evaluated at Task 16.

---

## Resolved questions

| #   | Question                                                                    | Resolution                                                                                                                                                                                                                                                                                              | Task       |
| --- | --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| Q1  | Which OCSF class_uid for incident findings?                                 | **2004 Detection Finding** with `types[0]="incident"` as discriminator. F.6's plan-correction taught us to verify; if 2005 (Incident Finding) is more accurate on close OCSF v1.3 reading at Task 4, amend the plan there.                                                                              | Task 4     |
| Q2  | How does sub-agent spawning work? Charter has no primitive today.           | **Land the sub-agent primitive in D.7 Task 8** with allowlist enforcement (1 entry: `investigation`). Promote to `charter.subagent` in an ADR-007 v1.4 amendment if Supervisor (whenever it ships) needs the same pattern. Mirrors F.6's v1.3 pattern: land in consumer first, hoist on duplication.    | Task 8, 16 |
| Q3  | How does D.7 read findings.json from sibling agents?                        | Operator pins `sibling_workspaces: tuple[Path, ...]` in the contract; `find_related_findings` reads each path and deserialises via shared OCSF schemas. No autodiscovery in v0.1.                                                                                                                       | Task 5     |
| Q4  | Sub-agent budget allocation?                                                | v0.1 caps parallel sub-agents at 4 (per agent spec) but doesn't divide budgets — each sub-agent gets its own `BudgetSpec` with its own caps. Phase 1c adds proportional budget transfer.                                                                                                                | Task 8     |
| Q5  | What if LLM is unavailable? D.7's LLM use is load-bearing (hypothesis gen). | Template-only fallback — D.7 still emits an incident report with a deterministic "evidence enumeration" instead of LLM-generated hypotheses. Operator sees the bare evidence; they can re-run with the LLM later. NL-summary is a UX nicety, not load-bearing for compliance correctness.               | Task 11    |
| Q6  | Evidence preservation — what counts as evidence?                            | v0.1 preserves: the sibling findings.json files (copied to `<workspace>/evidence/<source>_findings.json`), the audit chain (queried at investigation time, snapshot to `<workspace>/evidence/audit_snapshot.jsonl`), and the workspace's own audit log. Memory dumps / disk images deferred to Phase 2. | Task 12    |

---

## File map (target)

```
packages/agents/investigation/
├── pyproject.toml                                # Task 1
├── README.md                                     # Tasks 1, 16
├── runbooks/
│   └── investigation_workflow.md                 # Task 16
├── src/investigation/
│   ├── __init__.py                               # Task 1
│   ├── py.typed                                  # Task 1
│   ├── schemas.py                                # Task 2 (OCSF 2004 + incident discriminator)
│   ├── nlah_loader.py                            # Task 10 (25-LOC shim)
│   ├── orchestrator.py                           # Task 8 (sub-agent spawning + allowlist)
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── audit_trail.py                        # Task 3
│   │   ├── memory_walk.py                        # Task 4
│   │   ├── related_findings.py                   # Task 5
│   │   ├── ioc_extractor.py                      # Task 6
│   │   └── mitre_mapper.py                       # Task 7 (incl. bundled ATT&CK table)
│   ├── timeline.py                               # Task 9
│   ├── synthesizer.py                            # Task 11 (charter.llm_adapter consumer)
│   ├── agent.py                                  # Task 12 (driver: 6-stage pipeline)
│   ├── eval_runner.py                            # Task 14
│   └── cli.py                                    # Task 15
├── nlah/
│   ├── README.md                                 # Task 10
│   ├── tools.md                                  # Task 10
│   └── examples/                                 # Task 10 (2 examples: triage + deep-investigation)
├── data/
│   └── mitre_attack_14.json                      # Task 7 (bundled ATT&CK tactics+techniques)
├── eval/
│   └── cases/                                    # Task 13 (10 YAML cases)
└── tests/
    ├── test_pyproject.py                         # Task 1
    ├── test_schemas.py                           # Task 2
    ├── test_tools_audit_trail.py                 # Task 3
    ├── test_tools_memory_walk.py                 # Task 4
    ├── test_tools_related_findings.py            # Task 5
    ├── test_tools_ioc_extractor.py               # Task 6
    ├── test_tools_mitre_mapper.py                # Task 7
    ├── test_orchestrator.py                      # Task 8 (depth + parallel caps; allowlist)
    ├── test_timeline.py                          # Task 9
    ├── test_nlah_loader.py                       # Task 10
    ├── test_synthesizer.py                       # Task 11
    ├── test_agent.py                             # Task 12 (6-stage pipeline)
    ├── test_eval_runner.py                       # Task 14 (incl. 10/10 acceptance)
    └── test_cli.py                               # Task 15
```

---

## Risks

| Risk                                                                                                                                      | Mitigation                                                                                                                                                                                                                                                                                             |
| ----------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Sub-agent spawning amplifies budget consumption — a runaway investigation could spawn 5 × 4 × 3 = 60 sub-runs.                            | Hard cap at depth 3 + parallel 5 (per spec); enforced in `orchestrator.spawn_sub_investigation` with a runtime check. Plus `wall_clock_sec` 600s cap on the parent driver — the always-on policy from F.6 v1.3 does NOT apply to D.7 (it's not in the always-on allowlist).                            |
| LLM hallucinations in hypothesis generation could fabricate evidence that doesn't exist.                                                  | Hypothesis JSON shape requires `evidence_refs: tuple[str, ...]` pointing at audit_event_id / finding_id values. Synthesizer validates that every ref resolves before writing the hypothesis. Unresolved refs → hypothesis dropped + warning logged.                                                    |
| Cross-agent filesystem reads could leak sibling-agent state if `sibling_workspaces` includes paths the operator shouldn't have access to. | Contract-level whitelist: `find_related_findings` only reads paths listed in `contract.persistent_root.glob`. RBAC enforcement is the operator's responsibility; v0.1 trusts the contract. Phase 1c adds Postgres-backed cross-agent reads via an `agent_findings` table (replacing filesystem reads). |
| OCSF class choice locks in too early; F.6 had to plan-correct 2007→6003.                                                                  | Verify at Task 4 against the OCSF v1.3 spec. If 2005 (Incident Finding) is more accurate, amend the plan + schemas before they're consumed by downstream tasks.                                                                                                                                        |
| Sub-agent primitive (Task 8) creates lock-in if Supervisor needs a different shape.                                                       | Allowlist-based (one entry in v0.1); promote to `charter.subagent` in ADR-007 v1.4 only when the third duplicate appears. Task 16 evaluates whether Supervisor's needs (from the agent spec) match — if yes, hoist; if no, keep local.                                                                 |

---

## Done definition

D.7 is **done** when:

- 16/16 tasks closed; every commit pinned in the execution-status table.
- ≥ 80% test coverage on `packages/agents/investigation` (gate same as D.3 / F.6).
- `ruff check` + `ruff format --check` + `mypy --strict` clean.
- `eval-framework run --runner investigation` returns 10/10.
- ADR-007 v1.1 + v1.2 + (if applicable) v1.4 conformance verified end-to-end.
- README + runbook reviewed.
- D.7 verification record committed.

That closes the first Phase-1b agent and validates the substrate from the consumer side. D.4 (Network Threat) and D.5–D.6 (CSPM extensions) follow at a faster cadence — they're pure pattern application against the now-validated substrate + D.7's incident-correlation contract.

---

## Next plans queued (for context)

- **D.4 Network Threat Agent** — CWPP cross-confirmation (pcap / Suricata / Zeek). Mirrors D.3's three-feed pattern. Likely ships at the D.3 cadence (~16 tasks, ~3 weeks calendar).
- **D.5 CSPM extension #1** — multi-cloud (Azure + GCP beyond F.3's AWS-focus). Pure pattern application.
- **D.6 CSPM extension #2** — Kubernetes posture (CIS-bench + Polaris). Pure pattern application.

D.7 → D.4 → D.5 → D.6 covers all of Phase 1b detection. Phase 1c brings A.1–A.3 remediation + A.4 Meta-Harness + streaming ingest.
