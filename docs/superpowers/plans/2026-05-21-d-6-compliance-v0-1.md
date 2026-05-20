# D.6 — Compliance Agent v0.1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Pause for review after each numbered task.

**Goal:** Ship the **Compliance Agent** (`packages/agents/compliance/`) — the **third of the 7 unbuilt agents** under the [Path-B-breadth-first operating rule](../sketches/2026-05-20-agent-version-roadmaps.md) (2026-05-20) and the **thirteenth under [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)** (F.3 / D.1 / D.2 / D.3 / F.6 / D.7 / D.4 / multi-cloud-posture / k8s-posture / A.1 / D.5 / D.8 / **D.6**). Maps sibling-agent findings to compliance-framework controls (CIS AWS Foundations v3) and emits framework-level compliance findings + a posture-summary report.

**Scope (v0.1, locked per Path-B-breadth-first rule + sketch §2).** One framework: **CIS AWS Foundations Benchmark v3.0** (~50 controls; paraphrased per Q6 licence posture). Two sibling sources: **F.3 Cloud Posture** + **D.5 Data Security** workspaces (read-only, operator-pinned via flags). One charter substrate touch: zero. OCSF v1.3 Compliance Finding (`class_uid 2003`) — re-exported from `cloud_posture.schemas` per Q1 — with `finding_info.types[0]="compliance_cis_aws_v3_<control_id>"` discriminator. Deterministic (no LLM in loop). v0.1 ships eval-only; live-lane CI deferred to v0.2.

**Strategic role.** Third agent in the breadth-first cadence. Closes the **compliance-aggregation loop**: F.3 + D.5 produce per-resource findings; D.6 aggregates them by control and reports posture against an external standard. The cross-agent aggregation pattern is **read-only** — D.6 reads sibling workspaces, never writes back. Mirrors D.8 Threat Intel's sibling-workspace pattern + F.3 Cloud Posture's 2003 emission shape. **No charter-level substrate work expected** — bundled YAML control library + agent-local correlators + agent-local aggregator.

**Q1 (resolve up-front).** OCSF class — extend a new compliance type or reuse F.3's 2003?

**Resolution: re-export `class_uid 2003 Compliance Finding`** from `cloud_posture.schemas`. D.6 is the **3rd re-exporter of F.3's 2003 schema** (F.3 itself = 1st; D.5 + multi-cloud-posture + k8s-posture = 2nd-4th producers; D.6 = 5th). The compliance-finding shape carries `finding_info.types[0]` as the control discriminator — perfect fit for `compliance_cis_aws_v3_1_1`-shape strings. D.6 inherits `Severity`, `AffectedResource`, `build_finding`, `FindingsReport` verbatim. Adds `ComplianceFindingType` (one per CIS control) + `ControlMapping` (CIS-Level → Severity table).

**Q2 (resolve up-front).** Which compliance framework(s) in v0.1?

**Resolution: CIS AWS Foundations Benchmark v3.0 only.** ~50 paraphrased controls bundled as YAML in `control_libraries/cis_aws_v3.yaml`. Tight scope: covers IAM, S3, CloudTrail, EC2, RDS, VPC — the controls F.3 + D.5 actually evaluate. **v0.2:** SOC2, PCI-DSS v4.0, HIPAA Security Rule, NIST 800-53 Rev. 5 (one per minor version). Single framework keeps the eval surface tight and lets v0.2 prove the multi-framework dispatch shape.

**Q3 (resolve up-front).** Sibling-source read pattern — F.6 audit-chain or sibling-workspace `findings.json`?

**Resolution: sibling-workspace `findings.json`** (matches D.8 + D.7 pattern). Two operator-pinned flags: `--cloud-posture-workspace` (F.3 output) + `--data-security-workspace` (D.5 output). Each independent; missing flag means that source contributes zero control evaluations. Forgiving on every failure (missing workspace / malformed JSON / non-2003 entries dropped silently, with a one-line warning). F.6 audit-chain live read deferred to v0.2 along with `findings.>` fabric-event subscription.

**Q4 (resolve up-front).** Per-control PASS/FAIL roll-up shape — emit one finding per source-finding, or one finding per control?

**Resolution: one finding per (control, customer_account, status-change) tuple.** For each CIS control with at least one source-finding mapping to it, D.6 emits a single `ComplianceFinding` whose `evidence` block carries the list of contributing source-finding IDs. Status = FAIL if any contributing source-finding has severity ≥ MEDIUM; PASS otherwise (and the finding is omitted from `findings.json` by default — only failed controls land in the report). v0.2 adds PASS findings for compliance-attestation export.

**Q5 (resolve up-front).** Tenancy — single-tenant or multi-tenant in v0.1?

**Resolution: single-tenant (`semantic_store=None` opt-in default).** Per the Path-B operating rule §11.1: SET LOCAL `$1` tenant-RLS bug NOT a v0.1 blocker. D.6 v0.1 writes finding-artifacts to the workspace filesystem; SemanticStore writes only when an explicit instance is passed. Multi-tenant production blocks on the future tenant-RLS substrate-fix plan.

**Q6 (resolve up-front).** Framework-content licensing posture?

**Resolution.** CIS Benchmarks distribution: **CIS Securesuite licence restricts redistribution of verbatim benchmark text**. v0.1 ships **paraphrased control names + control IDs only** — no verbatim CIS text. `report.md` carries a CIS attribution footer naming "CIS Benchmarks®, © Center for Internet Security" with a pointer to the canonical source (`https://www.cisecurity.org/cis-benchmarks/`). Per-control descriptions in the bundled YAML are operator-readable summaries written in-house from public CIS metadata (control ID, level, applicability) — not lifted text. Q6 reminder for downstream: no PII, no classifier-matched substrings.

**No commercial-feed entanglement; no API keys; no per-customer credential management.** Operator stages no external files (the framework library is bundled). Sibling workspaces are pre-existing F.3 + D.5 outputs. v0.2 introduces additional frameworks under the same bundled-YAML pattern; v0.3+ adds vendor-specific dashboards which bring their own licence ADRs.

---

## Architecture

```
ExecutionContract (signed)
        │
        ▼
┌──────────────────────────────────────────────────────────────────┐
│ Compliance Agent driver                                          │
│                                                                  │
│  Stage 1: INGEST     — load bundled CIS YAML (sync, fast)        │
│  Stage 2: ENRICH     — build control index keyed by control_id   │
│  Stage 3: CORRELATE  — 2 correlators concurrent via TaskGroup    │
│  Stage 4: AGGREGATE  — per-control PASS/FAIL roll-up             │
│  Stage 5: SCORE      — CIS Level → Severity canonicalization     │
│  Stage 6: SUMMARIZE  — posture markdown + CIS attribution footer │
│  Stage 7: HANDOFF    — emit findings.json + report.md to ws      │
└─────────┬────────────────────────────────────────────────────────┘
          │
          ▼
┌──────────────────────────────────────────────────────────────────┐
│ Tools (per-stage)                                                │
│  read_cis_aws_benchmark    ─→ bundled YAML loader (fs, fast)     │
│  read_f3_findings          ─→ F.3 Cloud Posture workspace (opt)  │
│  read_d5_findings          ─→ D.5 Data Security workspace (opt)  │
│  correlate_cloud_posture   ─→ F.3 finding × CIS control          │
│  correlate_data_security   ─→ D.5 finding × CIS control          │
│  aggregate_controls        ─→ per-control PASS/FAIL roll-up      │
│  score_findings            ─→ Level-1/2 severity table           │
│  render_summary            ─→ posture report + attribution       │
└──────────────────────────────────────────────────────────────────┘
```

**Tech stack.** Python 3.12 · BSL 1.1 · OCSF v1.3 Compliance Finding (`class_uid 2003`, `types[0]="compliance_cis_aws_v3_*"` discriminator) · pydantic 2.9 · click 8 · `charter.llm_adapter` (ADR-007 v1.1; plumbed, never called) · `charter.nlah_loader` (ADR-007 v1.2). Re-exports `cloud_posture.schemas` for the OCSF Compliance Finding wire shape. No external network dependencies in v0.1.

**Depends on:** F.3 Cloud Posture (shipped) + D.5 Data Security (shipped, 2026-05-20). D.8 Threat Intel is **not** a v0.1 dep (TTP-based CIS controls are v0.2+).

---

## Execution status

```
1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12 → 13 → 14 → 15 → 16
```

| Task | Status | Commit | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ---- | ------ | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | ⬜     |        | Bootstrap — pyproject (BSL 1.1; deps on charter / shared / eval-framework / **nexus-cloud-posture** for the 2003 re-export per Q1 + **nexus-data-security** for D.5 finding-shape reference + PyYAML for the control library). py.typed + **init**. Smoke tests: ADR-007 v1.1 + v1.2 + 2 anti-pattern guards + 2 entry-point checks + F.3 schema re-export confirmation. ~9 tests.                                                                 |
| 2    | ⬜     |        | `schemas.py` — re-exports F.3's `class_uid 2003 Compliance Finding` verbatim (Q1). Adds `ComplianceFindingType` enum builder (one per CIS control; dynamically constructed from the YAML in Task 3+4) + `ControlMapping` (CIS Level 1/2 → Severity) + `COMPLIANCE_FINDING_ID_RE` (validates `COMPLIANCE-CIS_AWS_V3-<control_id>-NNN-<context>`). ~25 tests.                                                                                        |
| 3    | ⬜     |        | `tools/cis_aws_benchmark.py` — async YAML loader; `CisControl` pydantic model (control_id, name, level, applicability, paraphrased description). Per ADR-005, filesystem read on `asyncio.to_thread`. Forgiving on malformed entries; raises on missing/unparseable top-level YAML. ~12 tests.                                                                                                                                                     |
| 4    | ⬜     |        | `control_libraries/cis_aws_v3.yaml` — paraphrased ~50 CIS AWS Foundations v3.0 controls bundled as data. Test in Task 3's file asserts loadability + count + every control has a non-empty paraphrased description. Q6 verified: no verbatim CIS text.                                                                                                                                                                                             |
| 5    | ⬜     |        | `entities.py` (ControlEntity / FrameworkEntity pydantic models) + `kg_writer.py` (SemanticStore upsert pattern from F.3 v0.1.5). Single-tenant `semantic_store=None` opt-in default. ~18 tests.                                                                                                                                                                                                                                                    |
| 6    | ⬜     |        | `correlators/cloud_posture_correlator.py` — reads F.3 Cloud Posture findings from operator-pinned `--cloud-posture-workspace`. Maps each F.3 finding to one-or-more CIS control IDs via the control library's `applicability` mapping. Emits per-mapping ComplianceFinding (status carried at this stage; aggregator collapses in Task 8). ~14 tests.                                                                                              |
| 7    | ⬜     |        | `correlators/data_security_correlator.py` — reads D.5 Data Security findings. Maps each D.5 finding (public_bucket / unencrypted / etc.) to CIS controls (e.g., CIS-2.1.1, CIS-2.1.2). Same per-mapping emit shape. ~12 tests.                                                                                                                                                                                                                     |
| 8    | ⬜     |        | `aggregator.py` — per-control PASS/FAIL roll-up across all correlator outputs. Per Q4: status = FAIL if any contributing source-finding has severity ≥ MEDIUM. Carries contributing source-finding IDs in evidence. PASS controls omitted in v0.1 (FAIL-only output). ~12 tests.                                                                                                                                                                   |
| 9    | ⬜     |        | `scorer.py` — deterministic table-driven severity. CIS Level 1 + required → HIGH; CIS Level 1 + recommended → MEDIUM; CIS Level 2 + required → MEDIUM; CIS Level 2 + recommended → LOW. Source-finding severity propagated as a tie-breaker. ~10 tests.                                                                                                                                                                                            |
| 10   | ⬜     |        | `summarizer.py` — deterministic markdown render. CIS-Level-1 failures pinned above per-severity sections. Includes CIS Benchmarks® attribution footer per Q6. Includes pointer to canonical CIS source URL. ~14 tests covering: empty findings (still emits attribution), Level-1 pinned, posture-summary table (% controls passing).                                                                                                              |
| 11   | ⬜     |        | Agent driver `run()` — 7-stage pipeline (INGEST → ENRICH → CORRELATE → AGGREGATE → SCORE → SUMMARIZE → HANDOFF). 1-feed sync ingest + 2-correlator TaskGroup fan-out. `(contract, *, llm_provider, ...)` signature. 13th agent under ADR-007. ~15 driver tests.                                                                                                                                                                                    |
| 12   | ⬜     |        | NLAH bundle + 21-LOC shim. ADR-007 v1.2 conformance — D.6 is the 9th agent shipped natively against v1.2 (after D.3 / F.6 / D.7 / D.4 / multi-cloud-posture / k8s-posture / D.5 / D.8). README ("Compliance officer persona") + tools.md + 3 examples (CIS-IAM-FAIL, CIS-S3-PUBLIC-FAIL, multi-source-control). LOC-budget test enforces ≤35. ~13 tests.                                                                                           |
| 13   | ⬜     |        | 10 representative YAML eval cases + `ComplianceEvalRunner` registered via `nexus_eval_runners`. **10/10 acceptance** green via `uv run eval-framework run --runner compliance --cases ... --output ...`. Cases: clean / single-CIS-FAIL / multi-source-roll-up / Level-1-pinning / partial-workspace / no-source-workspaces / malformed-source-tolerated / cis-attribution-in-output / severity-canonicalization / multi-control-from-one-finding. |
| 14   | ⬜     |        | CLI (`compliance eval` / `compliance run`) — two subcommands; two optional sibling-workspace flags (`--cloud-posture-workspace` / `--data-security-workspace`). One-line digest; warning on no-source. ~13 CLI tests.                                                                                                                                                                                                                              |
| 15   | ⬜     |        | README polish + smoke runbook (CIS audit workflow, ~6 sections) + paraphrase verification (no verbatim CIS text in shipped YAML). ~5 README sections.                                                                                                                                                                                                                                                                                              |
| 16   | ⬜     |        | Verification record (`docs/_meta/d-6-compliance-v0-1-verification-2026-05-21.md`) — 16-task execution-status table, gate results, 10/10 eval acceptance, Q6 CIS-attribution verification at unit/render/CLI layers, WI-1 through WI-3 resolutions, Path-B sequence advance (13/17 agents at v0.1; next is **D.13 Synthesis**). **D.6 v0.1 done; third of 7 unbuilt agents shipped under Path-B operating rule.**                                   |

ADR references: [ADR-001](../../_meta/decisions/ADR-001-monorepo-bootstrap.md) · [ADR-004](../../_meta/decisions/ADR-004-fabric-layer.md) · [ADR-005](../../_meta/decisions/ADR-005-async-tool-wrapper-convention.md) · [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) · [ADR-008](../../_meta/decisions/ADR-008-eval-framework.md) · [ADR-009](../../_meta/decisions/ADR-009-memory-architecture.md) · [ADR-011](../../_meta/decisions/ADR-011-pr-flow-and-branch-protection-discipline.md).

---

## Resolved questions

| #   | Question                     | Resolution                                                                                                                                                                        | Task          |
| --- | ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------- |
| Q1  | OCSF class?                  | **Re-export F.3's `class_uid 2003` Compliance Finding** with `types[0]="compliance_cis_aws_v3_*"` discriminator. 3rd schema-reuse precedent (after D.5 + D.8).                    | Task 2        |
| Q2  | Which framework(s) in v0.1?  | **CIS AWS Foundations Benchmark v3.0 only.** ~50 paraphrased controls. SOC2 / PCI / HIPAA / NIST → v0.2.                                                                          | Tasks 3-4     |
| Q3  | Cross-source read pattern?   | **Sibling-workspace `findings.json`** (matches D.8 / D.7). F.6 audit-chain live read deferred to v0.2.                                                                            | Tasks 6-7, 11 |
| Q4  | PASS/FAIL roll-up shape?     | **One finding per (control, status-change) tuple.** FAIL if any source-finding ≥ MEDIUM; PASS omitted in v0.1 output (added v0.2 for attestation export).                         | Task 8        |
| Q5  | Tenancy in v0.1?             | **Single-tenant** (`semantic_store=None` opt-in default). Multi-tenant blocks on SET LOCAL `$1` fix.                                                                              | Task 11       |
| Q6  | Framework-content licensing? | **CIS Securesuite licence restricts redistribution of verbatim text.** v0.1 ships paraphrased control names + IDs only. Attribution footer + canonical-source URL in `report.md`. | Tasks 4, 10   |

---

## File map (target)

```
packages/agents/compliance/
├── pyproject.toml                              # Task 1
├── README.md                                   # Tasks 1, 15
├── src/compliance/
│   ├── __init__.py                             # Task 1
│   ├── py.typed                                # Task 1
│   ├── schemas.py                              # Task 2 (F.3 re-exports + ComplianceFindingType + ControlMapping)
│   ├── nlah_loader.py                          # Task 12 (21-LOC shim)
│   ├── entities.py                             # Task 5 (ControlEntity / FrameworkEntity)
│   ├── kg_writer.py                            # Task 5 (SemanticStore upsert adapter)
│   ├── tools/
│   │   ├── __init__.py
│   │   └── cis_aws_benchmark.py                # Task 3
│   ├── control_libraries/
│   │   ├── __init__.py
│   │   └── cis_aws_v3.yaml                     # Task 4 (~50 paraphrased controls)
│   ├── correlators/
│   │   ├── __init__.py
│   │   ├── cloud_posture_correlator.py         # Task 6
│   │   └── data_security_correlator.py         # Task 7
│   ├── aggregator.py                           # Task 8
│   ├── scorer.py                               # Task 9
│   ├── summarizer.py                           # Task 10
│   ├── agent.py                                # Task 11 (driver: 7-stage pipeline)
│   ├── nlah/
│   │   ├── README.md                           # Task 12 (Compliance officer persona)
│   │   ├── tools.md                            # Task 12
│   │   └── examples/                           # Task 12 (3 examples)
│   ├── eval_runner.py                          # Task 13
│   └── cli.py                                  # Task 14
├── eval/cases/                                 # Task 13 (10 YAML cases)
└── tests/
    ├── test_smoke.py                           # Task 1
    ├── test_schemas.py                         # Task 2
    ├── test_tools_cis_aws_benchmark.py         # Task 3 (incl. YAML loadability)
    ├── test_entities.py                        # Task 5
    ├── test_kg_writer.py                       # Task 5
    ├── test_correlators_cloud_posture.py       # Task 6
    ├── test_correlators_data_security.py       # Task 7
    ├── test_aggregator.py                      # Task 8
    ├── test_scorer.py                          # Task 9
    ├── test_summarizer.py                      # Task 10
    ├── test_agent_unit.py                      # Task 11
    ├── test_nlah_loader.py                     # Task 12
    ├── test_eval_runner.py                     # Task 13 (incl. 10/10 acceptance)
    └── test_cli.py                             # Task 14
```

---

## Risks

| Risk                                                                                                                                                              | Mitigation                                                                                                                                                                                                                                                                                      |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Schema re-export from F.3 couples D.6 to F.3's `class_uid 2003` shape.                                                                                            | Acceptable — Compliance Finding shape is stable v0.1 and proven across 4 producers (F.3 / D.5 / multi-cloud-posture / k8s-posture). D.6 is the 5th producer; well-trodden ground.                                                                                                               |
| CIS Benchmarks licence restricts verbatim redistribution; a careless YAML entry could leak protected text.                                                        | Task 4's YAML is paraphrased in-house from public control-ID metadata. Task 15 includes an explicit paraphrase-verification step. Q6 attribution footer in every `report.md` per Task 10 (regression probe: eval case 008 `cis_attribution_in_output`).                                         |
| 1 framework × 2 correlators = smaller v0.1 surface than D.8 (3 feeds × 3 correlators).                                                                            | Acceptable — tight scope by design. v0.2's multi-framework dispatch is a clean lift since the framework loader + control-index pattern is already in place.                                                                                                                                     |
| Sibling-workspace reads (F.3 / D.5) couple D.6 to those agents' OCSF output shapes; if F.3 or D.5 changes `class_uid 2003` evidence shape, D.6 silently degrades. | Per-correlator validation: read sibling findings as raw dicts; validate the minimal fields D.6 cares about (resource_id, control mapping hints). On validation failure, drop the entry silently + log a one-line warning. Eval case 005 (`partial_workspace_presence`) is the regression probe. |
| Per-control PASS/FAIL roll-up has a subtle ordering issue: if source-finding A flips status from FAIL to PASS while B stays FAIL, status must stay FAIL.          | Aggregator is order-independent — uses `any(severity >= MEDIUM)` over all contributing source-findings per control. Eval case 003 (`multi_source_rollup`) is the regression probe.                                                                                                              |
| SemanticStore writes (Task 5) introduce a multi-tenant code path that exercises the SET LOCAL `$1` bug.                                                           | v0.1 ships `semantic_store=None` opt-in default. Multi-tenant production blocks on future tenant-RLS substrate-fix plan. v0.1 single-tenant in-memory `aiosqlite` is supported for testing only.                                                                                                |
| CIS Benchmark v3.0 controls overlap; one F.3 finding may map to multiple CIS controls.                                                                            | The control library's `applicability` mapping is a list of control IDs; aggregator naturally handles multi-mapping. Eval case 010 (`multi_control_from_one_finding`) is the regression probe.                                                                                                   |

---

## Watch-items (carry-forward to verification record)

- **WI-1: Substrate sealed.** No changes to `packages/charter/`, `packages/shared/`, `packages/eval-framework/`. Empty-diff proof at close per sketch §8 invariant 1.
- **WI-2: CIS Benchmarks licence compliance.** Task 4's YAML is paraphrased; Task 10 emits the attribution footer unconditionally; Task 15 explicitly verifies no verbatim CIS text in `control_libraries/cis_aws_v3.yaml`. Eval case 008 (`cis_attribution_in_output`) is the regression probe.
- **WI-3: Single-tenant.** `semantic_store=None` default. SET LOCAL `$1` bug NOT touched. Multi-tenant production blocks on future tenant-RLS substrate plan.

---

## Done definition

D.6 Compliance v0.1 is **done** when:

- 16/16 tasks closed; every commit pinned in the execution-status table.
- ≥ 80% test coverage on `packages/agents/compliance` (gate same as F.3 / D.1 / D.3 / D.7 / D.4 / multi-cloud-posture / k8s-posture / D.5 / D.8).
- `ruff check` + `ruff format --check` + `mypy --strict` clean.
- `eval-framework run --runner compliance` returns 10/10.
- ADR-007 v1.1 + v1.2 conformance verified end-to-end; v1.3 + v1.4 opt-outs confirmed.
- README + smoke runbook reviewed.
- D.6 v0.1 verification record committed at `docs/_meta/d-6-compliance-v0-1-verification-2026-05-21.md`.
- Watch-items WI-1 through WI-3 verified at close.

That closes the **third of 7 unbuilt agents** under the Path-B operating rule. **D.13 Synthesis v0.1** follows at the same cadence per sketch §8 sequence.

---

## ADR-011 cadence (per-task discipline)

Every numbered task above lands as its **own PR** off branches like `feat/d-6-task-N-<scope>`. Per [ADR-011](../../_meta/decisions/ADR-011-pr-flow-and-branch-protection-discipline.md):

- **LOW-RISK label** on every D.6 task — all changes are scoped to `packages/agents/compliance/` (new package, isolated). No SAFETY-CRITICAL paths.
- **Report → review → merge → next task.** After each task PR opens, pause for review. Don't start the next task until the prior PR merges.
- **Verified-against-HEAD sentence** in PR body for every task.
- **Execution-status table is single source of truth** for task-commit pinning per ADR-010. Verification record cites; does not duplicate.

---

## Next plans queued (for context, per Path-B operating rule)

- **D.6 Compliance v0.1** (this plan) — third of 7 unbuilt agents.
- **D.13 Synthesis v0.1** — LLM-driven cross-agent narration.
- **D.12 Curiosity v0.1** — depends on F.7 `claims.>` substrate ADR shipping first.
- **A.4 Meta-Harness v0.1** — depends on all 6 D-track agents existing with eval suites.
- **Supervisor (#0) v0.1** — last; depends on all 17 prior agents.

---

## Reference template

Follows [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) (reference NLAH) + [ADR-010](../../_meta/decisions/ADR-010-version-extension-template.md) (within-agent version-extension template; D.6 v0.1 is initial-version, so ADR-010 applies only to D.6 v0.2 and later). [D.8 Threat Intel v0.1's verification record](../../_meta/d-8-threat-intel-v0-1-verification-2026-05-21.md) is the closest reference for cadence + verification-record shape.
