# D.6 Compliance v0.1 — Verification Record

**Date:** 2026-05-21
**Plan:** [`docs/superpowers/plans/2026-05-21-d-6-compliance-v0-1.md`](../superpowers/plans/2026-05-21-d-6-compliance-v0-1.md)
**Operating rule:** [Path-B-breadth-first (2026-05-20)](../../packages/agents/compliance/README.md#scope-v01) — every unbuilt agent ships to v0.1 in sketch §8 sequence before any v0.2+ work on a shipped agent.
**Outcome:** **D.6 v0.1 shipped.** 16 tasks, 17 PRs (plan + 16 task PRs), all merged to main. 225 tests passing. 10/10 eval cases pass. Q6 CIS Benchmarks® attribution + paraphrase posture verified at unit, render, and CLI layers. Path-B sequence advances to **D.13 Synthesis**.

## Execution-status table

| Task | Status | PR   | Summary                                                                                                                                                                                                                                                   |
| ---- | ------ | ---- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| -    | ✅     | #89  | Plan doc — `2026-05-21-d-6-compliance-v0-1.md` (16-task table, Q1-Q6, WI-1..WI-3).                                                                                                                                                                        |
| 1    | ✅     | #90  | Package bootstrap — pyproject + ADR-007 v1.1/v1.2 anti-pattern guards + 9 smoke tests.                                                                                                                                                                    |
| 2    | ✅     | #91  | `schemas.py` — re-exports F.3's `class_uid 2003` OCSF; adds `COMPLIANCE_FINDING_ID_RE`, `ComplianceFramework` (CIS_AWS_V3), `ControlLevel`, `compliance_finding_type()`, `severity_for_level()`, `ComplianceFinding` wrapper, `ControlMapping`. 28 tests. |
| 3    | ✅     | #92  | `tools/cis_aws_benchmark.py` — async YAML loader; `CisControl` pydantic; ControlMapping fold-in semantics; forgiving on individual entries. 18 tests.                                                                                                     |
| 4    | ✅     | #93  | `control_libraries/cis_aws_v3.yaml` — 45 paraphrased CIS controls (Identity / Storage / Logging / Monitoring / Networking sections). WI-2 regression probe for verbatim-text leakage. 15 tests.                                                           |
| 5    | ✅     | #94  | `entities.py` (FrameworkEntity / ControlEntity) + `kg_writer.py` (SemanticStore writer; single-tenant `semantic_store=None` opt-in). 15 tests.                                                                                                            |
| 6    | ✅     | #95  | `correlators/cloud_posture_correlator.py` + shared `control_index.py` — joins F.3 findings to CIS controls. 16 tests.                                                                                                                                     |
| 7    | ✅     | #96  | `correlators/data_security_correlator.py` — joins D.5 findings to CIS controls. **Schema-contract fix folded in**: short rule_ids (`s3_bucket_public` etc.) in `compliance.control` rather than long discriminator. 15 tests.                             |
| 8    | ✅     | #97  | `aggregator.py` — per-control PASS/FAIL roll-up; FAIL-floor gate at MEDIUM; arn-dedup resource union; deterministic lexicographic ordering. 19 tests.                                                                                                     |
| 9    | ✅     | #98  | `scorer.py` — deterministic table-driven canonical severity re-stamp via `severity_for_level()`. 14 tests.                                                                                                                                                |
| 10   | ✅     | #99  | `summarizer.py` — markdown render with Level-1 pinned section + **CIS Benchmarks® attribution footer with paraphrase declaration** (always emitted). 16 tests.                                                                                            |
| 11   | ✅     | #100 | `agent.py` — 7-stage driver wiring all stages (INGEST → ENRICH → CORRELATE → AGGREGATE → SCORE → SUMMARIZE → HANDOFF). 13 tests.                                                                                                                          |
| 12   | ✅     | #101 | NLAH bundle (Compliance officer persona README + tools.md + 3 examples) + 21-LOC `nlah_loader.py`. 15 tests.                                                                                                                                              |
| 13   | ✅     | #102 | `eval_runner.py` + 10 YAML eval cases (`eval/cases/001…010`). 19 tests (10 parametrised + 9 metadata).                                                                                                                                                    |
| 14   | ✅     | #103 | `cli.py` — `compliance run`/`eval` click commands. 13 tests.                                                                                                                                                                                              |
| 15   | ✅     | #104 | README polish + smoke runbook.                                                                                                                                                                                                                            |
| 16   | ✅     | #105 | This verification record.                                                                                                                                                                                                                                 |

## Gate results

| Gate                                                    | Result                                                                                           |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `ruff check`                                            | clean (`All checks passed!`)                                                                     |
| `ruff format --check`                                   | clean                                                                                            |
| `mypy --strict`                                         | clean — 18 source files in `src/compliance/`                                                     |
| `pytest packages/agents/compliance`                     | **225 passed** in <2s                                                                            |
| `compliance eval packages/agents/compliance/eval/cases` | **10/10 passed**                                                                                 |
| `compliance run --contract <path>` (empty inputs)       | exits 0; emits empty `findings.json` + `report.md` with CIS attribution + paraphrase declaration |

## Acceptance criteria (per plan §Q1-Q6 + watch-items)

| Criterion                                                                                                                 | Verification                                                                                                                                                                                                                                                                                                                                                                                            |
| ------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Q1.** OCSF 2003 re-export from F.3 with `types[0]="compliance_cis_aws_v3_*"` discriminator                              | `test_schemas.py` (28 tests) asserts `class_uid == 2003` re-exported; `compliance_finding_type(framework, control_id)` builds the canonical discriminator with `.`→`_` normalisation.                                                                                                                                                                                                                   |
| **Q2.** CIS AWS Foundations Benchmark v3.0 only (~50 paraphrased controls)                                                | `test_bundled_cis_aws_v3.py::test_bundled_library_has_at_least_min_controls` — 45 controls shipped, floor=40. Coverage spans all 5 CIS sections.                                                                                                                                                                                                                                                        |
| **Q3.** Sibling-workspace `findings.json` read pattern (operator-pinned via 2 flags, read-only)                           | Both correlators (`cloud_posture` + `data_security`) read via `asyncio.to_thread`; F1-F4 failure-taxonomy items resolved per `test_correlators_*` skip-paths + `005_partial_workspace_presence` eval case.                                                                                                                                                                                              |
| **Q4.** Per-control PASS/FAIL roll-up shape (one finding per `(control, status-change)` tuple)                            | `aggregator.py` + `test_aggregator.py` (19 tests) verify the grouping + max-severity + FAIL-floor gate; case `003_multi_source_rollup` exercises cross-source on the same control.                                                                                                                                                                                                                      |
| **Q5.** Single-tenant default (multi-tenant blocked on SET LOCAL fix)                                                     | `semantic_store=None` default in `agent.run`; `test_agent_unit::test_run_with_no_semantic_store_skips_kg_writes` enforces. Documented in driver + README.                                                                                                                                                                                                                                               |
| **Q6.** CIS Benchmarks® licence — paraphrased control names + IDs only; attribution footer + canonical URL in `report.md` | `summarizer.py` emits the footer unconditionally; `test_summarizer.py` asserts presence on empty + non-empty reports; `test_cli::test_run_writes_cis_attribution_footer_in_report_md` re-asserts after end-to-end CLI run; `test_no_securesuite_anchor_text_in_descriptions` guards the bundled YAML.                                                                                                   |
| **WI-1** Substrate sealed                                                                                                 | No changes to `packages/charter/`, `packages/shared/`, `packages/eval-framework/`. Confirmed by file-tree diff at close.                                                                                                                                                                                                                                                                                |
| **WI-2** CIS Benchmarks® licence compliance (paraphrased YAML, attribution footer, paraphrase verification step)          | Bundled YAML (Task 4) is paraphrased in-house; `test_no_securesuite_anchor_text_in_descriptions` (Task 4 test) guards against 5 CIS-PDF section-heading anchors regressing. Attribution footer + "No verbatim CIS Securesuite text is reproduced" declaration emitted in every `report.md` (verified at unit / render / CLI layers). Eval case `008_cis_attribution_in_output` is the regression probe. |
| **WI-3** Single-tenant; SET LOCAL fix parked                                                                              | `semantic_store=None` default; multi-tenant production remains gated on the future tenant-RLS substrate-fix plan. v0.1 single-tenant in-memory `aiosqlite` SemanticStore supported for tests only.                                                                                                                                                                                                      |

## Architecture notes for future maintainers

### 7-stage pipeline (one stage more than D.4 / D.8)

D.6 inserts a dedicated **AGGREGATE** stage between CORRELATE and SCORE that the other agents don't have. This was Q4: correlators emit one finding per `(source-finding × CIS control)` mapping, but the auditor wants one finding per CIS control. The aggregator collapses across contributors and produces a single per-control verdict — the unit downstream consumers (Meta-Harness, D.7, future auditor-export PDF) reason about.

### Schema-contract subtlety: D.5 short rule_ids

D.5's detectors stamp short rule*ids in `compliance.control` (`s3_bucket_public` / `s3_bucket_unencrypted` / `s3_oversharing_iam` / `s3_object_sensitive_in_untrusted_location`) — NOT the full `data_security*\*` `DataSecurityFindingType`discriminator. The full discriminator lands in`evidence.source_finding_type`but D.6's join key is the short form in`compliance.control`. Task 7 PR #96 corrected the bundled YAML to use the short forms after the initial Task 4 draft used the long ones. Future D.5 versions must preserve the short form in `compliance.control` to maintain the join contract.

### FindingsReport schema-debt note

D.6's `FindingsReport` is re-exported from F.3's `cloud_posture.schemas`. F.3's `FindingsReport.add_finding` is typed against `CloudPostureFinding`; D.6's `ComplianceFinding` is a different wrapper. The driver appends raw payload dicts directly to `report.findings` to keep pydantic serialisation clean. This is a known temporary shim until v0.2 lifts `FindingsReport` into `charter.shared` (the right home for the cross-agent container type).

### Path-B sequence advances

D.6 was **#3 of the 7 unbuilt agents** in the Path-B-breadth-first ordering. After this closure:

- **13 of 17 agents at v0.1** (was 12 after D.8 closure on 2026-05-21).
- **Next agent:** D.13 Synthesis (fourth in the sketch §8 sequence).
- **Remaining v0.1 work:** D.13 Synthesis → D.12 Curiosity (after F.7 `claims.>` ADR) → A.4 Meta-Harness → Supervisor (#0).

## Cross-references

- Plan: [`docs/superpowers/plans/2026-05-21-d-6-compliance-v0-1.md`](../superpowers/plans/2026-05-21-d-6-compliance-v0-1.md)
- Sketch §2 (D.6 scope + ID-namespace resolution): [`docs/superpowers/sketches/2026-05-20-remaining-agents-sketch.md`](../superpowers/sketches/2026-05-20-remaining-agents-sketch.md)
- Package README + smoke runbook: [`packages/agents/compliance/README.md`](../../packages/agents/compliance/README.md)
- NLAH bundle (Compliance officer persona): [`packages/agents/compliance/src/compliance/nlah/`](../../packages/agents/compliance/src/compliance/nlah/)
- ADR-007 (reference NLAH template, v1.2): [`docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md`](decisions/ADR-007-cloud-posture-as-reference-agent.md)
- ADR-010 (within-agent version extension): [`docs/_meta/decisions/ADR-010-within-agent-version-extension.md`](decisions/ADR-010-within-agent-version-extension.md)
- ADR-011 (PR-flow discipline): [`docs/_meta/decisions/ADR-011-pr-flow-discipline.md`](decisions/ADR-011-pr-flow-discipline.md)
- D.8 verification record (reference template for this doc): [`docs/_meta/d-8-threat-intel-v0-1-verification-2026-05-21.md`](d-8-threat-intel-v0-1-verification-2026-05-21.md)
