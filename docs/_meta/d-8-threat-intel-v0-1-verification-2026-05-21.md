# D.8 Threat Intel v0.1 — Verification Record

**Date:** 2026-05-21
**Plan:** [`docs/superpowers/plans/2026-05-21-d-8-threat-intel-v0-1.md`](../superpowers/plans/2026-05-21-d-8-threat-intel-v0-1.md)
**Operating rule:** [Path-B-breadth-first (2026-05-20)](../../packages/agents/threat-intel/README.md#scope-v01) — every unbuilt agent ships to v0.1 in sketch §8 sequence before any v0.2+ work on a shipped agent.
**Outcome:** **D.8 v0.1 shipped.** 16 tasks, 16 PRs, all merged to main. 249 tests passing. 10/10 eval cases pass. Q6 attribution verified at unit, render, and CLI layers. Path-B sequence advances to **D.6 Compliance**.

## Execution-status table

| Task | Status | PR  | Summary                                                                                                                                                                                                                                                 |
| ---- | ------ | --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | ✅     | #73 | Package bootstrap — pyproject + ADR-007 v1.1/v1.2 anti-pattern guards + 9 smoke tests.                                                                                                                                                                  |
| 2    | ✅     | #74 | `schemas.py` — re-exports D.4's `class_uid 2004` OCSF + `Severity` + `AffectedResource`; adds `THREAT_INTEL_FINDING_ID_RE`, `ThreatIntelFindingType` (4 buckets), `IocType` (5 kinds), `build_finding`, `ThreatIntelFinding` wrapper, `FindingsReport`. |
| 3    | ✅     | #75 | `tools/nvd_feed.py` — NVD CVE 2.0 JSON reader (CVE-ID + CVSS v3.1/3.0 + multi-language description). 18 tests.                                                                                                                                          |
| 4    | ✅     | #76 | `tools/cisa_kev.py` — CISA KEV catalog reader; conservative ransomware-flag derivation. 16 tests.                                                                                                                                                       |
| 5    | ✅     | #77 | `tools/mitre_attack.py` — STIX 2.1 enterprise bundle reader; `attack-pattern` only; drops revoked/deprecated. 15 tests.                                                                                                                                 |
| 6    | ✅     | #78 | `entities.py` (IocEntity / CveEntity / TechniqueEntity) + `kg_writer.py` (SemanticStore writer; single-tenant `semantic_store=None` opt-in). 24 tests.                                                                                                  |
| 7    | ✅     | #79 | `correlators/cve_correlator.py` — joins D.1 VulnerabilityFinding cve_ids against KEV; emits CVE_KEV at CRITICAL. 17 tests.                                                                                                                              |
| 8    | ✅     | #80 | `correlators/ioc_correlator_network.py` + shared `ioc_index.py` — joins D.4 observables (IP / DOMAIN / CVE-ID) against IOC index. 17 tests.                                                                                                             |
| 9    | ✅     | #81 | `correlators/ioc_correlator_runtime.py` — joins D.3 observables (IP / FILE_HASH) against IOC index. 15 tests.                                                                                                                                           |
| 10   | ✅     | #82 | `scorer.py` — deterministic table-driven canonical severity re-stamp. 15 tests.                                                                                                                                                                         |
| 11   | ✅     | #83 | `summarizer.py` — markdown render with CVE-in-KEV pinned + MITRE ATT&CK CC-BY-4.0 attribution footer (always emitted). 16 tests.                                                                                                                        |
| 12   | ✅     | #84 | `agent.py` — end-to-end driver wiring all 6 stages; 3-feed TaskGroup ingest + 3-correlator TaskGroup CORRELATE. 15 tests.                                                                                                                               |
| 13   | ✅     | #85 | NLAH bundle (CTI analyst persona README + tools.md + 3 examples) + 21-LOC `nlah_loader.py`. 13 tests.                                                                                                                                                   |
| 14   | ✅     | #86 | `eval_runner.py` + 10 YAML eval cases (`eval/cases/001…010`). 17 tests (10 parametrised + 7 metadata).                                                                                                                                                  |
| 15   | ✅     | #87 | `cli.py` — `threat-intel run`/`eval` click commands. 13 tests.                                                                                                                                                                                          |
| 16   | ✅     | #88 | README polish + smoke runbook + this verification record.                                                                                                                                                                                               |

## Gate results

| Gate                                                        | Result                                                                     |
| ----------------------------------------------------------- | -------------------------------------------------------------------------- |
| `ruff check`                                                | clean (`All checks passed!`)                                               |
| `ruff format --check`                                       | clean                                                                      |
| `mypy --strict`                                             | clean — 19 source files in `src/threat_intel/`                             |
| `pytest packages/agents/threat-intel`                       | **249 passed** in <1s                                                      |
| `threat-intel eval packages/agents/threat-intel/eval/cases` | **10/10 passed**                                                           |
| `threat-intel run --contract <path>` (empty inputs)         | exits 0; emits empty `findings.json` + `report.md` with attribution footer |

## Acceptance criteria (per plan §Q1-Q6 + watch-items)

| Criterion                                                                           | Verification                                                                                                                                                                                                                                  |
| ----------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Q1.** OCSF 2004 re-export from D.4 with `types[0]="threat_intel_*"` discriminator | `test_schemas.py` (38 tests) asserts class_uid 2004 + the 4 ThreatIntelFindingType buckets land in `finding_info.types[0]`.                                                                                                                   |
| **Q2.** Offline filesystem snapshots only (no live HTTP in v0.1)                    | All 3 readers (`read_nvd_feed`, `read_cisa_kev`, `read_mitre_attack`) are filesystem-only via `asyncio.to_thread`; no `httpx`/`aiohttp` imports in the package.                                                                               |
| **Q3.** Three pydantic entity models + kg_writer; single-tenant opt-in default      | `entities.py` + `kg_writer.py`; `agent.py` driver guards SemanticStore writes behind `semantic_store=None` default; test_agent_unit.py verifies opt-in path.                                                                                  |
| **Q4.** Operator-pinned sibling workspaces via 3 flags, read-only                   | `cli.py` exposes `--vulnerability-workspace`, `--network-threat-workspace`, `--runtime-threat-workspace`; correlators perform read-only sibling-workspace reads.                                                                              |
| **Q5.** Single-tenant default (multi-tenant blocked on SET LOCAL fix)               | `semantic_store=None` default in `agent.run`; documented in driver + README.                                                                                                                                                                  |
| **Q6.** MITRE ATT&CK CC-BY-4.0 attribution footer required in `report.md`           | `summarizer.py` emits the footer unconditionally; `test_summarizer.py` asserts presence on empty + non-empty reports; `test_cli.py` re-asserts after end-to-end CLI run; `test_nlah_loader.py` confirms the README documents the requirement. |
| **WI-1** Within-run AFFECTS-edge dedup (cross-run debt accepted)                    | `ioc_correlator_*` dedupes per-finding (IocType, value) within a single source-finding scan; cross-run dedup remains known debt (KG-loop §13.1).                                                                                              |
| **WI-2** ADR-007 v1.2 conformance (NLAH 21-LOC shim)                                | `nlah_loader.py` is a 21-LOC delegation; `test_nlah_loader.test_loader_is_under_35_loc` enforces the ≤35 LOC budget.                                                                                                                          |
| **WI-3** Scorer is canonical source of truth                                        | `scorer.score_findings` re-stamps severity; `test_scorer.py` (15 tests) verifies identity preservation on canonical + re-stamp on mismatch; eval case 009 covers the end-to-end behavior.                                                     |
| **WI-4** No PII / no classifier substrings                                          | All correlator descriptions are constructed from feed-derived metadata (KEV entry, IOC index entry); no verbatim source-finding text. README + tools.md + every NLAH example reiterates the constraint.                                       |
| **WI-5** Partial-workspace presence (sibling-drift resilience)                      | Eval case `008_partial_workspace_presence` is the regression probe — malformed D.4 findings.json + valid D.1 workspace → CVE correlator still emits, IOC correlator silently degrades.                                                        |

## Architecture notes for future maintainers

### v0.1 IOC index sparseness

None of the three v0.1 feeds carry IP / DOMAIN / URL / FILE_HASH IOCs. The agent driver builds the IOC index from CVE-IDs in NVD + KEV (each becomes an `IocEntity` of type `CVE_ID`). This means:

- **IOC × D.4 lights up via Suricata-signature CVE-ID matches** (regex-pulled from `evidences[0].signature`).
- **IOC × D.3 IP-match path is wired but stays cold in v0.1** — there are no IP IOCs in the index until v0.2 abuse.ch / VirusTotal feeds land.
- **ATT&CK-observed correlator** is wired (technique index built in Stage 2 ENRICH) but emits no findings in v0.1 — needs D.3 v0.x to surface `evidence.attack_technique`-shaped breadcrumbs.

This is intentional. The wire shape is stable so v0.2 can plug in richer feeds without changing any downstream consumer.

### Single-tenant SemanticStore opt-in

`semantic_store=None` default in `agent.run` was a deliberate choice driven by the **SET LOCAL `$1` tenant-RLS substrate-fix plan** (parked; see project memory). When a `SemanticStore` IS passed:

- CVE entities (union of NVD + KEV CVE IDs) are upserted via `KnowledgeGraphWriter`.
- ATT&CK techniques are upserted as `TechniqueEntity` (entity_type `ttp`).
- IOC entities — though sparse in v0.1 — would also be upserted; v0.2 feed-uplift will exercise the full IOC persistence path.
- Failures bubble up to abort the run (no silent KG drift).

### Path-B sequence advances

D.8 was **#2 of the 7 unbuilt agents** in the Path-B-breadth-first ordering. After this closure:

- **12 of 17 agents at v0.1** (was 11 after D.5 closure on 2026-05-20).
- **Next agent:** D.6 Compliance (third in the sketch §8 sequence).
- **Remaining v0.1 work:** D.6 Compliance → D.13 Synthesis → D.12 Curiosity (after F.7 `claims.>` ADR) → A.4 Meta-Harness → Supervisor (#0).

## Cross-references

- Plan: [`docs/superpowers/plans/2026-05-21-d-8-threat-intel-v0-1.md`](../superpowers/plans/2026-05-21-d-8-threat-intel-v0-1.md)
- Sketch §13 (D.8 version trajectory): [`docs/superpowers/sketches/2026-05-20-agent-version-roadmaps.md#13-d8-threat-intel`](../superpowers/sketches/2026-05-20-agent-version-roadmaps.md)
- Package README + smoke runbook: [`packages/agents/threat-intel/README.md`](../../packages/agents/threat-intel/README.md)
- NLAH bundle (CTI analyst persona): [`packages/agents/threat-intel/src/threat_intel/nlah/`](../../packages/agents/threat-intel/src/threat_intel/nlah/)
- ADR-007 (reference NLAH template, v1.2): [`docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md`](decisions/ADR-007-cloud-posture-as-reference-agent.md)
- ADR-010 (within-agent version extension): [`docs/_meta/decisions/ADR-010-within-agent-version-extension.md`](decisions/ADR-010-within-agent-version-extension.md)
- ADR-011 (PR-flow discipline): [`docs/_meta/decisions/ADR-011-pr-flow-discipline.md`](decisions/ADR-011-pr-flow-discipline.md)
