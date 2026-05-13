# D.5 — Multi-Cloud Posture Agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Pause for review after each numbered task.

**Goal:** Ship the **Multi-Cloud Posture Agent** (`packages/agents/multi-cloud-posture/`) — the **third Phase-1b agent** and the **eighth under [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)** (F.3 / D.1 / D.2 / D.3 / F.6 / D.7 / D.4 / **D.5**). Lifts CSPM coverage from AWS-only (F.3) to **Azure + GCP** — the multi-cloud delta the Wiz equivalence story needs.

**Scope:** v0.1 ingests four operator-pinned input feeds (Azure Defender for Cloud findings · Azure Activity Log · GCP Security Command Center findings · GCP Cloud Asset Inventory IAM) from filesystem snapshots (offline-mode, mirrors F.3's LocalStack pattern + D.4's filesystem-only pattern). Emits OCSF v1.3 Compliance Findings (`class_uid 2003`) — **identical wire shape to F.3** — with a `cloud_provider` discriminator on `finding_info.types[0]`. Phase 1c adds live SDK calls (`azure-mgmt-security` + `google-cloud-securitycenter`).

**Strategic role.** Third Phase-1b agent; lifts the Wiz CSPM family from ~50% (AWS-only via F.3) to ~75% (AWS + Azure + GCP). The CSPM family carries the highest Wiz weight (0.40), so D.5's lift is the **largest single coverage delta** of any Phase-1b agent — projected +8pp weighted. Pure pattern application against the now-stable substrate + F.3 schemas — no new architectural decisions blocking.

**Q1 (resolve up-front).** Schema reuse — share F.3's `cloud_posture.schemas` or fork into a per-agent shape?

**Resolution: re-export `class_uid 2003 Compliance Finding` from F.3 and add a `CloudProvider` enum on the `finding_info.types[0]` discriminator.** Two reasons: (1) Compliance Findings have no AWS-specific fields in F.3's shape — `AffectedResource` is generic over `resource_type / resource_id / region`, so Azure + GCP fit directly; (2) sharing the schema unlocks downstream consumers (Meta-Harness, D.7 Investigation) that already filter on `class_uid 2003`. Discriminator pattern: `finding_info.types[0]` carries `cspm_azure_defender` / `cspm_azure_activity` / `cspm_gcp_scc` / `cspm_gcp_iam` per source. The `CloudProvider` enum (AZURE / GCP) rides as a finding-info dict key for explicit filtering.

**Q2 (resolve up-front).** Live SDK calls or offline fixture mode in v0.1?

**Resolution: offline filesystem snapshots only.** Mirrors F.3 (LocalStack mock + Prowler subprocess) + D.4 (filesystem-only readers). Phase 1c adds live `azure-mgmt-security` + `google-cloud-securitycenter` calls; v0.1 ships the readers + normalizers without external network dependencies. The live SDK path is the next-highest-leverage Phase 1c task — D.5 v0.1's offline mode validates the normalizers against frozen fixtures first.

**Q3 (resolve up-front).** One agent or two (Azure-only + GCP-only sibling agents)?

**Resolution: one agent.** Both clouds emit the same OCSF wire shape (`class_uid 2003`) and share the agent driver + summarizer + audit chain + eval-runner. Splitting would double the substrate footprint with no compounding capability. The package internally separates parsers (`tools/azure_*.py` + `tools/gcp_*.py`) and normalizers (`normalizers/azure.py` + `normalizers/gcp.py`); the agent driver stitches both feeds through one TaskGroup ingest.

**Q4 (resolve up-front).** Tenant credential management?

**Resolution: env vars in v0.1.** Mirrors F.3's `AWS_PROFILE` precedent — `AZURE_*` for the Azure SDK (when Phase 1c live mode lands) and `GOOGLE_APPLICATION_CREDENTIALS` for GCP. v0.1 reads filesystem-snapshot paths from the contract; tenant creds aren't loaded. F.4 control-plane integration (per-tenant secret-store) lands in Phase 1c alongside the live SDK paths.

**Q5 (resolve up-front).** Azure SDK choice when live mode lands?

**Resolution: `azure-mgmt-security` for Defender findings, `azure-mgmt-monitor` for Activity Log.** Both have explicit `list_*` pagers and OCSF-friendly response shapes. SDK shims live behind the offline-mode readers' `read_azure_findings` / `read_azure_activity` signatures so Phase 1c only swaps the implementation, not the contract.

**Q6 (resolve up-front).** GCP SDK choice when live mode lands?

**Resolution: `google-cloud-securitycenter` for SCC findings, `google-cloud-asset` for asset inventory + IAM.** Same shim-behind-reader pattern as Azure. Note: GCP SCC requires `Security Center Standard` tier — we surface this as a runbook prerequisite; without SCC enabled the v0.1 fixture reader still works.

**Architecture:**

```
ExecutionContract (signed)
        │
        ▼
┌──────────────────────────────────────────────────────────────────┐
│ Multi-Cloud Posture Agent driver                                 │
│                                                                  │
│  Stage 1: INGEST      — 4 feeds concurrent via TaskGroup         │
│  Stage 2: NORMALIZE   — Azure + GCP findings → OCSF 2003         │
│  Stage 3: SCORE       — deterministic severity per source        │
│  Stage 4: SUMMARIZE   — per-cloud + per-severity sections        │
│  Stage 5: HANDOFF     — emit `findings.json` + `report.md`       │
└─────────┬────────────────────────────────────────────────────────┘
          │
          ▼
┌──────────────────────────────────────────────────────────────────┐
│ Tools (per-stage)                                                │
│  read_azure_findings    ─→ Defender for Cloud JSON (filesystem)  │
│  read_azure_activity    ─→ Azure Activity Log JSON (filesystem)  │
│  read_gcp_findings      ─→ SCC findings JSON (filesystem)        │
│  read_gcp_iam_findings  ─→ Cloud Asset Inventory IAM (fs)        │
│  normalize_azure        ─→ Azure shape → OCSF 2003               │
│  normalize_gcp          ─→ GCP shape → OCSF 2003                 │
│  render_summary         ─→ per-cloud pinned + per-severity       │
└──────────────────────────────────────────────────────────────────┘
```

**Tech stack:** Python 3.12 · BSL 1.1 · OCSF v1.3 Compliance Finding (`class_uid 2003`, `types[0]` carries source discriminator) · pydantic 2.9 · click 8 · `charter.llm_adapter` (ADR-007 v1.1) · `charter.nlah_loader` (ADR-007 v1.2). Re-exports F.3's `cloud_posture.schemas` for the OCSF Compliance Finding wire shape. No external network dependencies in v0.1.

**Depends on:**

- F.1 charter — standard budget caps; no extensions needed (D.5 is not always-on, not sub-agent-spawning).
- F.3 cloud-posture — re-exports `class_uid 2003 Compliance Finding` schema; reuses `AffectedResource`, `build_finding`, `Severity`. No code duplication.
- F.4 control-plane — tenant context propagates through the contract; per-tenant cred-store integration deferred to Phase 1c.
- F.5 memory engines — `EpisodicStore` for per-run persistence (optional in v0.1).
- F.6 Audit Agent — every D.5 run emits an audit chain via `charter.audit.AuditLog`.
- ADR-007 v1.1 + v1.2 — reference NLAH template. D.5 is the **eighth** agent under it. v1.3 (always-on) opt-out; v1.4 (sub-agent spawning) not consumed.

**Defers (Phase 1c / Phase 2):**

- **Live Azure SDK calls** (`azure-mgmt-security` + `azure-mgmt-monitor`) — Phase 1c.
- **Live GCP SDK calls** (`google-cloud-securitycenter` + `google-cloud-asset`) — Phase 1c.
- **Per-tenant secret store** (F.4 cred-store integration) — Phase 1c.
- **Kubernetes posture** (CIS-bench + Polaris) — **D.6** (next plan after D.5 closes).
- **IBM Cloud / Oracle Cloud / Alibaba Cloud** — Phase 2 (these are <2% of customer footprint by survey).
- **Compliance framework engine** (SOC 2 / ISO 27001 / HIPAA / HITRUST mappings) — Phase 1c (`D.6 Compliance Agent` per the build roadmap; not the same as D.6 K8s in this plan trajectory).

**Reference template:** F.3 Cloud Posture Agent (closest match — same OCSF class, same compliance-finding shape, same offline-mode pattern). D.5 is structurally F.3 with: (a) two new clouds (Azure + GCP) instead of AWS; (b) **four readers** instead of three (two per cloud — findings + activity / IAM); (c) two normalizers (one per cloud) instead of one (Prowler did all the work in F.3); (d) **shared schema** with F.3 (re-export, not fork); (e) **non-load-bearing LLM** (deterministic normalizers; same v0.1 posture as F.3 + D.4).

---

## Execution status

```
1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12 → 13 → 14 → 15 → 16
```

| Task | Status     | Commit    | Notes                                                                                                                                                                                                                                                                                                                                          |
| ---- | ---------- | --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | ✅ done    | `89528ed` | Bootstrap — pyproject (BSL 1.1; deps on charter / shared / eval-framework / **nexus-cloud-posture** for the F.3 schema re-export per Q1). 9 smoke tests: ADR-007 v1.1 + v1.2 + F.1 audit log + F.5 episodic + F.3 schema re-export confirmation + 2 anti-pattern guards + 2 entry-point checks. Repo-wide 1580 passed / 11 skipped.            |
| 2    | ✅ done    | `7c80397` | Re-exports F.3's class_uid 2003 Compliance Finding verbatim (Q1 confirmed). Adds `CloudProvider` enum + `CSPMFindingType` enum (4 discriminators) + `cloud_provider_for()` + `source_token()` + `short_resource_token()`. Chore: added py.typed to F.3 cloud-posture for cross-package mypy. 17 tests.                                         |
| 3    | ✅ done    | `7c80397` | `read_azure_findings` — async parser for Azure Defender for Cloud JSON exports. Three top-level shapes (`{"value": [...]}` / bare array / heuristic); classifies records as assessment vs alert; severity normalisation; preserves alertType / compromisedEntity / remediation under `unmapped`. 18 tests. Repo-wide 1615 passed / 11 skipped. |
| 4    | ✅ done    | `e75f8dd` | `read_azure_activity` — async Activity Log parser; canonical + bare-array shapes; operation_name → 6 buckets (iam/network/storage/compute/keyvault/other) via case-insensitive regex; operationName/category/status accept str-or-dict; subscription_id + resource_group extracted from resource paths. 17 tests.                              |
| 5    | ✅ done    | `e75f8dd` | `read_gcp_findings` — async SCC parser; three top-level shapes (canonical ListFindingsResponse / gcloud wrapper / bare array); severity normalisation; INACTIVE state preserved; project_id from resource_name; parent + resourceName fallback paths. 21 tests. Repo-wide 1656 passed / 11 skipped.                                            |
| 6    | ⬜ pending | —         | `read_gcp_iam_findings` tool — GCP Cloud Asset Inventory IAM JSON parser; async; flags overly-permissive bindings (`roles/owner` to ext users) and stale service accounts.                                                                                                                                                                     |
| 7    | ⬜ pending | —         | `normalize_azure` — Azure findings + activity → OCSF 2003 Compliance Finding tuple; severity mapping (Azure Defender 1-3 → Severity); per-discriminator finding_id construction.                                                                                                                                                               |
| 8    | ⬜ pending | —         | `normalize_gcp` — GCP SCC findings + IAM → OCSF 2003 Compliance Finding tuple; severity mapping (GCP SCC severity strings → Severity); per-discriminator finding_id construction.                                                                                                                                                              |
| 9    | ⬜ pending | —         | NLAH bundle + 21-LOC shim. ADR-007 v1.2 conformance (5th native v1.2 agent after D.3 / F.6 / D.7 / D.4). README + tools.md + 2 examples (Azure + GCP).                                                                                                                                                                                         |
| 10   | ⬜ pending | —         | `render_summary` — per-cloud breakdown pinned ABOVE per-severity sections (Azure / GCP counts at the top); CRITICAL findings pinned (mirrors F.3's pattern); per-severity sections.                                                                                                                                                            |
| 11   | ⬜ pending | —         | Agent driver `run()` — 5-stage pipeline (INGEST → NORMALIZE → SCORE → SUMMARIZE → HANDOFF). TaskGroup fan-out across the four readers. 4 optional feed flags.                                                                                                                                                                                  |
| 12   | ⬜ pending | —         | 10 representative YAML eval cases: clean_multicloud / azure_defender_high / azure_iam_overpermissive / azure_activity_quiet / gcp_scc_critical / gcp_iam_stale_sa / gcp_quiet / mixed_clouds / azure_only / gcp_only.                                                                                                                          |
| 13   | ⬜ pending | —         | `MultiCloudPostureEvalRunner` + `nexus_eval_runners` entry-point + **10/10 acceptance** via `eval-framework run --runner multi_cloud_posture`.                                                                                                                                                                                                 |
| 14   | ⬜ pending | —         | CLI (`multi-cloud-posture eval` / `multi-cloud-posture run`). Four optional feed flags: `--azure-findings-feed`, `--azure-activity-feed`, `--gcp-findings-feed`, `--gcp-iam-feed`.                                                                                                                                                             |
| 15   | ⬜ pending | —         | README + operator runbook (`runbooks/multicloud_scan.md`). ADR-007 v1.1 + v1.2 conformance verified; v1.3 + v1.4 opt-outs confirmed.                                                                                                                                                                                                           |
| 16   | ⬜ pending | —         | Final verification record `docs/_meta/d5-verification-<date>.md`. Plan close + commit-hash pinning.                                                                                                                                                                                                                                            |

ADR references: [ADR-001](../../_meta/decisions/ADR-001-monorepo-bootstrap.md) · [ADR-004](../../_meta/decisions/ADR-004-fabric-layer.md) · [ADR-005](../../_meta/decisions/ADR-005-async-tool-wrapper-convention.md) · [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) · [ADR-008](../../_meta/decisions/ADR-008-eval-framework.md) · [ADR-009](../../_meta/decisions/ADR-009-memory-architecture.md).

---

## Resolved questions

| #   | Question                                    | Resolution                                                                                                                                                                  | Task       |
| --- | ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| Q1  | Schema reuse strategy?                      | **Re-export F.3's `class_uid 2003` Compliance Finding** with a `CloudProvider` enum + 4-bucket `CSPMFindingType` discriminator. No fork, no duplication.                    | Task 2     |
| Q2  | Live SDK calls or offline fixtures in v0.1? | **Offline filesystem snapshots only** (mirrors F.3 LocalStack + D.4 filesystem-only). Live SDK paths (`azure-mgmt-security` + `google-cloud-securitycenter`) ship Phase 1c. | Tasks 3-6  |
| Q3  | One agent or two (Azure / GCP)?             | **One agent.** Both clouds share OCSF wire shape + agent driver + summarizer + audit chain. Internal separation via `tools/azure_*` + `tools/gcp_*` + `normalizers/`.       | Task 11    |
| Q4  | Tenant credential management?               | **Env vars in v0.1** (mirrors F.3's `AWS_PROFILE`). F.4 per-tenant secret-store integration ships Phase 1c.                                                                 | Task 11    |
| Q5  | Azure SDK choice (when live)?               | **`azure-mgmt-security` + `azure-mgmt-monitor`.** Both have explicit `list_*` pagers and OCSF-friendly response shapes.                                                     | (Phase 1c) |
| Q6  | GCP SDK choice (when live)?                 | **`google-cloud-securitycenter` + `google-cloud-asset`.** SCC requires Security Center Standard tier — runbook prerequisite.                                                | (Phase 1c) |

---

## File map (target)

```
packages/agents/multi-cloud-posture/
├── pyproject.toml                              # Task 1
├── README.md                                   # Tasks 1, 15
├── runbooks/
│   └── multicloud_scan.md                      # Task 15
├── src/multi_cloud_posture/
│   ├── __init__.py                             # Task 1
│   ├── py.typed                                # Task 1
│   ├── schemas.py                              # Task 2 (CloudProvider + CSPMFindingType + F.3 re-exports)
│   ├── nlah_loader.py                          # Task 9 (21-LOC shim)
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── azure_defender.py                   # Task 3
│   │   ├── azure_activity.py                   # Task 4
│   │   ├── gcp_scc.py                          # Task 5
│   │   └── gcp_iam.py                          # Task 6
│   ├── normalizers/
│   │   ├── __init__.py
│   │   ├── azure.py                            # Task 7
│   │   └── gcp.py                              # Task 8
│   ├── summarizer.py                           # Task 10
│   ├── agent.py                                # Task 11 (driver: 5-stage pipeline)
│   ├── eval_runner.py                          # Task 13
│   └── cli.py                                  # Task 14
├── nlah/
│   ├── README.md                               # Task 9
│   ├── tools.md                                # Task 9
│   └── examples/                               # Task 9 (2 examples: Azure + GCP)
├── eval/
│   └── cases/                                  # Task 12 (10 YAML cases)
└── tests/
    ├── test_pyproject.py                       # Task 1
    ├── test_schemas.py                         # Task 2
    ├── test_tools_azure_defender.py            # Task 3
    ├── test_tools_azure_activity.py            # Task 4
    ├── test_tools_gcp_scc.py                   # Task 5
    ├── test_tools_gcp_iam.py                   # Task 6
    ├── test_normalizers_azure.py               # Task 7
    ├── test_normalizers_gcp.py                 # Task 8
    ├── test_nlah_loader.py                     # Task 9
    ├── test_summarizer.py                      # Task 10
    ├── test_agent.py                           # Task 11
    ├── test_eval_runner.py                     # Task 13 (incl. 10/10 acceptance)
    └── test_cli.py                             # Task 14
```

---

## Risks

| Risk                                                                                                                                       | Mitigation                                                                                                                                                                                                                                       |
| ------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Schema re-export from F.3 creates coupling; if F.3 amends `Severity` or `AffectedResource`, D.5 has to follow.                             | Acceptable — Compliance Finding schema is stable v0.1. The alternative (forking) is worse: every CSPM extension would need to track F.3 changes by hand. v0.1 ships one re-export site; we monitor for breakage.                                 |
| Azure Defender + Activity Log are structurally different (severity scale, resource-id format); normalizers must handle both.               | Two separate readers + two normalizer entry-points in `normalizers/azure.py`. Each emits OCSF 2003 finding-shape; the eval cases exercise both paths.                                                                                            |
| GCP SCC findings can include enormous JSON blobs (asset inventory snapshot); the file-mode reader could OOM.                               | Cap the per-file findings count at 5000 (mirrors F.6's 500-event cap on audit_trail_query). Phase 1c live SDK paths handle pagination natively; v0.1 readers expect the operator to pre-filter the snapshot to a manageable window.              |
| GCP IAM analyzer outputs are stored as Cloud Asset Inventory queries (JSON) — operators may not have this enabled.                         | Runbook documents the Asset Inventory prerequisite explicitly; the fixture reader works against any JSON file with the documented `assets` array shape. Phase 1c live mode uses `asset-search-all-iam-policies` API.                             |
| Live SDK paths deferred to Phase 1c — the v0.1 offline mode could mask normalizer bugs that only surface against real cloud-shaped data.   | 10 eval cases use **realistic** Azure + GCP JSON shapes (sampled from public documentation + dev-account exports). Phase 1c adds a smoke runbook (`multicloud_dev_account_smoke.md`) analogous to F.3's `aws_dev_account_smoke.md`.              |
| Eval-case YAMLs duplicating large JSON blobs become a maintenance burden.                                                                  | YAML directives like D.4's `flow_records_scan` — synthesise N findings from a template directive when the test needs scale. v0.1 fixtures stay small (1-3 findings each).                                                                        |
| The Wiz CSPM family weight (0.40) makes D.5's lift highly visible; under-delivering on Azure/GCP coverage will dent the equivalence story. | v0.1 covers the **operator-visible** surface (findings + IAM + activity) for both clouds. The remaining ~25% (network rule findings, encryption-at-rest scans, deeper resource graphs) is Phase 1c — flagged explicitly in the README + runbook. |

---

## Done definition

D.5 is **done** when:

- 16/16 tasks closed; every commit pinned in the execution-status table.
- ≥ 80% test coverage on `packages/agents/multi-cloud-posture` (gate same as F.3 / D.1 / D.3 / D.7 / D.4).
- `ruff check` + `ruff format --check` + `mypy --strict` clean.
- `eval-framework run --runner multi_cloud_posture` returns 10/10.
- ADR-007 v1.1 + v1.2 conformance verified end-to-end; v1.3 + v1.4 opt-outs confirmed.
- README + runbook reviewed.
- D.5 verification record committed.

That closes the third Phase-1b agent. **D.6 (Kubernetes posture)** follows at the same cadence to close the Phase-1b detection track.

---

## Next plans queued (for context)

- **D.6 CSPM extension #2** — Kubernetes posture (CIS-bench + Polaris); reads kubeconfig + cluster API directly (or offline `kubeconfig` + manifest dump).
- **D.8 Threat Intel Agent** — replaces D.4/D.5's bundled static-intel snapshots with live VirusTotal + OTX + CISA KEV feeds. Phase 1b late or Phase 1c early.

D.5 → D.6 closes Phase 1b detection (D.1 + D.2 + D.3 + D.4 + D.5 + D.6 + D.7 all shipped). Phase 1c brings A.1–A.4 Track-A remediation + A.4 Meta-Harness + streaming ingest.
