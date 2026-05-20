# D.8 — Threat Intel Agent v0.1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Pause for review after each numbered task.

**Goal:** Ship the **Threat Intel Agent** (`packages/agents/threat-intel/`) — the **second of the 7 unbuilt agents** under the [Path-B-breadth-first operating rule](../sketches/2026-05-20-agent-version-roadmaps.md) (2026-05-20) and the **twelfth under [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)** (F.3 / D.1 / D.2 / D.3 / F.6 / D.7 / D.4 / multi-cloud-posture / k8s-posture / A.1 / D.5 / **D.8**). Lifts platform coverage from siloed detection to **threat-context correlation** — the first agent that consumes external threat-intel feeds (NVD CVE + CISA KEV + MITRE ATT&CK) and joins them against sibling-agent findings to elevate risk.

**Scope (v0.1, locked per Path-B-breadth-first rule + sketch §3).** Three public, no-auth feeds (offline-mode JSON snapshots staged by the operator). Three correlation hooks against existing detect-agent workspaces (D.1 Vulnerability + D.4 Network Threat + D.3 Runtime Threat) via the D.7-style operator-pinned sibling-workspace flag. SemanticStore writes for `ioc` / `cve` / `ttp` entity types (single-tenant `semantic_store=None` opt-in default per sketch §3). OCSF v1.3 Detection Finding (`class_uid 2004`) — re-exported from `network_threat.schemas` per Q1 — with `finding_info.types[0]="threat_intel"` discriminator. Deterministic (no LLM in loop). v0.1 ships eval-only; live-lane CI deferred to v0.2.

**Strategic role.** Second "detect" agent in the breadth-first cadence. Closes the **detection-correlation loop**: D.1 / D.3 / D.4 produce raw findings; D.8 enriches them with external threat context (KEV active-exploitation flag, IOC match, ATT&CK technique observation). The cross-agent correlation pattern is **read-only** — D.8 reads sibling workspaces, never writes back. Mirrors D.7 Investigation's sibling-workspace pattern + D.4 Network Threat's external-feed-consumer shape. **No charter-level substrate work expected** — agent-local feed clients + agent-local correlators + reuse of F.3's `SemanticStore` writer pattern (from F.3 v0.1.5 KG-loop closure).

**Q1 (resolve up-front).** OCSF class — extend 2003 Compliance Finding or use 2004 Detection Finding?

**Resolution: re-export `class_uid 2004 Detection Finding`** from `network_threat.schemas`. Threat-intel correlations are detection-shaped (IOC observed, KEV exploited, technique attributed), not compliance-shaped. D.4 Network Threat is already the canonical 2004 producer; D.8 inherits the same class and adds `finding_info.types[0]="threat_intel"` as the discriminator (4 buckets: `threat_intel_cve_in_kev_catalog` / `threat_intel_ioc_match_network` / `threat_intel_ioc_match_runtime` / `threat_intel_attack_technique_observed`). Same precedent as D.5 Data Security re-exporting F.3's 2003 schema — schema reuse over fork.

**Q2 (resolve up-front).** Live HTTP polling or offline filesystem fixtures in v0.1?

**Resolution: offline filesystem snapshots only.** Operator stages three JSON dumps per scan: NVD CVE feed (`https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz` — decompressed), CISA KEV catalog (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`), and MITRE ATT&CK enterprise STIX 2.1 bundle (`https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json`). Mirrors D.4 Network Threat's bundled-static-intel posture + D.5 Data Security's offline-mode pattern. Live polling (HTTP + caching + refresh cadence) deferred to D.8 v0.2 (same shim-behind-reader pattern).

**Q3 (resolve up-front).** IOC entity-type schema in SemanticStore?

**Resolution: three pydantic models in `threat_intel/entities.py`.** `IocEntity` (entity_type=`"ioc"`; fields: `ioc_type` ∈ {ip, domain, url, file_hash, cve_id}, `value`, `first_seen`, `last_seen`, `confidence`, `source_feed`); `CveEntity` (entity_type=`"cve"`; fields: `cve_id`, `cvss_v3_score`, `epss_score` optional, `kev_listed` bool, `kev_added_date` optional, `description`, `affected_products`); `TechniqueEntity` (entity_type=`"ttp"`; fields: `technique_id` like "T1059", `tactic` ∈ Initial Access / Execution / Persistence / etc., `name`, `description`, `platforms`). Writer uses the same `kg_writer.py` pattern proven in F.3 v0.1.5 (KG-loop closure). Single-tenant `semantic_store=None` opt-in default — when None, no SemanticStore writes happen and the agent operates entirely on the filesystem-output path. Within-run dedup proven; cross-run dedup is known debt (KG-loop §13.1) — does NOT block D.8 v0.1.

**Q4 (resolve up-front).** Cross-correlation hooks with D.1 / D.3 / D.4 — operator-pinned or autodiscovery?

**Resolution: operator-pinned via three flags.** `--vulnerability-workspace`, `--network-threat-workspace`, `--runtime-threat-workspace` — each independent. When a flag is present and the path contains a `findings.json`, the corresponding correlator runs; when absent or the file is missing, that correlator emits nothing (no exception). **Read-only**: D.8 reads sibling workspaces and never writes back to them. Mirrors D.7 Investigation's pattern + D.5 Data Security's `--cloud-posture-workspace` (Q4 there). v0.1 does NOT autodiscover sibling workspaces.

**Q5 (resolve up-front).** Tenancy — single-tenant or multi-tenant in v0.1?

**Resolution: single-tenant (`semantic_store=None` opt-in default).** Per the Path-B operating rule §11.1: SET LOCAL `$1` tenant-RLS bug NOT a v0.1 blocker; multi-tenant production blocks on the future tenant-RLS substrate-fix plan. D.8 v0.1 writes finding-artifacts to the workspace filesystem; SemanticStore writes only when an explicit instance is passed (mirrors F.3 v0.1.5 pattern after KG-loop closure). v0.2 keeps the option open; multi-tenant remains gated on the SET LOCAL fix.

**Q6 (resolve up-front).** Feed-data privacy / licensing posture?

**Resolution.** All three v0.1 feeds are public-domain / Creative Commons:

- **NVD CVE JSON 2.0** — U.S. Government work, public domain (17 U.S.C. § 105).
- **CISA KEV catalog** — CISA-published, public domain (CC0).
- **MITRE ATT&CK STIX 2.1** — Creative Commons Attribution 4.0 (CC-BY-4.0); requires attribution in derivative works. D.8's `report.md` and `findings.json` include a `mitre_attack_attribution` evidence field naming "MITRE ATT&CK®" per the licence.

**No API keys, no commercial-feed entanglement, no rate-limited endpoints.** Operator stages the three JSON files; D.8 reads them with no network calls. v0.2 introduces live polling (still public feeds; same licence terms). v0.3+ commercial feeds (VirusTotal, MISP-licensed, Recorded Future) are deferred — they bring per-customer credential management and licensing terms that need ADR-level resolution before they can land.

---

## Architecture

```
ExecutionContract (signed)
        │
        ▼
┌──────────────────────────────────────────────────────────────────┐
│ Threat Intel Agent driver                                        │
│                                                                  │
│  Stage 1: INGEST     — 3 feeds concurrent via TaskGroup          │
│  Stage 2: ENRICH     — build IOC + CVE + technique indices       │
│  Stage 3: CORRELATE  — 3 correlators concurrent via TaskGroup    │
│  Stage 4: SCORE      — deterministic severity per match type     │
│  Stage 5: SUMMARIZE  — per-correlator + per-severity sections    │
│  Stage 6: HANDOFF    — emit findings.json + report.md +          │
│                        optional SemanticStore writes             │
└─────────┬────────────────────────────────────────────────────────┘
          │
          ▼
┌──────────────────────────────────────────────────────────────────┐
│ Tools (per-stage)                                                │
│  read_nvd_feed              ─→ NVD JSON 2.0 (filesystem)         │
│  read_cisa_kev              ─→ CISA KEV catalog JSON (fs)        │
│  read_mitre_attack          ─→ STIX 2.1 ATT&CK bundle (fs)       │
│  read_d1_findings           ─→ D.1 Vulnerability workspace (opt) │
│  read_d4_findings           ─→ D.4 Network Threat workspace (opt)│
│  read_d3_findings           ─→ D.3 Runtime Threat workspace (opt)│
│  correlate_cve_kev          ─→ CVE × D.1 join + KEV flag         │
│  correlate_ioc_network      ─→ IOC × D.4 (IP / domain / URL)     │
│  correlate_ioc_runtime      ─→ IOC × D.3 (file / process hash)   │
│  kg_writer.upsert_ioc       ─→ SemanticStore (entity_type="ioc") │
│  render_summary             ─→ per-correlator + CRITICAL pinned  │
└──────────────────────────────────────────────────────────────────┘
```

**Tech stack.** Python 3.12 · BSL 1.1 · OCSF v1.3 Detection Finding (`class_uid 2004`, `types[0]="threat_intel"` discriminator) · pydantic 2.9 · click 8 · `charter.llm_adapter` (ADR-007 v1.1; plumbed, never called) · `charter.nlah_loader` (ADR-007 v1.2). Re-exports `network_threat.schemas` for the OCSF Detection Finding wire shape. No external network dependencies in v0.1.

**Depends on:**

- F.1 charter — standard budget caps; no extensions needed (D.8 is not always-on, not sub-agent-spawning).
- F.3 cloud-posture / F.5 memory engines — reuses `SemanticStore` writer pattern from F.3 v0.1.5 (KG-loop closure) for the IOC/CVE/TTP entities.
- F.4 control-plane — tenant context propagates through the contract; per-tenant cred-store integration not needed in v0.1 (no API keys; public feeds only).
- F.6 Audit Agent — every D.8 run emits a hash-chained audit chain via `charter.audit.AuditLog`.
- D.4 Network Threat — re-exports `class_uid 2004 Detection Finding` schema; 2nd re-exporter of D.4's schema (D.8 is the first; D.5 Data Security re-exported F.3's 2003).
- ADR-007 v1.1 + v1.2 — reference NLAH template. D.8 is the **12th** agent under it. v1.3 (always-on) opt-out; v1.4 (sub-agent spawning) not consumed.

**Defers (D.8 v0.2 / v0.3 / v0.4 / v0.5+, per the [2026-05-20 version-roadmap](../sketches/2026-05-20-agent-version-roadmaps.md#13-d8-threat-intel)):**

- **v0.2:** MISP integration; STIX/TAXII server polling; abuse.ch + VirusTotal IOC feeds; live HTTP polling for NVD / KEV / ATT&CK.
- **v0.3:** Active-campaign tracking (PRD §7.6.3); customer-specific correlation engine; predictive scoring.
- **v0.4:** Vertical-specific feeds (FS-ISAC for finance, H-ISAC for healthcare — Phase 2 per build-roadmap).
- **v0.5+:** Predictive-exploitation-risk modeling (Phase 3 per PRD); custom threat-actor attribution; commercial-feed credential management ADR.
- **Multi-tenant production** — blocks on the future SET LOCAL `$1` tenant-RLS substrate-fix plan (NOT this plan).
- **D.4 Network Threat v0.2 live-IOC uplift** — D.4's own future plan; D.8 ships static-feed IOCs in v0.1 and D.4 continues to consume its bundled static intel until D.4 v0.2 lands.
- **D.7 Investigation v0.3 threat-intel API integration** — cross-references D.8 v0.1's findings; D.7's own future plan, NOT this one.

**Reference template.** D.4 Network Threat (closest match — same OCSF class 2004, same external-feed-consumer pattern, same async TaskGroup ingest, same deterministic-in-v0.1 stance). D.8 is structurally D.4 with: (a) **three feeds** (NVD + KEV + ATT&CK) instead of three (Suricata + VPC flow + DNS); (b) **three correlators** against sibling-agent workspaces instead of three local detectors; (c) **SemanticStore writes** for IOC / CVE / TTP entities (new vs D.4 which is filesystem-only); (d) **shared schema** with D.4 (re-export, not fork). D.7 Investigation provides the sibling-workspace read pattern.

---

## Execution status

```
1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12 → 13 → 14 → 15 → 16
```

| Task | Status | Commit | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| ---- | ------ | ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | ⬜     |        | Bootstrap — pyproject (BSL 1.1; deps on charter / shared / eval-framework / **nexus-network-threat** for the D.4 schema re-export per Q1). py.typed + **init**. Smoke tests: ADR-007 v1.1 + v1.2 + F.1 audit log + F.5 episodic + D.4 schema re-export confirmation + 2 anti-pattern guards + 2 entry-point checks. 9 tests.                                                                                                                        |
| 2    | ⬜     |        | `schemas.py` — re-exports D.4's `class_uid 2004 Detection Finding` verbatim (Q1). Adds `ThreatIntelFindingType` enum (4 detector discriminators) + `IocType` enum (5 IOC kinds: ip, domain, url, file_hash, cve_id) + `source_token` helper. No detectors, no clients — types only.                                                                                                                                                                 |
| 3    | ⬜     |        | `tools/nvd_feed.py` — async parser for NVD CVE JSON 2.0 dumps. Forgiving on malformed entries; raises on missing / unparseable top-level. Bundled v0.1 fixture in `eval/fixtures/nvd-snapshot.json`. ~15 unit tests.                                                                                                                                                                                                                                |
| 4    | ⬜     |        | `tools/cisa_kev.py` — async parser for CISA KEV catalog JSON. Same forgiving shape; bundled v0.1 fixture in `eval/fixtures/kev-snapshot.json`. ~10 unit tests.                                                                                                                                                                                                                                                                                      |
| 5    | ⬜     |        | `tools/mitre_attack.py` — async parser for STIX 2.1 ATT&CK enterprise bundle. Extracts `attack-pattern` objects (techniques); filters out malware / intrusion-set / tool / threat-actor for v0.1 scope. ~12 unit tests.                                                                                                                                                                                                                             |
| 6    | ⬜     |        | `entities.py` (IocEntity / CveEntity / TechniqueEntity pydantic models) + `kg_writer.py` (SemanticStore upsert pattern from F.3 v0.1.5). Single-tenant `semantic_store=None` opt-in default. ~18 unit tests.                                                                                                                                                                                                                                        |
| 7    | ⬜     |        | `correlators/cve_correlator.py` — reads D.1 Vulnerability findings from operator-pinned `--vulnerability-workspace`. Joins on CVE ID; emits `threat_intel_cve_in_kev_catalog` finding when D.1 CVE appears in KEV catalog. Severity CRITICAL (KEV = actively exploited per CISA definition). ~14 unit tests.                                                                                                                                        |
| 8    | ⬜     |        | `correlators/ioc_correlator_network.py` — reads D.4 Network Threat findings. Joins on IP / domain / URL extracted from D.4 evidence against the IOC index built in Stage 2. Emits `threat_intel_ioc_match_network` finding. ~14 unit tests.                                                                                                                                                                                                         |
| 9    | ⬜     |        | `correlators/ioc_correlator_runtime.py` — reads D.3 Runtime Threat findings. Joins on file hash / process hash from D.3 evidence. Emits `threat_intel_ioc_match_runtime` finding. ~12 unit tests.                                                                                                                                                                                                                                                   |
| 10   | ⬜     |        | `scorer.py` — deterministic table-driven severity. CVE in KEV → CRITICAL; IOC match high-confidence → HIGH; IOC match medium-confidence → MEDIUM; ATT&CK technique observed → MEDIUM (correlator-output severity for v0.1; richer scoring deferred to v0.3). ~10 unit tests covering the scoring matrix.                                                                                                                                            |
| 11   | ⬜     |        | `summarizer.py` — deterministic markdown render. Per-correlator breakdown above per-severity sections (mirrors F.3 / D.4 / D.5 patterns). CRITICAL pinned. Includes MITRE ATT&CK® attribution footer per Q6 CC-BY-4.0 licence. ~8 unit tests.                                                                                                                                                                                                       |
| 12   | ⬜     |        | Agent driver `run()` — 6-stage pipeline (INGEST → ENRICH → CORRELATE → SCORE → SUMMARIZE → HANDOFF). 3-feed TaskGroup ingest + 3-correlator TaskGroup fan-out. `(contract, *, llm_provider, ...)` signature confirmed. 12th agent under ADR-007. Audit chain: 8 events. ~20 driver tests.                                                                                                                                                           |
| 13   | ⬜     |        | NLAH bundle + 21-LOC shim. ADR-007 v1.2 conformance — D.8 is the 8th agent shipped natively against v1.2 (after D.3 / F.6 / D.7 / D.4 / multi-cloud-posture / k8s-posture / D.5). README ("CTI analyst persona") + tools.md + 3 examples (CVE-in-KEV, IOC-match-network, technique-observed). LOC-budget test enforces ≤35.                                                                                                                         |
| 14   | ⬜     |        | 10 representative YAML eval cases + `ThreatIntelEvalRunner` registered via `nexus_eval_runners`. **10/10 acceptance** green via `uv run eval-framework run --runner threat_intel --cases ... --output ...`. Cases: clean-no-matches / cve-in-kev / ioc-network-match / ioc-runtime-match / technique-observed / multi-correlator-hit / no-sibling-workspaces / partial-workspace-presence / malformed-feed-tolerated / mitre-attribution-in-output. |
| 15   | ⬜     |        | CLI (`threat-intel eval` / `threat-intel run`) — two subcommands; three required-or-defaulted feed flags (`--nvd-snapshot` / `--kev-snapshot` / `--mitre-attack-snapshot`) + three optional sibling-workspace flags (`--vulnerability-workspace` / `--network-threat-workspace` / `--runtime-threat-workspace`). One-line digest; warning on no-feed. ~12 CLI tests.                                                                                |
| 16   | ⬜     |        | README polish + smoke runbook (`runbooks/ti_correlation_scan.md`, 8 sections) + verification record (`docs/_meta/d-8-threat-intel-v0-1-verification-2026-05-22.md`). ADR-007 v1.1 + v1.2 conformance verified end-to-end; v1.3 + v1.4 opt-outs confirmed. Coverage ≥ 80% on `threat_intel.*`. WI-1 through WI-5 verified at close. **D.8 v0.1 done; second of 7 unbuilt agents shipped under Path-B operating rule. Next: D.6 Compliance v0.1.**    |

ADR references: [ADR-001](../../_meta/decisions/ADR-001-monorepo-bootstrap.md) · [ADR-004](../../_meta/decisions/ADR-004-fabric-layer.md) · [ADR-005](../../_meta/decisions/ADR-005-async-tool-wrapper-convention.md) · [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) · [ADR-008](../../_meta/decisions/ADR-008-eval-framework.md) · [ADR-009](../../_meta/decisions/ADR-009-memory-architecture.md) · [ADR-011](../../_meta/decisions/ADR-011-pr-flow-and-branch-protection-discipline.md).

---

## Resolved questions

| #   | Question                                              | Resolution                                                                                                                                                                                        | Task          |
| --- | ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------- |
| Q1  | OCSF class — extend 2003 or use 2004?                 | **Re-export D.4's `class_uid 2004` Detection Finding** with `types[0]="threat_intel"` discriminator + 4-bucket `ThreatIntelFindingType` enum. 2nd re-exporter of D.4's schema.                    | Task 2        |
| Q2  | Live polling or offline fixtures in v0.1?             | **Offline filesystem snapshots only** for all 3 feeds. Live HTTP polling ships D.8 v0.2.                                                                                                          | Tasks 3-5     |
| Q3  | IOC entity-type schema in SemanticStore?              | **3 pydantic models** (IocEntity / CveEntity / TechniqueEntity); `kg_writer.py` adapter; `semantic_store=None` opt-in default.                                                                    | Task 6        |
| Q4  | Cross-correlation — operator-pinned or autodiscovery? | **Operator-pinned** via 3 independent flags. Each correlator gracefully no-ops when its workspace flag is absent or `findings.json` missing. Read-only.                                           | Tasks 7-9, 12 |
| Q5  | Tenancy in v0.1?                                      | **Single-tenant** (`semantic_store=None` opt-in default). Multi-tenant blocks on future SET LOCAL `$1` fix.                                                                                       | Task 12       |
| Q6  | Feed-data privacy / licensing?                        | **All 3 v0.1 feeds public-domain / CC**. NVD: 17 U.S.C. § 105. CISA KEV: CC0. MITRE ATT&CK: CC-BY-4.0 (attribution footer required in `report.md`). No API keys; no commercial-feed entanglement. | Task 11       |

---

## File map (target)

```
packages/agents/threat-intel/
├── pyproject.toml                              # Task 1
├── README.md                                   # Tasks 1, 16
├── runbooks/
│   └── ti_correlation_scan.md                  # Task 16
├── src/threat_intel/
│   ├── __init__.py                             # Task 1
│   ├── py.typed                                # Task 1
│   ├── schemas.py                              # Task 2 (D.4 re-exports + ThreatIntelFindingType + IocType)
│   ├── nlah_loader.py                          # Task 13 (21-LOC shim)
│   ├── entities.py                             # Task 6 (IocEntity / CveEntity / TechniqueEntity)
│   ├── kg_writer.py                            # Task 6 (SemanticStore upsert adapter)
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── nvd_feed.py                         # Task 3
│   │   ├── cisa_kev.py                         # Task 4
│   │   └── mitre_attack.py                     # Task 5
│   ├── correlators/
│   │   ├── __init__.py
│   │   ├── cve_correlator.py                   # Task 7
│   │   ├── ioc_correlator_network.py           # Task 8
│   │   └── ioc_correlator_runtime.py           # Task 9
│   ├── scorer.py                               # Task 10
│   ├── summarizer.py                           # Task 11
│   ├── agent.py                                # Task 12 (driver: 6-stage pipeline)
│   ├── eval_runner.py                          # Task 14
│   └── cli.py                                  # Task 15
├── nlah/
│   ├── README.md                               # Task 13 (CTI analyst persona)
│   ├── tools.md                                # Task 13
│   └── examples/                               # Task 13 (3 examples: CVE-in-KEV, IOC-network, technique-observed)
├── eval/
│   ├── cases/                                  # Task 14 (10 YAML cases)
│   └── fixtures/                               # Tasks 3-5 (small NVD + KEV + ATT&CK snapshots)
└── tests/
    ├── test_smoke.py                           # Task 1
    ├── test_schemas.py                         # Task 2
    ├── test_tools_nvd_feed.py                  # Task 3
    ├── test_tools_cisa_kev.py                  # Task 4
    ├── test_tools_mitre_attack.py              # Task 5
    ├── test_entities.py                        # Task 6
    ├── test_kg_writer.py                       # Task 6
    ├── test_correlators_cve.py                 # Task 7
    ├── test_correlators_ioc_network.py         # Task 8
    ├── test_correlators_ioc_runtime.py         # Task 9
    ├── test_scorer.py                          # Task 10
    ├── test_summarizer.py                      # Task 11
    ├── test_agent.py                           # Task 12
    ├── test_nlah_loader.py                     # Task 13
    ├── test_eval_runner.py                     # Task 14 (incl. 10/10 acceptance)
    └── test_cli.py                             # Task 15
```

---

## Risks

| Risk                                                                                                                                                    | Mitigation                                                                                                                                                                                                                                                                                               |
| ------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Schema re-export from D.4 creates coupling; if D.4 amends `class_uid 2004` shape, D.8 has to follow.                                                    | Acceptable — Detection Finding shape is stable v0.1 and proven across D.4 production. D.8 is the 2nd re-exporter of 2004 (after D.4 itself); we monitor for breakage.                                                                                                                                    |
| 3 feeds × 3 correlators = larger v0.1 surface than D.5 (which had 2 feeds × 4 detectors).                                                               | Each correlator is a pure function with its own test file. Mirrors D.4's 3-feed shape. Test budget per the breakdown above (~180 unit tests + 10 eval cases) sits at ~190 tests — comparable to D.5's 292 and within the ADR-007 reference template's expected surface for a 16-task agent.              |
| Sibling-workspace reads (D.1 / D.3 / D.4) couple D.8 to those agents' OCSF output shapes; if any of them changes finding format, D.8 silently degrades. | Per-correlator validation: read sibling findings as raw dicts and validate the minimal fields D.8 cares about (CVE ID, IOC strings, file/process hashes). On validation failure, drop the entry silently + log a one-line warning. Eval case 008 (`partial_workspace_presence`) is the regression probe. |
| MITRE ATT&CK CC-BY-4.0 licence requires attribution in derivative works; missing attribution is a licence violation.                                    | Summarizer (Task 11) emits a fixed footer `"Includes data from MITRE ATT&CK®, © The MITRE Corporation. Licensed under CC-BY-4.0."` in `report.md`. Eval case 010 (`mitre_attribution_in_output`) is the regression probe.                                                                                |
| SemanticStore writes (Task 6) introduce a multi-tenant code path that exercises the SET LOCAL `$1` bug.                                                 | v0.1 ships `semantic_store=None` opt-in default — by default, NO writes happen. Multi-tenant production blocks on the future tenant-RLS substrate-fix plan. v0.1 single-tenant in-memory `aiosqlite` is supported for testing only.                                                                      |
| KEV catalog updates daily; v0.1's offline-mode means "active exploitation" labels go stale as the snapshot ages.                                        | Documented permanent limitation in README + runbook. Operators stage a fresh KEV snapshot per scan. v0.2 introduces live polling with a cache-TTL.                                                                                                                                                       |
| 3-correlator TaskGroup fan-out raises concurrency concerns if one correlator throws — TaskGroup cancels the others.                                     | Each correlator wraps its inner I/O in a try/except that converts unexpected exceptions into a typed `CorrelatorError`. The driver collects errors and proceeds with whichever correlators succeeded. Eval case 009 (`malformed_feed_tolerated`) is the regression probe.                                |

---

## Watch-items (carry-forward to verification record)

- **WI-1: Substrate sealed.** No changes to `packages/charter/`, `packages/shared/`, `packages/eval-framework/`. Empty-diff proof at close per sketch §8 invariant 1.
- **WI-2: Correlators stay agent-local.** No charter hoist in v0.1. Revisit at 3rd consumer if D.12 Curiosity or D.13 Synthesis end up needing the cross-finding-ARN join pattern.
- **WI-3: Single-tenant.** `semantic_store=None` default. SET LOCAL `$1` bug NOT touched. Multi-tenant production blocks on future tenant-RLS substrate plan.
- **WI-4: MITRE ATT&CK attribution.** Eval case `mitre_attribution_in_output` green; summarizer footer stable across all output paths.
- **WI-5: No SAFETY-CRITICAL paths.** LOW-RISK label on every task PR. No `packages/charter/` or `packages/shared/` touches.

---

## Done definition

D.8 Threat Intel v0.1 is **done** when:

- 16/16 tasks closed; every commit pinned in the execution-status table.
- ≥ 80% test coverage on `packages/agents/threat-intel` (gate same as F.3 / D.1 / D.3 / D.7 / D.4 / multi-cloud-posture / k8s-posture / D.5).
- `ruff check` + `ruff format --check` + `mypy --strict` clean.
- `eval-framework run --runner threat_intel` returns 10/10.
- ADR-007 v1.1 + v1.2 conformance verified end-to-end; v1.3 + v1.4 opt-outs confirmed.
- README + smoke runbook reviewed.
- D.8 v0.1 verification record committed at `docs/_meta/d-8-threat-intel-v0-1-verification-2026-05-22.md`.
- Watch-items WI-1 through WI-5 verified at close.

That closes the **second of 7 unbuilt agents** under the Path-B operating rule. **D.6 Compliance v0.1** follows at the same cadence per sketch §8 sequence.

---

## ADR-011 cadence (per-task discipline)

Every numbered task above lands as its **own PR** off branches like `feat/d-8-task-N-<scope>`. Per [ADR-011](../../_meta/decisions/ADR-011-pr-flow-and-branch-protection-discipline.md):

- **LOW-RISK label** (title text) on every D.8 task — all changes are scoped to `packages/agents/threat-intel/` (new package, isolated). No SAFETY-CRITICAL paths (no `packages/charter/` or `packages/shared/` touches).
- **Report → review → merge → next task.** After each task commits + the PR opens, pause for review. Don't start the next task until the prior task PR merges or is approved.
- **Verified-against-HEAD sentence** in PR body for every task: "Verified against HEAD = `<sha>` — tests + ruff + mypy green."
- **Execution-status table is single source of truth** for task-commit pinning per ADR-010. Verification record cites; does not duplicate.

---

## Next plans queued (for context, per Path-B operating rule)

- **D.8 Threat Intel v0.1** (this plan) — second of 7 unbuilt agents.
- **D.6 Compliance v0.1** — cross-source framework-mapping over existing detect findings (depends on D.5 + D.8 having shipped).
- **D.13 Synthesis v0.1** — LLM-driven cross-agent narration.
- **D.12 Curiosity v0.1** — depends on F.7 `claims.>` substrate ADR shipping first (out-of-scope here).
- **A.4 Meta-Harness v0.1** — depends on all 6 D-track agents existing with eval suites.
- **Supervisor (#0) v0.1** — last; depends on all 17 prior agents.

After Supervisor v0.1 closes (17/17 at v0.1), the Path-B operating rule opens the second-pass conversation: which agent's v0.2 first? Driven by design-partner signal at that point.

---

## Reference template

Follows [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) (reference NLAH) + [ADR-010](../../_meta/decisions/ADR-010-version-extension-template.md) (within-agent version-extension template; D.8 v0.1 is initial-version, so ADR-010 applies only to D.8 v0.2 and later). D.5 Data Security v0.1's [closing verification record](../../_meta/d-5-data-security-v0-1-verification-2026-05-20.md) is the closest reference for cadence + verification-record shape.
