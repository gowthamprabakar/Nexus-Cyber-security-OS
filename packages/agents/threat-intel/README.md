# `nexus-threat-intel-agent`

Threat Intel Agent — **D.8**; **second of the 7 unbuilt agents** shipped under the [2026-05-20 Path-B-breadth-first operating rule](../../../docs/superpowers/sketches/2026-05-20-agent-version-roadmaps.md); **twelfth under [ADR-007](../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)** (F.3 / D.1 / D.2 / D.3 / F.6 / D.7 / D.4 / multi-cloud-posture / k8s-posture / A.1 / D.5 / **D.8**). Lifts platform coverage from siloed detection to threat-context correlation — the first agent that consumes external threat-intel feeds (NVD CVE + CISA KEV + MITRE ATT&CK) and joins them against sibling-agent findings to elevate risk.

> **v0.1 shipped 2026-05-21.** 16 tasks, PRs #73-#88 merged. 249 tests passing. 10/10 eval cases pass. Q6 CC-BY-4.0 attribution verified at unit, render, and CLI layers. See [`docs/_meta/d-8-threat-intel-v0-1-verification-2026-05-21.md`](../../../docs/_meta/d-8-threat-intel-v0-1-verification-2026-05-21.md) for the closure record.

## Scope (v0.1)

**3 public, no-auth feeds** (offline-mode JSON snapshots staged by the operator):

- **NVD CVE JSON 2.0** (public domain).
- **CISA KEV catalog** (CC0).
- **MITRE ATT&CK STIX 2.1** (CC-BY-4.0 — attribution footer required in `report.md`).

**3 sibling-workspace correlators** (read-only):

- `correlate_cve_kev` against D.1 Vulnerability findings.
- `correlate_ioc_network` against D.4 Network Threat findings.
- `correlate_ioc_runtime` against D.3 Runtime Threat findings.

SemanticStore writes for IOC / CVE / TTP entities (single-tenant `semantic_store=None` opt-in default). OCSF v1.3 Detection Finding (`class_uid 2004`) re-exported from D.4 with `finding_info.types[0]="threat_intel_*"` discriminator. Deterministic (no LLM in loop).

## Deferred to D.8 v0.2 / v0.3 / v0.4 / v0.5+

- **v0.2:** live HTTP polling; MISP + STIX/TAXII; abuse.ch + VirusTotal IOC feeds (populates IP / DOMAIN / URL / FILE_HASH buckets in the IOC index).
- **v0.3:** active-campaign tracking; customer-specific correlation engine; composite scoring (CVSS × EPSS × KEV × asset-criticality).
- **v0.4:** vertical-specific feeds (FS-ISAC / H-ISAC).
- **v0.5+:** predictive exploitation-risk modeling; custom threat-actor attribution; commercial-feed credential management ADR.
- **Multi-tenant production** blocks on the future SET LOCAL `$1` tenant-RLS substrate-fix plan.

Full version trajectory: [`docs/superpowers/sketches/2026-05-20-agent-version-roadmaps.md` §13](../../../docs/superpowers/sketches/2026-05-20-agent-version-roadmaps.md#13-d8-threat-intel).

## ADR-007 conformance

D.8 is the **12th** agent under the reference template, **8th** shipped natively against v1.2 (D.3 / F.6 / D.7 / D.4 / multi-cloud-posture / k8s-posture / D.5 / **D.8**). Inherits v1.1 (LLM adapter via `charter.llm_adapter`; no per-agent `llm.py`) and v1.2 (NLAH loader is a 21-LOC shim over `charter.nlah_loader`). **Not** in the v1.3 always-on class — D.8 honours every budget axis. **Does not consume** the v1.4 candidate (sub-agent spawning primitive); single-driver per the agent spec.

**Schema reuse (Q1).** D.8 re-exports D.4's `class_uid 2004 Detection Finding` schema verbatim — `Severity`, `AffectedResource` (from `cloud_posture.schemas`), the OCSF constants. Adds `ThreatIntelFindingType` enum (4 correlator buckets) + `IocType` enum (5 IOC kinds) + its own `THREAT_INTEL_FINDING_ID_RE` and `build_finding` on top. Downstream consumers (D.7, Meta-Harness) filter on `class_uid == 2004` first then on `finding_info.types[0] == "threat_intel_*"` to disambiguate.

## Smoke runbook

### 1. Stage offline feed snapshots

```bash
# NVD CVE 2.0 — public domain.
curl -sL "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=100" \
    > /tmp/nvd-cve-snapshot.json

# CISA KEV catalog — CC0.
curl -sL https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json \
    > /tmp/cisa-kev-snapshot.json

# MITRE ATT&CK STIX 2.1 enterprise bundle — CC-BY-4.0.
curl -sL https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json \
    > /tmp/mitre-attack-snapshot.json
```

> **v0.2 will replace these with live HTTP polling** behind the same `read_*` wrapper signatures. v0.1 keeps the operator-staged offline mode so commercial-feed credential management can land in its own ADR.

### 2. Run the agent

```bash
uv run threat-intel run \
    --contract path/to/execution-contract.yaml \
    --nvd-snapshot /tmp/nvd-cve-snapshot.json \
    --kev-snapshot /tmp/cisa-kev-snapshot.json \
    --mitre-attack-snapshot /tmp/mitre-attack-snapshot.json \
    --vulnerability-workspace path/to/d1-vuln-run/ \
    --network-threat-workspace path/to/d4-net-run/ \
    --runtime-threat-workspace path/to/d3-runtime-run/
```

Each sibling workspace must contain a `findings.json` produced by the corresponding agent (D.1 Vulnerability, D.4 Network Threat, D.3 Runtime Threat). The agent writes `findings.json` + `report.md` to the contract's workspace and prints a one-line digest of severity + finding-type counts.

**Skipped inputs are tolerated.** Any combination of the six input flags may be omitted; the corresponding correlator silently emits zero findings. The MITRE ATT&CK CC-BY-4.0 attribution footer is rendered in `report.md` even on empty runs (Q6 compliance).

### 3. Run the local eval suite

```bash
uv run threat-intel eval packages/agents/threat-intel/eval/cases
```

Expected output: `10/10 passed`. Exit code 1 on any failure with per-failure `FAIL <case_id>: <reason>` lines.

### 4. Run the unit test suite

```bash
uv run pytest packages/agents/threat-intel -q
```

Expected: **249 passed** in <1s.

## Architecture

Six-stage pipeline:

```text
INGEST  -> ENRICH    -> CORRELATE      -> SCORE      -> SUMMARIZE -> HANDOFF
(3 feeds   (build CVE/   (3 correlators    (canonical    (markdown    (findings.json
 via Task   KEV/TTP +     vs sibling        severity      with KEV-     + report.md
 Group)     IOC indices   workspaces        table-driven  pinned +      to charter
            + optional     via TaskGroup)   re-stamp)     attribution   workspace)
            KG writes)                                    footer)
```

| Stage        | Module                                                                                              | Output                                                         |
| ------------ | --------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| 1. INGEST    | `tools/{nvd_feed,cisa_kev,mitre_attack}.py`                                                         | `(NvdCveRecord[], KevEntry[], TechniqueRecord[])`              |
| 2. ENRICH    | `correlators/{cve_correlator.build_kev_index, ioc_index.build_ioc_index}` + `kg_writer.py` (opt-in) | `(kev_index, ioc_index)` + optional SemanticStore writes       |
| 3. CORRELATE | `correlators/{cve_correlator, ioc_correlator_network, ioc_correlator_runtime}.py`                   | `tuple[ThreatIntelFinding, ...]`                               |
| 4. SCORE     | `scorer.py`                                                                                         | canonical-severity re-stamped findings                         |
| 5. SUMMARIZE | `summarizer.py`                                                                                     | markdown with CVE-in-KEV pinned + CC-BY-4.0 attribution footer |
| 6. HANDOFF   | `agent.py`                                                                                          | `findings.json` + `report.md` to charter workspace             |

## License

BSL 1.1 per [ADR-001](../../../docs/_meta/decisions/ADR-001-monorepo-bootstrap.md). Substrate this agent consumes (`charter`, `network-threat`, `vulnerability`, `runtime-threat`, `cloud-posture`, `eval-framework`) is Apache 2.0; the agent itself is BSL.

**Third-party feed attribution** (carried in every `report.md` per Q6):

- **MITRE ATT&CK®** — CC-BY-4.0 — https://attack.mitre.org/
- **NVD** — public domain — https://nvd.nist.gov/
- **CISA KEV** — CC0 — https://www.cisa.gov/known-exploited-vulnerabilities-catalog
