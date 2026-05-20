# Threat Intel Agent — Tools Reference

Six tools, grouped by stage. Stage-1 INGEST tools are charter-registered (whitelist-checked, budget-counted, audit-logged); Stage-3 CORRELATE functions are called directly from the driver (filesystem-only, no charter-budget impact).

## Stage 1: INGEST (three feeds, concurrent)

### `read_nvd_feed(*, path: Path) -> tuple[NvdCveRecord, ...]`

Async filesystem reader for NVD CVE 2.0 JSON snapshots. Per ADR-005 the filesystem read happens on `asyncio.to_thread`.

- Parses CVE ID, English description, published / lastModified timestamps, vuln status, CVSS v3 score + severity, references.
- CVSS extraction prefers v3.1, falls back to v3.0; multi-language descriptions resolved to English.
- Forgiving — malformed objects dropped; raises `NvdCveReaderError` on missing file / bad file type / malformed top-level JSON.

### `read_cisa_kev(*, path: Path) -> tuple[KevEntry, ...]`

Async filesystem reader for the CISA KEV catalog JSON. Per ADR-005, `asyncio.to_thread`.

- Parses CVE ID, vendor/project, product, vulnerability name, date_added (date), short_description, required_action, due_date (date|None), known_ransomware_campaign_use (only `"Known"` -> True; conservative).
- Forgiving on malformed objects; raises `CisaKevReaderError` on missing/bad file or malformed top-level JSON.

### `read_mitre_attack(*, path: Path) -> tuple[TechniqueRecord, ...]`

Async filesystem reader for MITRE ATT&CK STIX 2.1 bundle JSON. v0.1 scope: only `attack-pattern` objects (techniques + sub-techniques). Drops `revoked`, `x_mitre_deprecated`, plus all non-`attack-pattern` STIX object types (malware, intrusion-set, tool, threat-actor, relationship).

Parses technique_id (`T<num>` or `T<num>.<sub>`), name, description, tactics (from `kill_chain_phases[].phase_name`), platforms, is_subtechnique, url.

## Stage 3: CORRELATE (three correlators, concurrent)

### `correlate_cve_kev(*, vulnerability_workspace, kev_index, correlated_at, envelope) -> tuple[ThreatIntelFinding, ...]`

Joins D.1 Vulnerability findings against the CISA KEV catalog. For each (D.1 finding, CVE ID) pair where the CVE is in KEV, emits one `ThreatIntelFinding` of type `CVE_IN_KEV_CATALOG` at severity CRITICAL.

- Reads `findings.json` from the operator-pinned `vulnerability_workspace` via `asyncio.to_thread`.
- Forgiving on every failure (missing workspace, malformed JSON, non-2002 entries, bad VULN-finding-ids silently dropped).
- Evidence carries the full KEV-entry block (vendor, product, date_added, due_date, ransomware flag, required_action) + source D.1 finding-id + title for D.7 cross-reference.

### `correlate_ioc_network(*, network_threat_workspace, ioc_index, correlated_at, envelope) -> tuple[ThreatIntelFinding, ...]`

Joins D.4 Network Threat findings against the IOC index. Observables extracted:

- `affected_networks[].ip` and `affected_networks[].traffic.dst_ip` -> `(IP, ip)`.
- `evidences[0].src_ip` / `dst_ip` -> `(IP, ip)`.
- `evidences[0].query_name` (DGA findings) -> `(DOMAIN, ...)`.
- CVE-IDs regex-matched in `evidences[0].signature` (Suricata findings) -> `(CVE_ID, ...)`.

Severity from `IocEntity.confidence`: ≥0.8 HIGH, 0.5-0.79 MEDIUM, <0.5 LOW. Within-finding dedup so the same (IocType, value) doesn't emit twice for one D.4 finding.

### `correlate_ioc_runtime(*, runtime_threat_workspace, ioc_index, correlated_at, envelope) -> tuple[ThreatIntelFinding, ...]`

Joins D.3 Runtime Threat findings against the IOC index. Observables extracted:

- `affected_hosts[].ip[]` -> `(IP, ip)`.
- `evidences[0].remote_ip` (NETWORK findings) -> `(IP, ip)`.
- `evidences[0].{file_hash,sha256,sha1,md5,proc_hash,process_hash,binary_hash}` -> `(FILE_HASH, ...)`.

URL observables NOT extracted in v0.1 (D.4 doesn't carry URLs as a top-level field; freeform signature URL parsing deferred to v0.2 alongside abuse.ch / VirusTotal URL-IOC feeds).

## Stage 4: SCORE

### `score_findings(findings) -> tuple[ThreatIntelFinding, ...]`

Pure, deterministic re-stamp. Table:

- `CVE_IN_KEV_CATALOG` -> CRITICAL.
- `IOC_MATCH_NETWORK` / `IOC_MATCH_RUNTIME` (conf >=0.8) -> HIGH.
- IOC match (0.5 <= conf < 0.8) -> MEDIUM.
- IOC match (conf < 0.5) -> LOW.
- `ATTACK_TECHNIQUE_OBSERVED` -> MEDIUM.

Findings whose correlator-emitted severity already matches canonical are returned unchanged (identity preserved). Mismatched findings get a new `ThreatIntelFinding` with updated `severity_id` + `severity` string; the rest of the payload (finding_info.uid, nexus_envelope, evidence) stays verbatim.

## Stage 5: SUMMARIZE

### `render_summary(report) -> str`

Renders the OCSF findings report as a markdown document with CVE-in-KEV pinned above per-severity sections plus the **MITRE ATT&CK CC-BY-4.0 attribution footer** (always emitted, including on empty reports).
