# Compliance Agent — Tools Reference

Five tool-level entry points, grouped by stage. Only the CIS YAML loader is charter-registered (whitelist-checked, budget-counted, audit-logged); the two correlators + aggregator + scorer + summarizer are called directly from the driver (filesystem-only or pure-function, no charter-budget impact).

## Stage 1: INGEST

### `read_cis_aws_benchmark(*, path: Path | None = None) -> tuple[CisControl, ...]`

Async filesystem reader for the bundled CIS AWS Foundations Benchmark v3.0 YAML library. Per ADR-005, the filesystem read happens on `asyncio.to_thread`. When `path=None`, reads the bundled `compliance/control_libraries/cis_aws_v3.yaml` via `importlib.resources`.

- Parses control_id (dotted decimal), name, level (level_1 / level_2), applicability, required, paraphrased description, source_mappings (per-source-agent rule_id list).
- Forgiving on individual control entries (unknown level / missing control_id / pydantic validation failure → dropped silently with a structlog warning).
- Raises `CisAwsBenchmarkReaderError` on missing file / dir-not-file / malformed YAML / non-mapping top-level / non-list `controls` field.

## Stage 3: CORRELATE (two correlators, concurrent)

### `correlate_cloud_posture(*, cloud_posture_workspace, control_index, correlated_at, envelope) -> tuple[ComplianceFinding, ...]`

Joins F.3 Cloud Posture findings (read from operator-pinned `--cloud-posture-workspace`) against the bundled CIS library. For each F.3 finding whose `compliance.control` rule_id (e.g. `CSPM-AWS-IAM-001`) is referenced by one or more CIS controls in the library, emits one per-mapping ComplianceFinding.

- Per-mapping emit; aggregator (Stage 4) collapses to per-control roll-up.
- Severity at emit time = `severity_for_level(mapping.level, required=mapping.required)`.
- Resources: F.3's OCSF `resources[]` projected back into D.9's `AffectedResource` shape (preserving AWS `owner.account_uid` over envelope tenant when present).
- Forgiving on every failure (missing workspace / missing/malformed findings.json / non-2003 entries / missing compliance block silently skipped).
- Finding-id: `COMPLIANCE-CIS_AWS_V3-<control_token>-NNN-f3_<hash>` (8-char SHA-256 of the source F.3 finding-id).
- Evidence: `source_finding` block (agent=cloud_posture / finding_id / rule_id) + `control` block (framework / control_id / level / required) for D.7 cross-reference.

### `correlate_data_security(*, data_security_workspace, control_index, correlated_at, envelope) -> tuple[ComplianceFinding, ...]`

Mirrors `correlate_cloud_posture` exactly, with the following deltas:

- Workspace flag: `--data-security-workspace`.
- Index lookup key: `("data_security", rule_id)`.
- Finding-id context: `d5_<hash>` (vs `f3_<hash>`).
- Evidence `source_finding.agent = "data_security"`.

D.5's `compliance.control` field carries the short rule_id (`s3_bucket_public`, `s3_bucket_unencrypted`, `s3_oversharing_iam`, `s3_object_sensitive_in_untrusted_location`); D.9 joins on that form. The full `DataSecurityFindingType.value` discriminator lives in D.5's `evidence.source_finding_type` but D.9 doesn't read from there in v0.1.

## Stage 4: AGGREGATE

### `aggregate_controls(findings, *, envelope, aggregated_at) -> tuple[ComplianceFinding, ...]`

Pure, deterministic. Collapses per-mapping ComplianceFindings (from Tasks 6 + 7) into one finding per `(control, status-change)` tuple.

- Group by `compliance.control` value.
- Emit FAIL if any contributor has severity ≥ `Severity.MEDIUM` (the FAIL-floor gate).
- Severity at emit time = `max()` over contributors.
- Resource union with arn-dedup.
- v0.1 ships **FAIL-only output**; PASS-only controls (only LOW contributors) are omitted from output. v0.2 lifts this for attestation export.
- Finding-id: `COMPLIANCE-CIS_AWS_V3-<control_token>-NNN-aggregated`.
- Evidence: `aggregated_status` + `contributor_count` + `contributing_finding_ids` + `contributing_source_findings` + `control` blocks (full traceability back to per-mapping + source-finding provenance).

## Stage 5: SCORE

### `score_findings(findings) -> tuple[ComplianceFinding, ...]`

Pure, deterministic re-stamp. Reads `evidence.control.{level, required}` and applies the canonical Level × required → Severity table:

- Level 1 + required → HIGH.
- Level 1 + recommended → MEDIUM.
- Level 2 + required → MEDIUM.
- Level 2 + recommended → LOW.

Findings already at the canonical severity are returned unchanged (identity preserved). Mismatched findings get a new `ComplianceFinding` with updated `severity_id` + `severity` string; everything else (finding_info.uid, nexus_envelope, evidence, resources) stays verbatim.

## Stage 6: SUMMARIZE

### `render_summary(report) -> str`

Renders the OCSF findings report as a markdown document with:

1. Header + metadata (customer, run_id, scan window, total failures).
2. Posture summary table (Level 1 vs Level 2 failure counts).
3. Severity breakdown (CRITICAL → INFO).
4. Failing controls breakdown (per CIS control id, sorted lexicographically).
5. **CIS Level-1 failures pinned section** above per-severity sections.
6. Per-severity sections (CRITICAL → LOW).
7. **CIS Benchmarks® attribution footer** (always emitted, including on empty reports; explicitly declares no-verbatim-Securesuite-text per WI-2).
