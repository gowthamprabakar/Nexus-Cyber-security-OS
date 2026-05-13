# Multi-Cloud Posture Agent — Tools Reference

Seven tools, grouped by stage. Four readers are async-safe (per ADR-005) so the agent driver can fan them out via `asyncio.TaskGroup`; the two normalizers + summarizer are pure functions.

## Stage 1: INGEST (four feeds, concurrent)

### `read_azure_findings(*, path: Path) -> tuple[AzureDefenderFinding, ...]`

Async parser for Azure Defender for Cloud JSON exports. Supports three top-level shapes (`{"value": [...]}` canonical, bare array, heuristic-classified). Auto-detects assessment vs alert via `type` field or property-key heuristic.

- Severity normalisation: lowercase → TitleCase (`high` → `High`); non-canonical values dropped.
- Timestamp resolution tries kind-specific keys (`timeGeneratedUtc` / `startTimeUtc` / `lastEvaluationTimeUtc`).
- Subscription ID extracted from `/subscriptions/<id>/...` in `record_id`.
- Preserves `alertType` / `compromisedEntity` / `category` / `remediation` under `unmapped`.
- Forgiving on malformed entries; top-level malformed JSON raises explicitly.

### `read_azure_activity(*, path: Path) -> tuple[AzureActivityRecord, ...]`

Async parser for Azure Activity Log JSON. Supports `{"value": [...]}` canonical + bare-array shapes.

- `operationName` classified into 6 buckets (`iam` / `network` / `storage` / `compute` / `keyvault` / `other`) via case-insensitive regex against `Microsoft.*` resource-provider prefixes.
- Accepts `operationName` / `category` / `status` as either string or `{"value": ..., "localizedValue": ...}` dict (Azure exports vary by tool).
- `subscription_id` + `resource_group` extracted from `/subscriptions/x/resourceGroups/<rg>/...` paths.
- Preserves `correlationId` / `operationId` / `callerIpAddress` / `claims` / `httpRequest` / `properties` / `authorization` / `tenantId` under `unmapped`.

### `read_gcp_findings(*, path: Path) -> tuple[GcpSccFinding, ...]`

Async parser for GCP Security Command Center findings JSON. Three top-level shapes auto-detected: canonical `ListFindingsResponse`, `gcloud` wrapper (`{"findings": [...]}`), and bare array.

- Severity normalised (lowercase → UPPERCASE; non-canonical dropped). Accepts `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `SEVERITY_UNSPECIFIED`.
- `INACTIVE`-state findings still parsed (operators want to see closed findings); the normalizer drops them so the report shows only active posture issues.
- `project_id` extracted from `resource_name` (handles compute / storage / cloudresourcemanager resource paths).
- `parent` derived from name when absent; `resourceName` falls back to `resource.name` when missing.
- Preserves `sourceProperties` / `indicator` / `vulnerability` / `compliances` / `mitreAttack` / `iamBindings` / `nextSteps` under `unmapped`.

### `read_gcp_iam_findings(*, path: Path, customer_domain_allowlist: tuple[str, ...] = ()) -> tuple[GcpIamFinding, ...]`

Async Cloud Asset Inventory IAM analyser. Supports two top-level shapes (bare array + `{"results": [...]}` canonical). **Deterministic flagging rules** (no LLM):

- `allUsers` / `allAuthenticatedUsers` + impersonation role (`serviceAccountUser`/`Token Creator`) → **CRITICAL**
- `allUsers` / `allAuthenticatedUsers` + any other role → **HIGH**
- `roles/owner` to `user:*@<external>` (external = not in `customer_domain_allowlist`) → **CRITICAL**
- `roles/owner` to user/group/serviceAccount → **HIGH**
- `roles/editor` to user → **MEDIUM**
- everything else → benign (no finding)

Stale-service-account check deferred to Phase 1c (needs IAM usage API).

## Stage 2: NORMALIZE

### `normalize_azure(*, defender: Sequence[AzureDefenderFinding] = (), activity: Sequence[AzureActivityRecord] = (), envelope: NexusEnvelope, scan_time: datetime) -> tuple[CloudPostureFinding, ...]`

Pure function lifting Azure reader outputs into OCSF 2003 Compliance Findings via F.3's re-exported `build_finding`. Severity mapping per the README; healthy-assessment filter drops `status="Healthy"` Defender records; activity-class filter drops `compute` / `other` operations. Per-(subscription, source) sequence counter for stable finding_ids matching `CSPM-AZURE-{DEFENDER|ACTIVITY}-NNN-<slug>`.

### `normalize_gcp(*, scc: Sequence[GcpSccFinding] = (), iam: Sequence[GcpIamFinding] = (), envelope: NexusEnvelope, scan_time: datetime) -> tuple[CloudPostureFinding, ...]`

Pure function lifting GCP reader outputs into OCSF 2003 Compliance Findings. Severity 1:1 map for SCC and IAM. SCC `INACTIVE` records dropped in the normalizer. Per-(project, source) sequence counter for stable finding_ids matching `CSPM-GCP-{SCC|IAM}-NNN-<slug>`.

## Stage 4: SUMMARIZE

### `render_summary(report: FindingsReport) -> str`

(Lands in Task 10.)

Renders the OCSF findings report as a markdown document with per-cloud breakdown pinned above per-severity sections. CRITICAL findings pinned at the top.
