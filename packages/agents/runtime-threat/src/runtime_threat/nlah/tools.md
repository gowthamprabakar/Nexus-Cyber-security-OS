# Tools reference

Every tool below is async (per [ADR-005](../../../../../docs/_meta/decisions/ADR-005-async-tool-wrapper-convention.md)). Permissions and budget impact go through the runtime charter.

## `falco_alerts_read`

Read a Falco JSONL feed (Falco's `json_output` mode).

**Signature:** `await falco_alerts_read(*, feed_path, timeout_sec=60.0)`

**Output:** `tuple[FalcoAlert, ...]` with `time`, `rule`, `priority`, `output`, `output_fields: dict`, `tags: tuple[str, ...]`.

**Notes:** Tolerates malformed JSONL lines (silently skips). Missing feed file → `FalcoError`. Live Falco gRPC streaming is Phase 1c.

## `tracee_alerts_read`

Read a Tracee JSONL alert feed.

**Signature:** `await tracee_alerts_read(*, feed_path, timeout_sec=60.0)`

**Output:** `tuple[TraceeAlert, ...]` with `timestamp` (parsed from nanoseconds), `event_name`, `process_name`, `process_id`, `host_name`, `container_image`, `container_id`, `args: dict[str, str]` (flattened from `[{name, value}, ...]`), `severity: int` (0-3), `description`, `pod_name`, `namespace`.

**Notes:** Tolerates malformed lines + missing optional sub-dicts (Tracee builds without container/k8s context still parse). ISO-string timestamps tolerated for forward compatibility.

## `osquery_run`

Invoke `osqueryi --json <sql>` against the local OS state.

**Signature:** `await osquery_run(*, sql, timeout_sec=30.0, osqueryi_binary="osqueryi")`

**Output:** `OsqueryResult(sql, rows: tuple[dict[str, str], ...], ran_at: datetime)`.

**Side effects:** Spawns `osqueryi --json` subprocess. Coerces numeric values to strings for downstream uniformity.

**Errors:** `OsqueryError` on missing binary, non-zero exit, malformed JSON, JSON-object-not-array, or timeout (subprocess killed before raising).

## `runtime_threat.severity` helpers

Pure-Python normalizers — three native scales → internal `Severity` enum.

- `falco_to_severity(priority: str) → Severity`
- `tracee_to_severity(value: int) → Severity`
- `osquery_to_severity(value: int) → Severity`

Unknown / out-of-range inputs fall back to `Severity.INFO` rather than raising — sensors evolve their schemas and the agent must not fail on a single anomalous alert.

## `runtime_threat.normalizer.normalize_to_findings`

Map (FalcoAlert[], TraceeAlert[], OsqueryResult[]) → list[RuntimeFinding].

**Signature:** `await normalize_to_findings(falco_alerts, tracee_alerts, osquery_results, *, envelope, detected_at=None, osquery_severity=2, osquery_finding_context="query_hit")`

**Output:** `list[RuntimeFinding]`. Order is deterministic: Falco, then Tracee, then OSQuery.

**Notes:** No multi-feed dedup in v0.1 — Falco + Tracee describing the same incident emit two findings. Cross-feed correlation deferred to D.7 Investigation Agent.
