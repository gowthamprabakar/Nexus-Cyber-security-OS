# Remediation Agent — Tools Reference

A.1 ships two tools (filesystem readers + the kubectl executor) and four pure-function pipeline modules. All cluster-touching paths flow through `kubectl_executor` so the audit chain is uniform.

## Stage 1 — INGEST

### `read_findings(*, path: Path | str) -> tuple[ManifestFinding, ...]`

`remediation.tools.findings_reader.read_findings` — async loader for `findings.json` produced by D.6 Kubernetes Posture.

- Reads via `asyncio.to_thread` (ADR-005 async convention).
- Round-trips D.6's `cloud_posture.FindingsReport.model_dump_json()` shape back into `k8s_posture.ManifestFinding` records.
- **Source-strict**: only `evidence[*].kind == "manifest"` surfaces. kube-bench + Polaris findings are silently dropped (different remediation shape).
- Defensive on per-finding malformations (drops the bad finding; keeps the run going).
- Raises `FindingsReaderError` on file-level errors (missing / non-JSON / non-object / no `findings: list`).

## Stage 2 — AUTHZ

Four pure functions in `remediation.authz`. All take an `Authorization` Pydantic model (loaded from a separate `auth.yaml` to keep F.1's `ExecutionContract` strict).

### `enforce_mode(auth, mode)`

Raises `AuthorizationError` when the requested `RemediationMode` is not opted-in via `auth.yaml`. Error message names the exact flag to flip.

### `filter_authorized_findings(auth, findings) -> (authorized, refused_with_reason)`

Splits the input into two lists. A finding is authorised iff:

- Its `rule_id` maps to a v0.1 action class (`lookup_action_class` is non-None), AND
- That action class's `action_type.value` appears in `auth.authorized_actions`.

Refused findings flow into the audit chain as `refused_unauthorized` outcomes with a human-readable reason.

### `enforce_blast_radius(auth, count)`

Raises `AuthorizationError` when `count > auth.max_actions_per_run` (default 5; capped 50). **No partial-apply** — the entire run is refused with a `refused_blast_radius` audit entry. Operators either trim the input set or raise the cap explicitly.

### `authorized_action_types(auth) -> set[RemediationActionType]`

Reverse-lookup helper; drops unknown strings in `auth.authorized_actions` silently (an unknown action class can't be authorized in any meaningful sense).

## Stage 3 — GENERATE

### `generate_artifacts(findings) -> tuple[RemediationArtifact, ...]`

`remediation.generator.generate_artifacts` — pure function. Per finding, looks up the action class via `lookup_action_class(rule_id)` and calls its `build()`. Returns artifacts in input order. Defense-in-depth: silently skips findings with no v0.1 action class.

**Determinism guarantee.** Same input → same output in the same order. This powers idempotency — re-running A.1 on the same findings.json yields kubectl patches that are no-ops on the second apply (strategic-merge-patch is idempotent under repeated identical patches).

## Stage 4 / 5 — DRY-RUN / EXECUTE

### `apply_patch(artifact, *, dry_run, kubeconfig=None, fetch_state=True) -> PatchResult`

`remediation.tools.kubectl_executor.apply_patch` — async wrapper around `kubectl patch` via `asyncio.create_subprocess_exec`. The single execution point for both Stage 4 (dry-run) and Stage 5 (execute).

- `dry_run=True` → adds `--dry-run=server`; skips state-capture (nothing to compare).
- `dry_run=False` + `fetch_state=True` → pre-fetches the resource, applies the patch, post-fetches, computes SHA-256 hashes of both states for the audit chain.
- `kubeconfig=None` → kubectl uses default discovery (KUBECONFIG env / ~/.kube/config / in-cluster SA token).
- Returns frozen `PatchResult` with exit_code, stdout/stderr, dry_run flag, pre/post-patch hashes, pre/post-patch resources, `succeeded` property.

Mirrors D.6 v0.2/v0.3 cluster-access discipline: explicit `kubeconfig` XOR `--in-cluster` XOR artifact-only. The agent driver enforces the 3-way exclusion before calling this function.

### `fetch_resource(*, kind, name, namespace, kubeconfig=None) -> (exit_code, dict | None, stderr)`

`kubectl get <kind>/<name> -o json`. Returned dict is None on non-zero exit OR non-JSON output. Used for the pre/post-patch state capture in `apply_patch`.

### `hash_resource(resource) -> str`

SHA-256 hex digest of a resource dict via `json.dumps(sort_keys=True)`. Exposed so the agent driver + audit code can hash arbitrary snapshots (e.g., the rollback flow re-hashes after applying the inverse).

## Stage 6 — VALIDATE

### `validate_outcome(*, artifact, source_rule_id, detector, rollback_window_sec) -> ValidationResult`

`remediation.validator.validate_outcome` — the safety-critical re-detection step.

1. Sleeps `rollback_window_sec` (gives K8s controllers time to reconcile the patch).
2. Calls the `detector` closure (a pre-bound `read_cluster_workloads` from D.6 with the cluster-access config the agent is running under).
3. Filters the fresh findings to the same `(namespace, kind, workload, container)` tuple AND the same `source_rule_id`.
4. Returns `ValidationResult(requires_rollback, matched_findings)`.

**Why re-detect, not just re-apply.** A K8s patch can succeed at the API layer but fail at the runtime layer (webhook rejection, missed reconcile, race condition with another writer). Only re-detection tells us the _vulnerability_ is gone, not just that the _patch_ applied. This is the gold-standard safety contract.

### `build_d6_detector(*, namespace, kubeconfig, in_cluster) -> DetectorCallable`

Factory that returns a closure binding the cluster-access config. The driver calls this once per artifact (scoping the detector to the patched workload's namespace); the validator just invokes the closure.

## Stage 7 — ROLLBACK

### `rollback(artifact, *, kubeconfig=None) -> PatchResult`

`remediation.validator.rollback` — applies the artifact's `inverse_patch_body` (the action class's `build` already emitted both forward and inverse leaves; rollback is a deterministic swap). Re-applies in execute mode with `fetch_state=True` so the post-rollback hash flows into the audit chain.

## Audit chain

### `PipelineAuditor(path, *, run_id)`

`remediation.audit.PipelineAuditor` — thin shim over F.6 `AuditLog`. One per agent run; one method per stage boundary. Centralised 11-action vocabulary (`remediation.*`):

| Action                             | Stage | Emitted by                                    |
| ---------------------------------- | ----- | --------------------------------------------- |
| `remediation.run_started`          | —     | driver, once                                  |
| `remediation.findings_ingested`    | 1     | driver after Stage 1                          |
| `remediation.action_refused`       | 2     | per refused finding                           |
| `remediation.blast_radius_refused` | 2     | once when cap exceeded                        |
| `remediation.artifact_generated`   | 3     | per artifact                                  |
| `remediation.dry_run_completed`    | 4     | per artifact (success OR failure)             |
| `remediation.execute_completed`    | 5     | per artifact (success; pre/post hashes)       |
| `remediation.execute_failed`       | 5     | per artifact (failure before validate)        |
| `remediation.validate_completed`   | 6     | per artifact (validated OR requires_rollback) |
| `remediation.rollback_completed`   | 7     | per artifact (only when validate said roll)   |
| `remediation.run_completed`        | —     | driver, once                                  |

Payloads carry the artifact's `correlation_id` — cross-reference via this ID to join an audit entry to its `RemediationFinding` in `findings.json`.

Patch bodies are **deliberately NOT in the audit** — they're on the OCSF finding; cross-reference keeps the chain compact. The audit chain is for _what happened_, not _what was patched_.
