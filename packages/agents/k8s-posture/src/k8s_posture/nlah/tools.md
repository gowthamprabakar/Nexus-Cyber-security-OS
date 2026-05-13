# Kubernetes Posture Agent — Tools Reference

Eight tools, grouped by stage. Three readers are async-safe (per ADR-005) so the agent driver can fan them out via `asyncio.TaskGroup`; the three normalizers + dedup + summarizer are pure functions.

## Stage 1: INGEST (three feeds, concurrent)

### `read_kube_bench(*, path: Path) -> tuple[KubeBenchFinding, ...]`

Async parser for `kube-bench --json` output. Supports the canonical `{"Controls": [...]}` shape and a bare-array shape.

- Flattens `Controls[].tests[].results[]` into a typed `KubeBenchFinding`.
- Only `FAIL` / `WARN` records become findings (`PASS` / `INFO` dropped at the reader).
- Preserves an upstream `severity: critical` marker so the normalizer can promote to CRITICAL.
- Captures `node_type` (master / worker / etcd / controlplane / policies) for resource shaping downstream.
- Forgiving on missing `tests` / `results`; explicit raise on top-level malformed JSON.

### `read_polaris(*, path: Path) -> tuple[PolarisFinding, ...]`

Async parser for `polaris audit --format=json` output. Walks all three check levels (workload / pod / container).

- Only `Success: false` records become findings; `check_id` falls back to the dict key when an explicit `ID` field is absent.
- Namespace defaults to `"default"` when missing.
- `severity` accepted: `danger` / `warning`; `ignore` + unknown values dropped.
- Preserves the originating `check_level` for evidence-side dedup hints.

### `read_manifests(*, path: Path) -> tuple[ManifestFinding, ...]`

Async directory walker over `*.yaml` + `*.yml` files. Runs D.6's bundled 10-rule analyser over every pod template.

- Supported workload kinds: `Pod` / `Deployment` / `StatefulSet` / `DaemonSet` / `ReplicaSet` / `Job` / `CronJob`. Other kinds skipped silently.
- Walks both `containers` AND `initContainers`.
- Multi-document YAML supported (`yaml.safe_load_all`).
- Malformed YAML files dropped silently; run continues.
- Severity is pre-graded per rule (see "Manifest ruleset" below).

## Stage 2: NORMALIZE (three pure functions)

### `normalize_kube_bench(findings, *, envelope, scan_time) -> tuple[CloudPostureFinding, ...]`

CIS shape → OCSF 2003. finding_id format: `CSPM-KUBERNETES-CIS-NNN-<slug>` where slug carries `node_type-control_id-control_text`. Per-(node_type) sequence counter so IDs are stable within a run. Resource shape: `cloud=kubernetes`, `account_id=<node_type>`, `region=cluster`, `resource_type` derived from node_type (MasterNode / WorkerNode / EtcdNode / ControlPlaneNode / PolicyConfig / K8sNode), `arn=k8s://cis/<node_type>/<control_id>`. Critical-marker promotes any FAIL/WARN to CRITICAL.

### `normalize_polaris(findings, *, envelope, scan_time) -> tuple[CloudPostureFinding, ...]`

Polaris shape → OCSF 2003. finding_id: `CSPM-KUBERNETES-POLARIS-NNN-<slug>` where slug carries the Polaris check_id. Per-namespace sequence counter. Resource shape: `cloud=kubernetes`, `account_id=<namespace>`, `region=cluster`, `resource_type=<workload_kind>`, `arn=k8s://workload/<namespace>/<kind>/<name>[#<container>]`. Evidence preserves `check_level`.

### `normalize_manifest(findings, *, envelope, scan_time) -> tuple[CloudPostureFinding, ...]`

Manifest-finding shape → OCSF 2003. finding_id: `CSPM-KUBERNETES-MANIFEST-NNN-<slug>` where slug carries `rule_id-workload_name`. Per-(namespace, rule_id) sequence counter. Resource shape mirrors Polaris but with `arn=k8s://manifest/<namespace>/<kind>/<name>[#<container>]`. Severity lifted verbatim from the reader (which pre-grades per rule).

## Stage 3: DEDUP (one pure function)

### `dedupe_overlapping(findings, *, window=timedelta(minutes=5)) -> tuple[CloudPostureFinding, ...]`

Composite-key collapse on `(rule_id, namespace, workload_arn, time_bucket)`. Highest severity wins with first-seen tiebreak. Collapsed loser IDs are appended to the survivor's `evidences` as `{"kind": "dedup-sources", "finding_ids": [...]}`.

- Container fragments preserved — `…#nginx` and `…#sidecar` stay distinct.
- Cross-tool collisions natural-boundary: kube-bench arns (`k8s://cis/…`) and Polaris/manifest arns (`k8s://workload/…` / `k8s://manifest/…`) never collide.
- Manifest's `run-as-root` and Polaris's `runAsRootAllowed` have distinct `rule_id`s — v0.1 keeps both. A future ontology map could merge them; deferred per Q3.
- Configurable window for testability + future tuning.

## Stage 4: SUMMARIZE (one pure function)

### `render_summary(findings, *, agent, agent_version, scan_started_at, scan_completed_at) -> str`

Renders a markdown operator report. Top-of-report headline shows total + per-namespace breakdown. CRITICAL findings are pinned above per-severity sections. Per-namespace tables sort by severity then finding_id for deterministic output.

## Manifest ruleset (D.6 v0.1)

The 10 rules baked into `read_manifests`:

| ID                             | Severity | Trigger                                                     |
| ------------------------------ | -------- | ----------------------------------------------------------- |
| `run-as-root`                  | HIGH     | `securityContext.runAsUser == 0` OR missing                 |
| `privileged-container`         | HIGH     | `securityContext.privileged == true`                        |
| `host-network`                 | HIGH     | pod-spec `hostNetwork == true`                              |
| `host-pid`                     | HIGH     | pod-spec `hostPID == true`                                  |
| `host-ipc`                     | HIGH     | pod-spec `hostIPC == true`                                  |
| `missing-resource-limits`      | MEDIUM   | `resources.limits.cpu` OR `resources.limits.memory` missing |
| `image-pull-policy-not-always` | MEDIUM   | container `imagePullPolicy != "Always"`                     |
| `allow-privilege-escalation`   | HIGH     | `securityContext.allowPrivilegeEscalation == true`          |
| `read-only-root-fs-missing`    | MEDIUM   | `securityContext.readOnlyRootFilesystem != true`            |
| `auto-mount-sa-token`          | MEDIUM   | pod-spec `automountServiceAccountToken != false`            |
