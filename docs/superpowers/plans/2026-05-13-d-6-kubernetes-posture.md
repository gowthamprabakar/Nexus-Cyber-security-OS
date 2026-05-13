# D.6 — Kubernetes Posture Agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Pause for review after each numbered task.

**Goal:** Ship the **Kubernetes Posture Agent** (`packages/agents/k8s-posture/`) — the **fourth Phase-1b agent** and the **ninth under [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)** (F.3 / D.1 / D.2 / D.3 / F.6 / D.7 / D.4 / D.5 / **D.6**). Adds **CIS Kubernetes Benchmark** + **Polaris** static analysis on operator-pinned kubeconfig / manifest snapshots. **Closes the Phase-1b detection track** (D.4 + D.5 + D.6 + D.7 all shipped).

**Scope:** v0.1 ingests three operator-pinned filesystem feeds (kube-bench JSON / Polaris JSON / a manifest snapshot tarball — flat directory of `*.yaml`). Emits OCSF v1.3 Compliance Findings (`class_uid 2003`) — **re-uses F.3's schema** (D.5 established the re-export pattern). Phase 1c adds live cluster API ingest (`kubernetes-client` + Helm chart inventory).

**Strategic role.** Fourth Phase-1b agent; **closes the detection track** at M2 (originally projected M5–M7). Lifts the CSPM family from 80% (AWS + Azure + GCP) to ~95% v0.1-equivalent across the four most-deployed surfaces (the three major clouds + Kubernetes). Pure pattern application against the now-stable substrate + D.5 schema re-export — no new architectural decisions blocking.

**Q1 (resolve up-front).** Schema reuse — fork or re-export?

**Resolution: re-export F.3's `class_uid 2003 Compliance Finding` via D.5's pattern.** D.5 set the precedent (first agent to inherit rather than fork). D.6 follows verbatim: `from cloud_posture.schemas import build_finding, Severity, AffectedResource, CloudPostureFinding, FindingsReport, FINDING_ID_RE`. The `CloudProvider` enum from `multi_cloud_posture.schemas` extends with `KUBERNETES` (or a parallel enum in D.6's own schemas — TBD at Task 2). The `K8sFindingType` discriminator has three buckets: `cspm_k8s_cis` / `cspm_k8s_polaris` / `cspm_k8s_manifest`.

**Q2 (resolve up-front).** Live cluster API or offline fixture mode in v0.1?

**Resolution: offline filesystem snapshots only** (mirrors F.3 LocalStack + D.4 + D.5 pattern). Phase 1c adds live `kubernetes-client` + `helm` API integration. v0.1 reads:

- kube-bench JSON output (`kube-bench --json` written to file)
- Polaris JSON output (`polaris audit --format=json --kubeconfig=...` written to file)
- A manifest directory (flat `*.yaml` files; can include Helm-rendered templates via `helm template`)

**Q3 (resolve up-front).** kube-bench vs Polaris — pick one or ship both?

**Resolution: ship both, normalize to one OCSF wire shape.** kube-bench covers CIS Benchmark controls (worker / master / etcd / policies); Polaris covers workload posture (security contexts, resource limits, image-pull policy). Overlapping checks dedupe via composite key `(node_uid, control_id, severity, 5min_bucket)`. Operators get one OCSF feed regardless of which tool produced the finding.

**Q4 (resolve up-front).** Manifest static analysis — what rules in v0.1?

**Resolution: a 10-rule bundled v0.1 ruleset focused on the most-impactful posture issues.** The ruleset:

1. Container running as root (`securityContext.runAsUser=0` OR missing)
2. Privileged container (`securityContext.privileged=true`)
3. Host network namespace (`hostNetwork=true`)
4. Host PID namespace (`hostPID=true`)
5. Host IPC namespace (`hostIPC=true`)
6. Missing resource limits (no `resources.limits.cpu` or `resources.limits.memory`)
7. `imagePullPolicy: Always` missing (defaults vary across cluster versions; explicit Always is best practice)
8. Capability escalation (`securityContext.allowPrivilegeEscalation=true`)
9. Read-only root filesystem missing (`securityContext.readOnlyRootFilesystem != true`)
10. ServiceAccount tokens auto-mounted (`automountServiceAccountToken != false` AND no explicit override)

**Q5 (resolve up-front).** Severity mapping — kube-bench / Polaris / manifest rules?

**Resolution: three deterministic source mappings (mirrors D.5's pattern):**

- **kube-bench** — uses CIS's `test_info.status`:
  - `FAIL` → HIGH (default)
  - `WARN` → MEDIUM
  - `PASS` / `INFO` → filtered (not a finding)
  - Critical-marked controls (`severity: critical` if upstream sets it) → CRITICAL
- **Polaris** — uses its own severity strings:
  - `danger` → HIGH
  - `warning` → MEDIUM
  - `ignore` → filtered
- **Manifest rules** (D.6 native) — fixed per-rule:
  - root / privileged / host-namespace → HIGH
  - missing-resource-limits / imagePullPolicy → MEDIUM
  - read-only-root / auto-mount-SA → MEDIUM
  - allowPrivilegeEscalation=true → HIGH

**Q6 (resolve up-front).** Helm chart inventory in v0.1?

**Resolution: NOT in v0.1.** Helm-rendered templates can be fed in via the manifest directory feed (`helm template my-release my-chart/ > manifests/my-release.yaml`); the operator pre-renders. Phase 1c adds a native `read_helm_releases` tool against the in-cluster Helm state.

**Architecture:**

```
ExecutionContract (signed)
        │
        ▼
┌──────────────────────────────────────────────────────────────────┐
│ Kubernetes Posture Agent driver                                  │
│                                                                  │
│  Stage 1: INGEST     — 3 feeds concurrent via TaskGroup          │
│  Stage 2: NORMALIZE  — kube-bench + Polaris + manifests → OCSF   │
│  Stage 3: SCORE      — per-source severity (deterministic)       │
│  Stage 4: DEDUP      — composite-key collapse (overlapping checks) │
│  Stage 5: SUMMARIZE  — per-namespace + per-severity sections     │
│  Stage 6: HANDOFF    — emit `findings.json` + `report.md`        │
└─────────┬────────────────────────────────────────────────────────┘
          │
          ▼
┌──────────────────────────────────────────────────────────────────┐
│ Tools (per-stage)                                                │
│  read_kube_bench         ─→ kube-bench JSON parser (filesystem)  │
│  read_polaris            ─→ Polaris JSON parser (filesystem)     │
│  read_manifests          ─→ flat dir of *.yaml files; runs the   │
│                             10-rule analyser                     │
│  normalize_kube_bench    ─→ kube-bench shape → OCSF 2003         │
│  normalize_polaris       ─→ Polaris shape → OCSF 2003            │
│  normalize_manifest      ─→ Manifest-finding → OCSF 2003         │
│  dedupe_overlapping      ─→ composite-key collapse               │
│  render_summary          ─→ per-namespace + per-severity         │
└──────────────────────────────────────────────────────────────────┘
```

**Tech stack:** Python 3.12 · BSL 1.1 · OCSF v1.3 Compliance Finding (`class_uid 2003`, `types[0]` carries source discriminator) · pydantic 2.9 · click 8 · `pyyaml` for manifest parsing · `charter.llm_adapter` (ADR-007 v1.1) · `charter.nlah_loader` (ADR-007 v1.2). Re-exports F.3's `cloud_posture.schemas` (per D.5's pattern). No external network dependencies in v0.1.

**Depends on:**

- F.1 charter — standard budget caps; no extensions needed (D.6 is not always-on, not sub-agent-spawning).
- F.3 cloud-posture — re-exports `class_uid 2003 Compliance Finding` schema.
- F.4 control-plane — tenant context propagates through the contract.
- F.5 memory engines — `EpisodicStore` for per-run persistence (optional in v0.1).
- F.6 Audit Agent — every D.6 run emits an audit chain via `charter.audit.AuditLog`.
- ADR-007 v1.1 + v1.2 — reference NLAH template. D.6 is the **ninth** agent under it. v1.3 (always-on) opt-out; v1.4 (sub-agent spawning) not consumed.

**Defers (Phase 1c / Phase 2):**

- **Live cluster API ingest** (`kubernetes-client` + RBAC inventory + admission-webhook posture) — Phase 1c.
- **Helm chart inventory** (`read_helm_releases`) — Phase 1c.
- **OPA / Gatekeeper policy posture** (constraint templates + violations) — Phase 1c.
- **Pod Security Standards** (restricted / baseline / privileged enforcement check) — Phase 1c (depends on PSS API availability).
- **Network policy graph analysis** — Phase 1c (depends on F.5 SemanticStore for graph queries).

**Reference template:** **D.5 Multi-Cloud Posture** (closest match — same schema re-export pattern, same OCSF 2003 wire shape, same offline-mode pattern). D.6 is structurally D.5 with: (a) **three** ingest feeds instead of four (kube-bench / Polaris / manifests); (b) one **native** normalizer (manifest rules) plus two for upstream tools; (c) explicit **dedup stage** for overlapping checks (D.5 didn't need this — Defender and SCC don't overlap); (d) per-namespace breakdown in summarizer (replacing D.5's per-cloud).

---

## Execution status

```
1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12 → 13 → 14 → 15 → 16
```

| Task | Status     | Commit    | Notes                                                                                                                                                                                                                                                                                                                                      |
| ---- | ---------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1    | ✅ done    | `72730f7` | Bootstrap — pyproject (BSL 1.1; deps on charter / shared / eval-framework / **nexus-cloud-posture** for F.3 schema re-export per Q1). 9 smoke tests: ADR-007 v1.1 + v1.2 + F.1 audit log + F.5 episodic + F.3 schema re-export confirmation + 2 anti-pattern guards + 2 entry-point checks. Repo-wide 1794 passed / 11 skipped.            |
| 2    | ✅ done    | `0efb340` | Re-exports F.3's `class_uid 2003` per D.5 precedent. Adds `K8sFindingType` enum (3 discriminators), `source_token()`, `short_workload_token()`, plus `kube_bench_severity()` / `polaris_severity()` mapping helpers per Q5. Finding-id cloud token is **KUBERNETES** (not K8S) — F.3 regex constrains cloud segment to `[A-Z]+`. 19 tests. |
| 3    | ✅ done    | `0efb340` | `read_kube_bench` — async parser for `kube-bench --json`; canonical + bare-array shapes; flattens `Controls[].tests[].results[]`; only FAIL/WARN become findings (PASS/INFO dropped); preserves upstream `severity:critical` marker; defensive on missing tests/results. 22 tests. Repo-wide 1847 passed / 11 skipped.                     |
| 4    | ✅ done    | `95d86a3` | `read_polaris` — async Polaris audit-JSON parser. Walks three check levels (workload / pod / container); only `Success: false` records become findings; danger/warning severity accepted, ignore/unknown dropped. Forgiving on missing fields. 19 tests.                                                                                   |
| 5    | ✅ done    | `95d86a3` | `read_manifests` — async dir walker (_.yaml + _.yml) with bundled 10-rule analyser per Q4. Supports Pod / Deployment / StatefulSet / DaemonSet / ReplicaSet / Job / CronJob; walks containers + initContainers; multi-doc YAML; malformed YAML files skipped. 37 tests. Repo-wide 1903 passed / 11 skipped.                                |
| 6    | ✅ done    | `6290701` | `normalize_kube_bench` — CIS shape → OCSF 2003; severity via `kube_bench_severity()`; critical-marker promotes to CRITICAL; per-(node_type) sequence counter; resource_type derived from node_type. 15 tests.                                                                                                                              |
| 7    | ✅ done    | `6290701` | `normalize_polaris` — Polaris shape → OCSF 2003; severity via `polaris_severity()`; per-namespace sequence counter; resource_id + arn carry container fragment when container-level; preserves check_level (workload/pod/container). 20 tests. Repo-wide 1938 passed / 11 skipped.                                                         |
| 8    | ✅ done    | `3b628f1` | `normalize_manifest` — Manifest-finding → OCSF 2003; severity preserved verbatim from reader's pre-graded 10-rule table; per-(namespace, rule) sequence numbering; arn=`k8s://manifest/<ns>/<kind>/<name>[#<container>]`. 15 tests.                                                                                                        |
| 9    | ✅ done    | `3b628f1` | `dedupe_overlapping` — composite-key collapse `(rule_id, namespace, workload_arn, 5min_bucket)`; highest severity wins with first-seen tiebreak; collapsed loser finding_ids preserved in a `dedup-sources` evidence on the survivor; configurable window. 13 tests. Repo-wide 1966 passed / 11 skipped.                                   |
| 10   | ✅ done    | `5ce6b45` | NLAH bundle + 21-LOC shim — sixth native v1.2 agent (D.3 / F.6 / D.7 / D.4 / D.5 / **D.6**). README + tools.md + 2 examples (CIS FAIL-promoted-critical + Polaris/manifest coexistence). 10 loader tests including ≤35-LOC shim cap.                                                                                                       |
| 11   | ✅ done    | `5ce6b45` | `render_summary` — per-namespace breakdown pinned ABOVE per-severity sections; CRITICAL findings pinned; per-source-type counts (CIS / Polaris / Manifest); deterministic alpha-sorted namespaces. 15 tests. Repo-wide 1991 passed / 11 skipped.                                                                                           |
| 12   | ✅ done    | `fa94038` | Agent driver `run()` — 6-stage pipeline (INGEST → NORMALIZE → SCORE → DEDUP → SUMMARIZE → HANDOFF). `asyncio.TaskGroup` fan-out across the three readers; 3 optional feed flags (kube_bench_feed / polaris_feed / manifest_dir); Charter ctx emits findings.json + report.md + audit.jsonl. 12 unit tests including DEDUP-stage collision. |
| 13   | ✅ done    | `fa94038` | 10 representative YAML eval cases — clean / kube-bench-fail / critical-marker promotion / polaris-danger / manifest-root-container / manifest-privileged / manifest-missing-limits / dedup-overlap / large-namespace-rollup / three-feed-merge. Repo-wide 2003 passed / 11 skipped.                                                        |
| 14   | ⬜ pending | —         | `K8sPostureEvalRunner` + `nexus_eval_runners` entry-point + **10/10 acceptance** via `eval-framework run --runner k8s_posture`.                                                                                                                                                                                                            |
| 15   | ⬜ pending | —         | CLI (`k8s-posture eval` / `k8s-posture run`). Three optional feed flags: `--kube-bench-feed`, `--polaris-feed`, `--manifest-dir`.                                                                                                                                                                                                          |
| 16   | ⬜ pending | —         | README + operator runbook (`runbooks/k8s_scan.md`). Final verification record `docs/_meta/d6-verification-<date>.md`. **Closes Phase-1b detection track.**                                                                                                                                                                                 |

ADR references: [ADR-001](../../_meta/decisions/ADR-001-monorepo-bootstrap.md) · [ADR-005](../../_meta/decisions/ADR-005-async-tool-wrapper-convention.md) · [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) · [ADR-008](../../_meta/decisions/ADR-008-eval-framework.md) · [ADR-009](../../_meta/decisions/ADR-009-memory-architecture.md).

---

## Resolved questions

| #   | Question                                          | Resolution                                                                                                                               | Task      |
| --- | ------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | --------- |
| Q1  | Schema reuse strategy?                            | **Re-export F.3's `class_uid 2003`** via D.5's pattern. `K8sFindingType` enum (3 discriminators) on `finding_info.types[0]`.             | Task 2    |
| Q2  | Live cluster API or offline fixture mode in v0.1? | **Offline filesystem snapshots only.** Live `kubernetes-client` ingest ships Phase 1c.                                                   | Tasks 3-5 |
| Q3  | kube-bench vs Polaris — pick one or ship both?    | **Both, with composite-key dedup.** Overlapping checks collapse via `(rule_id_or_control_id, namespace, workload, 5min_bucket)`.         | Task 9    |
| Q4  | Manifest static analysis — what rules in v0.1?    | **10-rule bundled ruleset** (root / privileged / host-namespaces / resource-limits / pull-policy / privesc / read-only-root / SA-token). | Task 5    |
| Q5  | Severity mapping?                                 | **Three deterministic per-source maps** (kube-bench FAIL→HIGH; Polaris danger→HIGH; manifest rules fixed). No LLM grading.               | Tasks 6-8 |
| Q6  | Helm chart inventory in v0.1?                     | **NOT in v0.1.** Operators feed `helm template`-rendered manifests through `--manifest-dir`. Phase 1c adds native `read_helm_releases`.  | —         |

---

## File map (target)

```
packages/agents/k8s-posture/
├── pyproject.toml                              # Task 1
├── README.md                                   # Tasks 1, 16
├── runbooks/
│   └── k8s_scan.md                             # Task 16
├── src/k8s_posture/
│   ├── __init__.py                             # Task 1
│   ├── py.typed                                # Task 1
│   ├── schemas.py                              # Task 2 (re-exports + K8sFindingType)
│   ├── nlah_loader.py                          # Task 10 (21-LOC shim)
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── kube_bench.py                       # Task 3
│   │   ├── polaris.py                          # Task 4
│   │   └── manifests.py                        # Task 5 (incl. 10-rule analyser)
│   ├── normalizers/
│   │   ├── __init__.py
│   │   ├── kube_bench.py                       # Task 6
│   │   ├── polaris.py                          # Task 7
│   │   └── manifest.py                         # Task 8
│   ├── dedup.py                                # Task 9
│   ├── summarizer.py                           # Task 11
│   ├── agent.py                                # Task 12 (driver: 6-stage pipeline)
│   ├── eval_runner.py                          # Task 14
│   └── cli.py                                  # Task 15
├── nlah/
│   ├── README.md                               # Task 10
│   ├── tools.md                                # Task 10
│   └── examples/                               # Task 10 (2 examples)
├── eval/
│   └── cases/                                  # Task 13 (10 YAML cases)
└── tests/
    ├── test_pyproject.py                       # Task 1
    ├── test_schemas.py                         # Task 2
    ├── test_tools_kube_bench.py                # Task 3
    ├── test_tools_polaris.py                   # Task 4
    ├── test_tools_manifests.py                 # Task 5
    ├── test_normalizers_kube_bench.py          # Task 6
    ├── test_normalizers_polaris.py             # Task 7
    ├── test_normalizers_manifest.py            # Task 8
    ├── test_dedup.py                           # Task 9
    ├── test_nlah_loader.py                     # Task 10
    ├── test_summarizer.py                      # Task 11
    ├── test_agent_unit.py                      # Task 12
    ├── test_eval_runner.py                     # Task 14 (incl. 10/10 acceptance)
    └── test_cli.py                             # Task 15
```

---

## Risks

| Risk                                                                                | Mitigation                                                                                                                                                                                     |
| ----------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| kube-bench JSON schema varies across versions (1.7.x, 1.8.x, 1.9.x).                | Reader is **forgiving** — unknown fields preserved under `unmapped`; missing required fields (control_id, status) drop the record. Eval cases use representative shapes from public docs.      |
| Polaris JSON schema is loosely documented; field names differ between releases.     | Reader follows the canonical `Results[].PodResult.ContainerResults[].Results[]` walk; defensive against missing intermediate nodes. Schema cap at 5000 records to avoid OOM on large clusters. |
| Manifest 10-rule v0.1 ruleset is shallow vs OPA/Polaris production rule sets.       | v0.1 covers highest-impact rules. Documented in README + runbook. Phase 1c expands to a 50-rule table modeled on KubeLinter + kubesec.io.                                                      |
| Overlapping findings between kube-bench + Polaris + manifest rules produce noise.   | Stage 4 DEDUP collapses via composite key. Per Q3 resolution.                                                                                                                                  |
| Schema re-export from F.3 + D.5 creates two-layer coupling (F.3 schema + D.5 enum). | Acceptable — D.5 set the precedent. Hoist candidate `charter.compliance_finding` becomes critical when third+ consumer arrives (likely Compliance Agent in Phase 1c).                          |
| Phase 1b detection close at M2 vs M5–M7 leaves Phase 1c capacity unclear.           | Track-A remediation (A.1) is queued as the next major plan; no slack risk. D.8 Threat Intel can ship in parallel with A.1.                                                                     |

---

## Done definition

D.6 is **done** when:

- 16/16 tasks closed; every commit pinned in the execution-status table.
- ≥ 80% test coverage on `packages/agents/k8s-posture` (gate same as F.3 / D.1 / D.3 / D.7 / D.4 / D.5).
- `ruff check` + `ruff format --check` + `mypy --strict` clean.
- `eval-framework run --runner k8s_posture` returns 10/10.
- ADR-007 v1.1 + v1.2 conformance verified end-to-end.
- README + runbook reviewed.
- D.6 verification record committed.

**That closes the Phase-1b detection track** (D.4 + D.5 + D.6 + D.7 all shipped). Phase 1c opens with **A.1 Tier-3 remediation** (recommendation-only).

---

## Next plans queued (for context)

- **A.1 Tier-3 remediation agent** — recommendation-only; consumes findings.json from any Track-D agent + D.7 containment plans. ~2 weeks. Opens Phase 1c.
- **D.8 Threat Intel Agent** — live VirusTotal + OTX + CISA KEV; replaces bundled snapshots in D.4 + D.5. Ships in parallel with A.1.
- **A.4 Meta-Harness** — reads D.7 hypothesis history + eval-framework traces; proposes NLAH rewrites scored against per-agent eval suites. ~3 weeks. Self-evolution operational.

D.6 closes Phase 1b detection. Phase 1c brings A.1–A.4 remediation + Meta-Harness + streaming ingest + live cloud SDK paths.
