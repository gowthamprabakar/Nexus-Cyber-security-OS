# `nexus-k8s-posture-agent`

Kubernetes Posture Agent — D.6; **fourth Phase-1b agent**; **ninth under [ADR-007](../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)** (F.3 / D.1 / D.2 / D.3 / F.6 / D.7 / D.4 / D.5 / **D.6**). **Closes the Phase-1b detection track.**

## What it does

Three-feed offline forensic analysis. Given an `ExecutionContract` requesting a Kubernetes posture scan, D.6 runs a **six-stage pipeline**:

```
INGEST → NORMALIZE → SCORE → DEDUP → SUMMARIZE → HANDOFF
```

Three concurrent input feeds (`asyncio.TaskGroup`):

- **kube-bench** — CIS Kubernetes Benchmark JSON output (`kube-bench --json`). FAIL/WARN records become findings; PASS/INFO dropped. An upstream `severity: critical` marker promotes any FAIL/WARN to CRITICAL.
- **Polaris** — workload-posture JSON output (`polaris audit --format=json`). Walks all three check levels (workload / pod / container). `Success: false` records with `danger`/`warning` severity become findings; `ignore` filtered.
- **Manifest directory** — flat `*.yaml` + `*.yml` files; runs D.6's bundled **10-rule analyser** over every pod template (Pod / Deployment / StatefulSet / DaemonSet / ReplicaSet / Job / CronJob).

Three deterministic normalizers (`normalize_kube_bench` + `normalize_polaris` + `normalize_manifest`) lift the typed reader outputs into OCSF v1.3 Compliance Findings via **F.3's re-exported `build_finding`** — D.6 emits the **identical wire shape** (`class_uid 2003`) as F.3 cloud-posture and D.5 multi-cloud-posture. Downstream consumers (Meta-Harness, D.7 Investigation, fabric routing) already filter on `class_uid 2003`; D.6 is invisible at the schema level. The `finding_info.types[0]` discriminator carries `cspm_k8s_cis` / `cspm_k8s_polaris` / `cspm_k8s_manifest`.

A dedicated **DEDUP stage** (new vs D.5) collapses overlapping findings on `(rule_id, namespace, workload_arn, 5min_bucket)`. Higher severity wins with first-seen tiebreak; collapsed loser finding-IDs are preserved on the survivor as a `dedup-sources` evidence entry. Cross-tool collisions (kube-bench vs Polaris/manifest) naturally avoid each other because their arn schemes differ (`k8s://cis/…` vs `k8s://workload/…` vs `k8s://manifest/…`).

Operators see per-namespace breakdown (CIS + Polaris + Manifest counts per namespace) and CRITICAL findings **pinned above** the per-severity sections (mirrors F.3 + D.3 + D.4 + D.5 patterns).

## ADR-007 conformance

D.6 is the **ninth** agent under the reference template. Inherits v1.1 (LLM adapter via `charter.llm_adapter`; no per-agent `llm.py`) and v1.2 (NLAH loader is a 21-LOC shim over `charter.nlah_loader` — D.6 is the **6th native v1.2 agent**). **Not** in the v1.3 always-on class — D.6 honours every budget axis. **Does not consume** the v1.4 candidate (sub-agent spawning primitive); single-driver per the agent spec.

**Schema reuse (Q1).** D.6 re-exports F.3's `class_uid 2003 Compliance Finding` schema verbatim — `Severity`, `AffectedResource`, `CloudPostureFinding`, `build_finding`, `FindingsReport`, and `FINDING_ID_RE` (`CSPM-<CLOUD>-<SVC>-<NNN>-<context>`). The cloud token is `KUBERNETES` (the regex constrains the cloud segment to `[A-Z]+`, so `K8S` would fail the gate). Adds D.6-specific `K8sFindingType` enum (3 discriminators) and three per-source severity helpers on top.

LLM use: **not load-bearing** (matches D.5). Normalizers, dedup, and summarizer are all deterministic. The `LLMProvider` parameter on `agent.run` is plumbed but never called in v0.1 — keeps the contract surface stable when Phase 1c adds optional LLM narrative.

## Quick start

```bash
# 1. Run the local eval suite (10/10)
uv run k8s-posture eval packages/agents/k8s-posture/eval/cases

# 2. Run via the eval-framework (resolves through nexus_eval_runners entry-point)
uv run eval-framework run \
    --runner k8s_posture \
    --cases packages/agents/k8s-posture/eval/cases \
    --output /tmp/d6-eval-out.json

# 3. Run against an ExecutionContract — three optional feeds
uv run k8s-posture run \
    --contract path/to/contract.yaml \
    --kube-bench-feed /tmp/kube-bench.json \
    --polaris-feed /tmp/polaris.json \
    --manifest-dir /tmp/manifests/
```

See [`runbooks/k8s_scan.md`](runbooks/k8s_scan.md) for the full operator workflow (staging the three feeds · interpreting the three artifacts · severity escalation rules · routing findings to D.7 Investigation + F.6 Audit · troubleshooting).

## Architecture

```
kube-bench JSON       ──→ read_kube_bench ───┐
polaris JSON          ──→ read_polaris ──────┤
manifest *.yaml dir   ──→ read_manifests ────┘
                                             │
                                             ▼ INGEST (TaskGroup)
                          ┌──────────────────────────────────┐
                          │ normalize_kube_bench (CIS)             │
                          │ normalize_polaris (workload posture)   │   NORMALIZE + SCORE
                          │ normalize_manifest (10-rule analyser)  │   (F.3 build_finding;
                          │     → CloudPostureFinding tuple        │    deterministic severity)
                          │     class_uid 2003 = F.3 wire shape    │
                          └────────────────┬─────────────────┘
                                           │
                                  dedupe_overlapping            DEDUP
                            (rule_id, namespace, arn, 5min)
                                           │
                                           ▼
                                  render_summary               SUMMARIZE
                          (per-namespace + CRITICAL pinned)
                                           │
                                           ▼
                              findings.json + report.md         HANDOFF
                              + audit.jsonl
```

Three async readers ([`tools/`](src/k8s_posture/tools/)) and three pure-function normalizers ([`normalizers/`](src/k8s_posture/normalizers/)). Plus dedup ([`dedup.py`](src/k8s_posture/dedup.py)), summarizer ([`summarizer.py`](src/k8s_posture/summarizer.py)), and the agent driver ([`agent.py`](src/k8s_posture/agent.py)).

## The 10-rule manifest analyser (D.6 v0.1)

| Rule ID                        | Severity | Trigger                                                     |
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

The reader pre-grades severity; the normalizer is a thin lift.

## Output contract — the three artifacts

| File            | Format                                | Purpose                                                                                                                       |
| --------------- | ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `findings.json` | `FindingsReport.model_dump_json()`    | Wire shape consumed by D.7 Investigation, fabric routing, Meta-Harness. **OCSF 2003 — identical to F.3 cloud-posture + D.5.** |
| `report.md`     | Markdown                              | Operator summary. Per-namespace breakdown pinned at top; CRITICAL findings pinned above per-severity sections.                |
| `audit.jsonl`   | `charter.audit.AuditEntry` JSON-lines | This run's own hash-chained audit log. F.6 `audit-agent query` reads it.                                                      |

## Tests

```bash
uv run pytest packages/agents/k8s-posture -q
```

245 tests; mypy strict clean. **10/10 eval acceptance gate** via the eval-framework entry-point:

```bash
uv run eval-framework run --runner k8s_posture \
    --cases packages/agents/k8s-posture/eval/cases \
    --output /tmp/d6-eval-out.json
# → 10/10 passed (100.0%)
```

## License

BSL 1.1 per [ADR-001](../../../docs/_meta/decisions/ADR-001-monorepo-bootstrap.md). Substrate this agent consumes (`charter`, `cloud-posture`, `eval-framework`) is Apache 2.0; the agent itself is BSL.
