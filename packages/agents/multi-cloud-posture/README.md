# `nexus-multi-cloud-posture-agent`

Multi-Cloud Posture Agent — D.5; **third Phase-1b agent**; **eighth under [ADR-007](../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)** (F.3 / D.1 / D.2 / D.3 / F.6 / D.7 / D.4 / **D.5**). Lifts CSPM coverage from AWS-only (F.3) to **Azure + GCP**.

## What it does

Four-feed offline forensic analysis. Given an `ExecutionContract` requesting a multi-cloud posture scan, D.5 runs a **five-stage pipeline**:

```
INGEST → NORMALIZE → SCORE → SUMMARIZE → HANDOFF
```

Four concurrent input feeds (`asyncio.TaskGroup`):

- **Azure Defender for Cloud** — assessments + alerts JSON exports.
- **Azure Activity Log** — JSON exports; `iam`/`network`/`storage`/`keyvault` operations only (compute lifecycle dropped).
- **GCP Security Command Center** — findings JSON (canonical `ListFindingsResponse` + gcloud wrapper + bare-array shapes).
- **GCP Cloud Asset Inventory IAM** — bindings analysed deterministically (public + impersonation → CRITICAL; `roles/owner` to external user → CRITICAL; `roles/editor` to user → MEDIUM; etc.).

Two deterministic normalizers (`normalize_azure` + `normalize_gcp`) lift the typed reader outputs into OCSF v1.3 Compliance Findings via **F.3's re-exported `build_finding`** — D.5 emits the **identical wire shape** (`class_uid 2003`) as F.3 cloud-posture. Downstream consumers (Meta-Harness, D.7 Investigation, fabric routing) already filter on `class_uid 2003`; D.5 is invisible at the schema level. The `finding_info.types[0]` discriminator carries `cspm_azure_defender` / `cspm_azure_activity` / `cspm_gcp_scc` / `cspm_gcp_iam`.

Operators see per-cloud breakdown (Azure: Defender + Activity counts; GCP: SCC + IAM counts) and CRITICAL findings **pinned above** the per-severity sections (mirrors F.3 + D.3 + D.4 patterns).

## ADR-007 conformance

D.5 is the **eighth** agent under the reference template. Inherits v1.1 (LLM adapter via `charter.llm_adapter`; no per-agent `llm.py`) and v1.2 (NLAH loader is a 21-LOC shim over `charter.nlah_loader` — D.5 is the **5th native v1.2 agent**). **Not** in the v1.3 always-on class — D.5 honours every budget axis. **Does not consume** the v1.4 candidate (sub-agent spawning primitive); single-driver per the agent spec.

**Schema reuse (Q1).** D.5 re-exports F.3's `class_uid 2003 Compliance Finding` schema verbatim — `Severity`, `AffectedResource`, `CloudPostureFinding`, `build_finding`, `FindingsReport`, and the cloud-agnostic `FINDING_ID_RE` (`CSPM-<CLOUD>-<SVC>-<NNN>-<context>`). Adds D.5-specific `CloudProvider` enum (AZURE / GCP) and `CSPMFindingType` enum (4 discriminators) on top.

LLM use: **not load-bearing** (contrast with D.7). Normalizers are deterministic. The `LLMProvider` parameter on `agent.run` is plumbed but never called in v0.1 — keeps the contract surface stable when Phase 1c adds optional LLM narrative.

## Quick start

```bash
# 1. Run the local eval suite (10/10)
uv run multi-cloud-posture eval packages/agents/multi-cloud-posture/eval/cases

# 2. Run via the eval-framework (resolves through nexus_eval_runners entry-point)
uv run eval-framework run \
    --runner multi_cloud_posture \
    --cases packages/agents/multi-cloud-posture/eval/cases \
    --output /tmp/d5-eval-out.json

# 3. Run against an ExecutionContract — four optional feeds
uv run multi-cloud-posture run \
    --contract path/to/contract.yaml \
    --azure-findings-feed /tmp/azure-defender.json \
    --azure-activity-feed /tmp/azure-activity-log.json \
    --gcp-findings-feed /tmp/gcp-scc-findings.json \
    --gcp-iam-feed /tmp/gcp-iam-policies.json \
    --customer-domain example.com \
    --customer-domain corp.example.com
```

See [`runbooks/multicloud_scan.md`](runbooks/multicloud_scan.md) for the full operator workflow (staging the four feeds · interpreting the three artifacts · severity escalation rules · routing findings to D.7 Investigation + F.6 Audit · troubleshooting).

## Architecture

```
Azure Defender for Cloud ──→ read_azure_findings ───┐
Azure Activity Log ────────→ read_azure_activity ───┤
                                                    ├──→ INGEST (TaskGroup)
GCP Security Command Center → read_gcp_findings ────┤
GCP Cloud Asset Inventory ──→ read_gcp_iam_findings ┘
                                                    │
                                                    ▼
                              ┌──────────────────────────────────┐
                              │ normalize_azure (Defender + Activity)  │
                              │ normalize_gcp (SCC + IAM)              │   NORMALIZE + SCORE
                              │     → CloudPostureFinding tuple        │   (F.3 build_finding;
                              │     class_uid 2003 = F.3 wire shape    │    deterministic severity)
                              └────────────────┬─────────────────┘
                                               │
                                       render_summary             SUMMARIZE
                                  (per-cloud + CRITICAL pinned)
                                               │
                                               ▼
                                  findings.json + report.md       HANDOFF
                                  + audit.jsonl
```

Four async readers ([`tools/`](src/multi_cloud_posture/tools/)) and two pure-function normalizers ([`normalizers/`](src/multi_cloud_posture/normalizers/)). Plus summarizer ([`summarizer.py`](src/multi_cloud_posture/summarizer.py)) and the agent driver ([`agent.py`](src/multi_cloud_posture/agent.py)).

## Output contract — the three artifacts

| File            | Format                                | Purpose                                                                                                                 |
| --------------- | ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `findings.json` | `FindingsReport.model_dump_json()`    | Wire shape consumed by D.7 Investigation, fabric routing, Meta-Harness. **OCSF 2003 — identical to F.3 cloud-posture.** |
| `report.md`     | Markdown                              | Operator summary. Per-cloud breakdown pinned at top; CRITICAL findings pinned above per-severity sections.              |
| `audit.jsonl`   | `charter.audit.AuditEntry` JSON-lines | This run's own hash-chained audit log. F.6 `audit-agent query` reads it.                                                |

## Tests

```bash
uv run pytest packages/agents/multi-cloud-posture -q
```

204 tests; mypy strict clean. **10/10 eval acceptance gate** via the eval-framework entry-point:

```bash
uv run eval-framework run --runner multi_cloud_posture \
    --cases packages/agents/multi-cloud-posture/eval/cases \
    --output /tmp/d5-eval-out.json
# → 10/10 passed (100.0%)
```

## License

BSL 1.1 per [ADR-001](../../../docs/_meta/decisions/ADR-001-monorepo-bootstrap.md). Substrate this agent consumes (`charter`, `cloud-posture`, `eval-framework`) is Apache 2.0; the agent itself is BSL.
