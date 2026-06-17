# `nexus-multi-cloud-posture-agent`

Multi-Cloud Posture Agent — **third Phase-1b agent**; **eighth under [ADR-007](../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)** (F.3 / D.1 / D.2 / D.3 / F.6 / D.7 / D.4 / **multi-cloud-posture**). Lifts CSPM coverage from AWS-only (F.3) to **Azure + GCP**.

> **Agent-ID note (v0.4, 2026-06-18).** Earlier copy self-claimed "D.5", which collided with the Data Security agent (DSPM, the canonical D.5). Per the v0.4 D-numbering resolution this agent is **D.15** (clear primacy after AppSec D.14). The python package directory name (`multi-cloud-posture`) is unchanged.

**Status: v0.2 (Level 2 — live Azure + GCP, single-subscription / single-project).** v0.2 matures the agent from offline JSON passthrough to **live SDKs + native rule engines**, an [ADR-010](../../../docs/_meta/decisions/ADR-010-version-extension-template.md) version-extension. See the [v0.2 plan](../../../docs/superpowers/plans/2026-06-09-d-5-multi-cloud-posture-v0-2.md).

## v0.2 (Level 2) — what's new

Per-cloud (single subscription / single project — Q6), no charter touch (D.15 is the 2nd consumer of F.3's seams; the charter hoist fires at D.2):

- **Credential resolvers** — Azure `DefaultAzureCredential` chain ([`credentials_azure.py`](src/multi_cloud_posture/credentials_azure.py), `--azure-credential-source`) and GCP ADC ([`credentials_gcp.py`](src/multi_cloud_posture/credentials_gcp.py), `--gcp-credential-source`). Secret-free seams.
- **Subscription / project + region discovery** — current-scope only ([`tools/azure_discovery.py`](src/multi_cloud_posture/tools/azure_discovery.py), [`tools/gcp_discovery.py`](src/multi_cloud_posture/tools/gcp_discovery.py)).
- **Region scoping** — `--azure-regions` / `--gcp-regions` (default = all discovered), one shared precedence helper ([`region_scope.py`](src/multi_cloud_posture/region_scope.py)).
- **Native rule engines** — **~8 CIS-Azure** ([`rules_azure/`](src/multi_cloud_posture/rules_azure/)) + **~10 CIS-GCP** ([`rules_gcp/`](src/multi_cloud_posture/rules_gcp/)) rules (plus the existing ~5 IAM-binding rules) emitting `class_uid 2003` tagged **`Source: Nexus-native`**. This closes Azure's zero-native-rule gap (Nexus _detects_, vs the Defender passthrough).
- **Provenance tagging** — every finding plainly distinguishes **Microsoft Defender** / **Google Security Command Center** (passthrough) from **Nexus-native** ([`provenance_label`](src/multi_cloud_posture/schemas.py)).
- **Partial-scan degradation** — a failed region degrades (secret-free marker in `report.md`), not the whole run ([`scan_errors.py`](src/multi_cloud_posture/scan_errors.py)).
- **Gated live-eval lanes** — `NEXUS_LIVE_AZURE=1` / `NEXUS_LIVE_GCP=1` (independent), with read-only integration tests.

**Deferred to v0.3:** multi-subscription / multi-project / organization scope (Q6) · the full CIS-Azure + CIS-GCP rule libraries (Q4) · removal of the Defender + SCC passthrough (Q7 / WI-D7).

## What it does

Four-feed offline forensic analysis. Given an `ExecutionContract` requesting a multi-cloud posture scan, multi-cloud-posture runs a **five-stage pipeline**:

```
INGEST → NORMALIZE → SCORE → SUMMARIZE → HANDOFF
```

Four concurrent input feeds (`asyncio.TaskGroup`):

- **Azure Defender for Cloud** — assessments + alerts JSON exports.
- **Azure Activity Log** — JSON exports; `iam`/`network`/`storage`/`keyvault` operations only (compute lifecycle dropped).
- **GCP Security Command Center** — findings JSON (canonical `ListFindingsResponse` + gcloud wrapper + bare-array shapes).
- **GCP Cloud Asset Inventory IAM** — bindings analysed deterministically (public + impersonation → CRITICAL; `roles/owner` to external user → CRITICAL; `roles/editor` to user → MEDIUM; etc.).

Two deterministic normalizers (`normalize_azure` + `normalize_gcp`) lift the typed reader outputs into OCSF v1.3 Compliance Findings via **F.3's re-exported `build_finding`** — multi-cloud-posture emits the **identical wire shape** (`class_uid 2003`) as F.3 cloud-posture. Downstream consumers (Meta-Harness, D.7 Investigation, fabric routing) already filter on `class_uid 2003`; multi-cloud-posture is invisible at the schema level. The `finding_info.types[0]` discriminator carries `cspm_azure_defender` / `cspm_azure_activity` / `cspm_gcp_scc` / `cspm_gcp_iam`.

Operators see per-cloud breakdown (Azure: Defender + Activity counts; GCP: SCC + IAM counts) and CRITICAL findings **pinned above** the per-severity sections (mirrors F.3 + D.3 + D.4 patterns).

## ADR-007 conformance

multi-cloud-posture is the **eighth** agent under the reference template. Inherits v1.1 (LLM adapter via `charter.llm_adapter`; no per-agent `llm.py`) and v1.2 (NLAH loader is a 21-LOC shim over `charter.nlah_loader` — multi-cloud-posture is the **5th native v1.2 agent**). **Not** in the v1.3 always-on class — multi-cloud-posture honours every budget axis. **Does not consume** the v1.4 candidate (sub-agent spawning primitive); single-driver per the agent spec.

**Schema reuse (Q1).** multi-cloud-posture re-exports F.3's `class_uid 2003 Compliance Finding` schema verbatim — `Severity`, `AffectedResource`, `CloudPostureFinding`, `build_finding`, `FindingsReport`, and the cloud-agnostic `FINDING_ID_RE` (`CSPM-<CLOUD>-<SVC>-<NNN>-<context>`). Adds package-specific `CloudProvider` enum (AZURE / GCP) and `CSPMFindingType` enum (4 discriminators) on top.

LLM use: **not load-bearing** (contrast with D.7). Normalizers are deterministic. The `LLMProvider` parameter on `agent.run` is plumbed but never called in v0.1 — keeps the contract surface stable when Phase 1c adds optional LLM narrative.

## Quick start

```bash
# 1. Run the local eval suite (10/10)
uv run multi-cloud-posture eval packages/agents/multi-cloud-posture/eval/cases

# 2. Run via the eval-framework (resolves through nexus_eval_runners entry-point)
uv run eval-framework run \
    --runner multi_cloud_posture \
    --cases packages/agents/multi-cloud-posture/eval/cases \
    --output /tmp/multi-cloud-posture-eval-out.json

# 3. Run against an ExecutionContract — four optional feeds
uv run multi-cloud-posture run \
    --contract path/to/contract.yaml \
    --azure-findings-feed /tmp/azure-defender.json \
    --azure-activity-feed /tmp/azure-activity-log.json \
    --gcp-findings-feed /tmp/gcp-scc-findings.json \
    --gcp-iam-feed /tmp/gcp-iam-policies.json \
    --customer-domain example.com \
    --customer-domain corp.example.com

# v0.2 live credential / region options (consumed by the live readers):
uv run multi-cloud-posture run --contract path/to/contract.yaml \
    --azure-credential-source chain --azure-regions eastus,westus \
    --gcp-credential-source adc --gcp-regions us-central1,us-west1
```

Per-cloud live runbooks: [`runbooks/azure_dev_subscription_smoke.md`](runbooks/azure_dev_subscription_smoke.md) · [`runbooks/gcp_dev_project_smoke.md`](runbooks/gcp_dev_project_smoke.md). Offline workflow: [`runbooks/multicloud_scan.md`](runbooks/multicloud_scan.md).

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

# v0.2 gated live integration tests (read-only; opt in, independent lanes):
NEXUS_LIVE_AZURE=1 uv run pytest \
    packages/agents/multi-cloud-posture/tests/integration/test_agent_azure_live.py
NEXUS_LIVE_GCP=1 uv run pytest \
    packages/agents/multi-cloud-posture/tests/integration/test_agent_gcp_live.py
```

344 tests (v0.2); mypy strict clean. **10/10 eval acceptance gate** via the eval-framework entry-point:

```bash
uv run eval-framework run --runner multi_cloud_posture \
    --cases packages/agents/multi-cloud-posture/eval/cases \
    --output /tmp/multi-cloud-posture-eval-out.json
# → 10/10 passed (100.0%)
```

## License

BSL 1.1 per [ADR-001](../../../docs/_meta/decisions/ADR-001-monorepo-bootstrap.md). Substrate this agent consumes (`charter`, `cloud-posture`, `eval-framework`) is Apache 2.0; the agent itself is BSL.
