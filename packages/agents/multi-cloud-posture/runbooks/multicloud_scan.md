# Multi-cloud posture scan — operator runbook

Owner: multi-cloud-posture on-call · Audience: a cloud-security operator / SRE with read access to Azure Defender for Cloud, Azure Activity Log, GCP Security Command Center, and GCP Cloud Asset Inventory IAM · Last reviewed: 2026-05-13.

This runbook walks an operator through pointing the Multi-Cloud Posture Agent (D.5) at the four v0.1 feeds — Azure Defender + Azure Activity Log + GCP SCC + GCP Cloud Asset Inventory IAM — interpreting the OCSF Compliance Findings it emits, and routing the findings into the rest of the Nexus pipeline (D.7 Investigation, F.6 Audit).

> **Status:** v0.1. Live SDK calls (`azure-mgmt-security` / `google-cloud-securitycenter`) and per-tenant secret-store integration ship in Phase 1c. v0.1 reads operator-pinned filesystem snapshots.

---

## Prerequisites

- A working `uv sync` of this repository.
- **At least one** of the four feeds:
  - **Azure Defender for Cloud** JSON export (assessments + alerts).
  - **Azure Activity Log** JSON export.
  - **GCP Security Command Center** findings JSON.
  - **GCP Cloud Asset Inventory IAM** policies JSON.
- An `ExecutionContract` YAML for the run.

The agent **never writes** to Azure or GCP. Every call is a filesystem read — safe to run against snapshots copied off production.

---

## 1. Stage the feeds

### 1a. Azure Defender for Cloud

Use the Azure CLI or the REST API. Two snapshot types — `assessments` (posture recommendations) and `alerts` (active threats):

```bash
# Assessments
az rest \
    --method get \
    --url "https://management.azure.com/subscriptions/<sub-id>/providers/Microsoft.Security/assessments?api-version=2020-01-01" \
    > /tmp/azure-defender-assessments.json

# Alerts
az rest \
    --method get \
    --url "https://management.azure.com/subscriptions/<sub-id>/providers/Microsoft.Security/alerts?api-version=2022-01-01" \
    > /tmp/azure-defender-alerts.json
```

The reader auto-detects which shape each top-level `{"value": [...]}` carries (or a bare array — some tools flatten the response). Severity values: `Critical` / `High` / `Medium` / `Low` / `Informational`. Records with `status="Healthy"` (assessments only) are filtered out by the normalizer — those mean configuration is **correct**, not a finding.

### 1b. Azure Activity Log

```bash
az monitor activity-log list \
    --start-time 2026-05-12T00:00:00Z \
    --end-time   2026-05-13T23:59:59Z \
    -o json \
    > /tmp/azure-activity-log.json
```

The reader classifies each entry's `operationName` into 6 buckets:

- `iam` — `Microsoft.Authorization/...`
- `network` — `Microsoft.Network/...`
- `storage` — `Microsoft.Storage/...`
- `compute` — `Microsoft.Compute/...` (dropped by the normalizer; lifecycle noise)
- `keyvault` — `Microsoft.KeyVault/...`
- `other` — anything else (dropped by the normalizer)

Only `iam` / `network` / `storage` / `keyvault` records produce findings.

### 1c. GCP Security Command Center

Requires SCC **Standard tier** or higher. Use the `gcloud` CLI:

```bash
gcloud scc findings list \
    organizations/<org-id> \
    --filter='state="ACTIVE"' \
    --format=json \
    > /tmp/gcp-scc-findings.json
```

The reader supports three top-level shapes: canonical `{"listFindingsResults": [{"finding": ..., "resource": ...}]}` (REST API), `{"findings": [...]}` (`gcloud` flat-wrapper), and bare array. SCC severity values: `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `SEVERITY_UNSPECIFIED`. Records with `state="INACTIVE"` are filtered by the normalizer (closed findings).

### 1d. GCP Cloud Asset Inventory IAM

```bash
gcloud asset search-all-iam-policies \
    --scope=projects/<project-id> \
    --format=json \
    > /tmp/gcp-iam-policies.json
```

The reader supports `{"results": [...]}` canonical + bare-array shapes. The analyser flags overly-permissive bindings deterministically (no LLM):

| Binding shape                                                         | Severity |
| --------------------------------------------------------------------- | -------- |
| `allUsers` / `allAuthenticatedUsers` + impersonation role             | CRITICAL |
| `allUsers` / `allAuthenticatedUsers` + any other role                 | HIGH     |
| `roles/owner` to `user:*@<external>` (not in `--customer-domain` set) | CRITICAL |
| `roles/owner` to user / group / serviceAccount                        | HIGH     |
| `roles/editor` to `user:*`                                            | MEDIUM   |
| Everything else                                                       | benign   |

**Stale service accounts** are NOT detected in v0.1 — that requires the IAM usage API (Phase 1c).

---

## 2. Write the `ExecutionContract`

Minimal `contract.yaml`:

```yaml
schema_version: '0.1'
delegation_id: 01J7M3X9Z1K8RPVQNH2T8DBHFZ
source_agent: supervisor
target_agent: multi_cloud_posture
customer_id: cust_acme
task: Multi-cloud posture scan — 2026-05-13 quarterly review
required_outputs:
  - findings.json
  - report.md
budget:
  llm_calls: 0 # normalizers are deterministic; LLM not called in v0.1
  tokens: 0
  wall_clock_sec: 60.0
  cloud_api_calls: 0
  mb_written: 10
permitted_tools:
  - read_azure_findings
  - read_azure_activity
  - read_gcp_findings
  - read_gcp_iam_findings
completion_condition: findings.json AND report.md exist
escalation_rules: []
workspace: /workspaces/cust_acme/multi_cloud_posture/01J7M3X9.../
persistent_root: /persistent/cust_acme/multi_cloud_posture/
created_at: '2026-05-13T12:00:00Z'
expires_at: '2026-05-13T13:00:00Z'
```

---

## 3. Run the agent

```bash
uv run multi-cloud-posture run \
    --contract /tmp/contract.yaml \
    --azure-findings-feed /tmp/azure-defender-assessments.json \
    --azure-activity-feed /tmp/azure-activity-log.json \
    --gcp-findings-feed /tmp/gcp-scc-findings.json \
    --gcp-iam-feed /tmp/gcp-iam-policies.json \
    --customer-domain example.com \
    --customer-domain corp.example.com
```

Each feed flag is optional — supply only what you have. With **no** feeds, the agent emits a clean empty report (useful for validating substrate plumbing). `--customer-domain` is repeatable; bindings to users on listed domains get HIGH (not CRITICAL) when the role is `roles/owner`.

Sample output:

```
agent: multi_cloud_posture (v0.1.0)
customer: cust_acme
run_id: 01J7M3X9Z1K8RPVQNH2T8DBHFZ
findings: 7
  critical: 1
  high: 3
  medium: 2
  low: 0
  info: 1
workspace: /workspaces/cust_acme/multi_cloud_posture/01J7M3X9.../
```

---

## 4. Read the three artifacts

| File            | Format                                | Purpose                                                                                                                                    |
| --------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `findings.json` | `FindingsReport.model_dump_json()`    | Wire shape consumed by D.7 Investigation, fabric routing, Meta-Harness. OCSF 2003 array under `findings`. **Identical wire shape to F.3.** |
| `report.md`     | Markdown                              | Operator summary. Per-cloud breakdown pinned at top; CRITICAL findings pinned above per-severity sections.                                 |
| `audit.jsonl`   | `charter.audit.AuditEntry` JSON-lines | This run's own hash-chained audit log. F.6 `audit-agent query` reads it.                                                                   |

### Reading `report.md`

Top-down layout:

```
# Multi-Cloud Posture Scan
- Customer / Run ID / Scan window / Total findings
## Per-cloud breakdown        ← PINNED Azure + GCP totals + per-source counts
## Severity breakdown         ← critical → info counts
## Source-type breakdown      ← 4 CSPMFindingType discriminators
## Critical findings          ← PINNED (every CRITICAL, drop-everything)
## Findings
### Critical (N)
### High (N)
### Medium (N)
### Low (N)
### Info (N)
```

If you see no `## Critical findings` section, no CRITICAL findings fired — operate from the per-severity sections in order.

---

## 5. Severity escalation rules (deterministic, no LLM)

| Source                    | Source value            | OCSF `Severity` |
| ------------------------- | ----------------------- | --------------- |
| Defender assessment/alert | Critical                | CRITICAL        |
| Defender assessment/alert | High                    | HIGH            |
| Defender assessment/alert | Medium                  | MEDIUM          |
| Defender assessment/alert | Low                     | LOW             |
| Defender assessment/alert | Informational           | INFO            |
| Activity Log              | Critical / Error        | HIGH            |
| Activity Log              | Warning                 | MEDIUM          |
| Activity Log              | Informational / Verbose | INFO            |
| SCC                       | CRITICAL                | CRITICAL        |
| SCC                       | HIGH                    | HIGH            |
| SCC                       | MEDIUM                  | MEDIUM          |
| SCC                       | LOW                     | LOW             |
| SCC                       | SEVERITY_UNSPECIFIED    | INFO            |
| IAM analyser              | CRITICAL                | CRITICAL        |
| IAM analyser              | HIGH                    | HIGH            |
| IAM analyser              | MEDIUM                  | MEDIUM          |
| IAM analyser              | LOW                     | LOW             |

---

## 6. Routing findings downstream

### To D.7 Investigation

Pin the D.5 workspace as a `--sibling-workspace`:

```bash
uv run investigation-agent run \
    --contract /tmp/d7-contract.yaml \
    --sibling-workspace /workspaces/cust_acme/multi_cloud_posture/01J7M3X9.../
```

D.7 reads `findings.json` and folds the multi-cloud posture findings into its 6-stage incident-correlation pipeline. **D.5 emits the same `class_uid 2003` as F.3 cloud-posture**, so D.7's correlation logic doesn't need cloud-specific code — only the `finding_info.types[0]` discriminator distinguishes the source.

### To F.6 Audit

D.5 emits its own audit chain at `<workspace>/audit.jsonl`:

```bash
uv run audit-agent query \
    --tenant cust_acme \
    --workspace /tmp/audit-query \
    --source /workspaces/cust_acme/multi_cloud_posture/01J7M3X9.../audit.jsonl \
    --format markdown
```

### To remediation (Phase 1c — NOT in v0.1)

D.5 emits findings only; Track-A remediation (A.1-A.3) lands in Phase 1c and acts on the per-finding `rule_id` + `affected.resource_id` to drive Tier-1/2/3 actions.

---

## 7. Troubleshooting

| Symptom                                                           | Likely cause                                                                                                                                      | Fix                                                                                                                          |
| ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `findings: 0` with feeds clearly populated                        | All Defender assessments are `status="Healthy"`; or Activity Log entries are `compute`/`other` class; or all SCC findings are `state="INACTIVE"`. | Inspect raw counts via `jq` on each input. Filtering is intentional — only actionable findings ride through.                 |
| GCP IAM normalizer skips `roles/owner` bindings                   | The binding member is not a `user:*` / `group:*` / `serviceAccount:*` prefix (Google-managed identity?).                                          | Confirm member format; only the four canonical prefixes are graded.                                                          |
| `AzureDefenderReaderError: malformed`                             | Top-level JSON is broken (truncated download, mixed encoding).                                                                                    | Re-download the snapshot; the reader explicitly raises on top-level parse errors (no silent drop for bulk feeds).            |
| All Azure findings show `subscription_id="unknown"`               | `resourceId` in the source records is empty AND the record_id path doesn't follow `/subscriptions/<id>/...`.                                      | Verify the Defender export wasn't filtered to bare-property fields; rerun the export with the full ARM response shape.       |
| External-user owner-role finding flagged HIGH instead of CRITICAL | `--customer-domain` allowlist not supplied at run time.                                                                                           | Re-run with `--customer-domain example.com --customer-domain corp.example.com` (or omit to keep all external users at HIGH). |
| `report.md` has all Suricata-style noise, no per-cloud pin        | This shouldn't happen — per-cloud + CRITICAL are pinned by the summarizer.                                                                        | If you see this, file a bug — the pin is enforced by `render_summary`.                                                       |

---

## 8. Production deployment notes

- **AWS coverage** lives in F.3 cloud-posture, not D.5. F.3 + D.5 together cover the three top clouds (~95% of customer footprint).
- **Live SDK paths** (Azure `azure-mgmt-security` + GCP `google-cloud-securitycenter`) land in Phase 1c behind the same reader signatures — operators won't need to change CLI usage when the live path ships.
- **GCP SCC tier requirement**: Standard tier minimum. Without SCC enabled, only the IAM feed produces findings (and Azure feeds if applicable).
- **Bundled v0.1 IAM grading rules** cover the highest-impact bindings; deeper rule sets (e.g. role-chain analysis, custom-role detection) land in Phase 1c.
- **Multi-cloud correlation** is D.7's job. D.5 emits per-cloud findings; D.7 stitches them into one incident timeline.

---

## Cross-references

- D.5 plan: [`docs/superpowers/plans/2026-05-13-d-5-multi-cloud-posture.md`](../../../../docs/superpowers/plans/2026-05-13-d-5-multi-cloud-posture.md)
- F.3 cloud-posture (AWS reference): [`packages/agents/cloud-posture/`](../../cloud-posture/)
- D.7 Investigation consumer: [`packages/agents/investigation/runbooks/investigation_workflow.md`](../../investigation/runbooks/investigation_workflow.md)
- F.6 Audit query: [`packages/agents/audit/runbooks/audit_query_operator.md`](../../audit/runbooks/audit_query_operator.md)
- ADR-007 (reference NLAH, D.5 is the 8th agent): [`docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md`](../../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)
