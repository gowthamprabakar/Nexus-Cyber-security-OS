# Network triage — operator runbook

Owner: network-threat-agent on-call · Audience: a SOC analyst / SRE with read access to Suricata `eve.json`, AWS VPC Flow Logs, and DNS query logs · Last reviewed: 2026-05-13.

This runbook walks an operator through pointing the Network Threat Agent at the three v0.1 feeds — Suricata + AWS VPC Flow Logs + DNS — interpreting the four OCSF Detection Findings it can emit (`PORT_SCAN`, `BEACON`, `DGA`, `SURICATA`), and routing the findings into the rest of the Nexus pipeline (D.7 Investigation, F.6 Audit, downstream Track-A remediation when that ships).

> **Status:** v0.1. Tier-1 `block_ip_at_waf` action is **NOT** implemented; D.4 v0.1 emits findings only. Phase 1c adds the WAF substrate.

---

## Prerequisites

- A working `uv sync` of this repository.
- **At least one** of the three feeds:
  - A Suricata `eve.json` ndjson file (Suricata's `output.eve-log.enabled: yes` config). Typical path: `/var/log/suricata/eve.json`.
  - An AWS VPC Flow Logs file (S3 → local copy, plaintext or `.gz`). v2 default + v3/v4/v5 with explicit header all supported.
  - A DNS log file: BIND query log (named) OR an AWS Route 53 Resolver Query Logs ndjson file (CloudWatch Logs export, S3-delivered).
- An `ExecutionContract` YAML for the run.

The agent **never writes** to the underlying sensors. Every call is a filesystem read — safe to run against snapshot files copied off production.

---

## 1. Stage the three feeds

### 1a. Suricata

```bash
sudo cp /var/log/suricata/eve.json /tmp/suricata-snapshot.json
```

The reader only consumes `event_type = "alert"` records. `dns`, `flow`, `http`, `tls`, `fileinfo` events are skipped — they're parsed by their respective typed readers in `D.4 tools/`. An **empty file** = "no Suricata alerts" (not an error). A **missing file** raises `SuricataReaderError`.

### 1b. AWS VPC Flow Logs

If your flow logs already land in S3 (`s3://my-flow-logs/AWSLogs/<account>/vpcflowlogs/...`):

```bash
aws s3 cp s3://my-flow-logs/AWSLogs/.../my-flow-log-file.log.gz /tmp/flow-snapshot.log.gz
```

The reader auto-detects gzip vs plaintext via the magic bytes (`\x1f\x8b`). The default v2 14-field layout is assumed if no `version`-bearing header line is present; with a header, the reader maps fields by name (v3/v4/v5 all work).

If your flow logs land in CloudWatch instead, export to S3 first (CloudWatch → Actions → Create export task), then download as above.

### 1c. DNS logs

**BIND query log** (`named` with `logging { channel queries { ... }; };`):

```bash
sudo cp /var/log/named/queries.log /tmp/dns-snapshot.log
```

**AWS Route 53 Resolver Query Logs** (CloudWatch Logs → S3):

```bash
aws s3 cp s3://my-dns-logs/AWSLogs/.../resolver-query-logs.jsonl /tmp/dns-snapshot.log
```

The reader peeks the first non-blank line: if it parses as a JSON object, the file is treated as Route 53 ndjson; otherwise BIND text. No extension dispatch — operator pipelines vary.

---

## 2. Write the `ExecutionContract`

Minimal `contract.yaml`:

```yaml
schema_version: '0.1'
delegation_id: 01J7M3X9Z1K8RPVQNH2T8DBHFZ # ULID; use `python -c "import ulid; print(ulid.new())"` if you have python-ulid
source_agent: supervisor
target_agent: network_threat
customer_id: cust_acme
task: Network threat scan — 2026-05-13 incident triage
required_outputs:
  - findings.json
  - report.md
budget:
  llm_calls: 0 # detectors are deterministic; LLM not called in v0.1
  tokens: 0
  wall_clock_sec: 60.0
  cloud_api_calls: 0
  mb_written: 10
permitted_tools:
  - read_suricata_alerts
  - read_vpc_flow_logs
  - read_dns_logs
completion_condition: findings.json AND report.md exist
escalation_rules: []
workspace: /workspaces/cust_acme/network_threat/01J7M3X9.../
persistent_root: /persistent/cust_acme/network_threat/
created_at: '2026-05-13T12:00:00Z'
expires_at: '2026-05-13T13:00:00Z'
```

---

## 3. Run the agent

```bash
uv run network-threat run \
    --contract /tmp/contract.yaml \
    --suricata-feed /tmp/suricata-snapshot.json \
    --vpc-flow-feed /tmp/flow-snapshot.log.gz \
    --dns-feed /tmp/dns-snapshot.log
```

Each feed flag is optional — supply only what you have. With **no** feeds, the agent emits a clean empty report (useful for validating substrate plumbing).

Sample output:

```
agent: network_threat (v0.1.0)
customer: cust_acme
run_id: 01J7M3X9Z1K8RPVQNH2T8DBHFZ
findings: 4
  critical: 1
  high: 2
  medium: 1
  low: 0
  info: 0
  network_port_scan: 1
  network_beacon: 1
  network_dga: 1
  network_suricata: 1
workspace: /workspaces/cust_acme/network_threat/01J7M3X9.../
```

---

## 4. Read the three artifacts

| File            | Format                                | Purpose                                                                                                             |
| --------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `findings.json` | `FindingsReport.model_dump_json()`    | Wire shape consumed by D.7 Investigation, fabric routing, Meta-Harness. OCSF 2004 array under `findings`.           |
| `report.md`     | Markdown                              | Operator summary. Beacons + DGA pinned **above** per-severity sections (mirrors F.6 tamper-pin + D.3 critical-pin). |
| `audit.jsonl`   | `charter.audit.AuditEntry` JSON-lines | This run's own hash-chained audit log. F.6 `audit-agent query` can read it.                                         |

### Reading `report.md`

Top-down layout:

```
# Network Threat Scan
- Customer / Run ID / Scan window / Total findings
## Severity breakdown        ← critical → info counts
## Finding-type breakdown    ← port_scan / beacon / dga / suricata counts
## Beacon alerts             ← PINNED (every BEACON regardless of severity)
## DGA domains               ← PINNED (every DGA regardless of severity)
## Findings
### Critical (N)
### High (N)
### Medium (N)
### Low (N)
```

If you see no `## Beacon alerts` or `## DGA domains` sections, the deterministic detectors didn't fire — only Suricata signatures and port-scan rate detection. That's a perfectly valid clean state.

---

## 5. Severity escalation rules (deterministic, no LLM)

| Detector  | MEDIUM                                | HIGH                                  | CRITICAL                                |
| --------- | ------------------------------------- | ------------------------------------- | --------------------------------------- |
| port_scan | ≥ 50 distinct dst-ports / 60s         | ≥ 100                                 | ≥ 200                                   |
| beacon    | count ≥ 5, CoV ≤ 0.30                 | count ≥ 20 AND CoV ≤ 0.20             | count ≥ 50 AND CoV ≤ 0.10               |
| dga       | entropy ≥ 3.5 AND bigram_score ≤ 0.30 | entropy ≥ 4.0 AND bigram_score ≤ 0.05 | (intel uplift only; no native CRITICAL) |
| suricata  | severity field 2                      | severity field 1                      | (intel uplift only)                     |

**Intel uplift**: when a finding's `src_ip` / `dst_ip` / `query_name` matches the bundled `data/intel_static.json` snapshot (CISA KEV + abuse.ch + MITRE ATT&CK group references), severity is bumped one level (MEDIUM → HIGH → CRITICAL). The uplifted severity carries the `evidence.intel.tags` annotation explaining why.

---

## 6. Routing findings downstream

### To D.7 Investigation

Pin the D.4 workspace as a `--sibling-workspace`:

```bash
uv run investigation-agent run \
    --contract /tmp/d7-contract.yaml \
    --sibling-workspace /workspaces/cust_acme/network_threat/01J7M3X9.../
```

D.7 reads `findings.json` and folds the network findings into its 6-stage incident-correlation pipeline.

### To F.6 Audit

D.4 already emits its own audit chain at `<workspace>/audit.jsonl`. To query that chain for chain integrity + 5-axis filtering:

```bash
uv run audit-agent query \
    --tenant cust_acme \
    --workspace /tmp/audit-query \
    --source /workspaces/cust_acme/network_threat/01J7M3X9.../audit.jsonl \
    --format markdown
```

### To a WAF (Phase 1c — NOT in v0.1)

In v0.1 D.4 **does not block**. To act on a BEACON finding now, hand the `dst_ip` + matched CIDR to your WAF playbook out-of-band. Track-A remediation (Phase 1c) will land the `block_ip_at_waf` Tier-1 action.

---

## 7. Troubleshooting

| Symptom                                                  | Likely cause                                                                                | Fix                                                                                      |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| `findings: 0` with feeds clearly populated               | Filter axes (loopback / link-local / unspecified) caught everything, or thresholds not met. | Inspect raw counts via `jq '.findings                                                    | length' findings.json`; loosen thresholds via CLI flags. |
| DGA flag on legitimate domain (e.g. `stackoverflow.com`) | Q2 false-positive ceiling — bigram-poor consonant-heavy names can clear the entropy gate.   | Phase 1c ML model fixes this; v0.1 mitigation: add to the bundled suffix allowlist.      |
| `Suricata: file not found`                               | `--suricata-feed` path doesn't exist.                                                       | Verify the path; check `sudo cp` succeeded.                                              |
| `VpcFlowReaderError: not a file`                         | `--vpc-flow-feed` is a directory.                                                           | Pin to a single `.log` or `.log.gz` file.                                                |
| Report has all Suricata noise, beacons buried            | This shouldn't happen — beacons are **pinned above** per-severity sections.                 | If you're seeing this, file a bug — the pin is enforced by `summarizer.render_summary`.  |
| `audit.jsonl` chain breaks on subsequent query           | Workspace was modified after the run (file edited, log rotated mid-write).                  | Quarantine the workspace; re-run the agent to regenerate from a fresh snapshot.          |
| Tor exit IPs not flagged                                 | Bundled intel snapshot is stale.                                                            | Snapshot date is in `data/intel_static.json`; Phase 1c integrates live D.8 Threat Intel. |

---

## 8. Production deployment notes

- **Single-window beacons.** v0.1's `detect_beacon` is single-window in-memory. Beacons that span beyond the input feed's time range are missed. Phase 1c TimescaleDB integration adds historical baselines.
- **AWS-only.** VPC Flow Logs are AWS-specific. Azure NSG Flow Logs + GCP VPC Flow Logs ship in D.5.
- **No live API ingest.** The reader takes filesystem paths only. Phase 1c boto3 `ec2.describe_flow_logs` + S3 → Athena adds live ingest.
- **Bundled intel is a snapshot.** Snapshot date is in `data/intel_static.json`. Phase 1c integrates the D.8 Threat Intel Agent for live VirusTotal + OTX + CISA KEV.
- **LLM not load-bearing.** v0.1 detectors are deterministic. The `LLMProvider` parameter on `agent.run` is plumbed but never called — keeps the contract surface stable when Phase 1c adds LLM narrative.

---

## Cross-references

- D.4 plan: [`docs/superpowers/plans/2026-05-13-d-4-network-threat-agent.md`](../../../../docs/superpowers/plans/2026-05-13-d-4-network-threat-agent.md)
- D.7 Investigation consumer: [`packages/agents/investigation/runbooks/investigation_workflow.md`](../../investigation/runbooks/investigation_workflow.md)
- F.6 Audit query for D.4's audit.jsonl: [`packages/agents/audit/runbooks/audit_query_operator.md`](../../audit/runbooks/audit_query_operator.md)
- ADR-007 (reference NLAH, D.4 is the 7th agent): [`docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md`](../../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)
