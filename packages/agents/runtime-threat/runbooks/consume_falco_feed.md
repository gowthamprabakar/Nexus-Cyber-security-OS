# Consume a Falco / Tracee / OSQuery feed — operator runbook

Owner: runtime-threat-agent on-call · Audience: a human operator with read access to a Falco / Tracee log file or a working `osqueryi` install · Last reviewed: 2026-05-11.

This runbook walks an SRE through pointing the Runtime Threat Agent at a real runtime-alert feed. The agent emits OCSF v1.3 Detection Findings (`class_uid 2004`) into the charter workspace; downstream consumers (Investigation Agent D.7 once it ships, Tier 2 / Tier 3 remediation, ChatOps) pick them up from there.

---

## Prerequisites

- A working `uv sync` of this repository.
- **At least one** of the three feeds:
  - A Falco JSONL feed (Falco's `json_output: true` config). On a typical Linux host this lives at `/var/log/falco/falco.jsonl` or `/var/log/falco.txt` depending on the install.
  - A Tracee JSONL alert feed (Tracee's `--output json` output piped to a file).
  - A local `osqueryi` binary (homebrew or the upstream `osquery` package) and a `.sql` file containing one query per v0.1.
- An `ExecutionContract` YAML for the run (see Section 2).

The agent **never writes** to the underlying sensor — every call is a file read or a one-shot `osqueryi --json` subprocess. You can run this on production hosts without staging permissions.

---

## 1. Stage the runtime feeds

### Falco

Falco emits one alert per line by default in `json_output` mode. Confirm the config:

```bash
sudo grep -E 'json_output|json_include_output_property' /etc/falco/falco.yaml
# Expected:
#   json_output: true
#   json_include_output_property: true
```

Tail or copy the active file to a known path:

```bash
sudo cp /var/log/falco/falco.jsonl /tmp/falco-snapshot.jsonl
```

The agent treats an **empty file** as "no Falco alerts" — it doesn't fail. A **missing file** raises `FalcoError`.

### Tracee

Tracee's JSON output is similar — one alert per line. The typical invocation is:

```bash
sudo tracee --output json --output-file /tmp/tracee-snapshot.jsonl
```

If you don't run Tracee, omit `--tracee-feed` from the CLI invocation.

### OSQuery

Write one SQL query to a `.sql` file. The agent invokes `osqueryi --json <sql>` and emits one `RUNTIME_OSQUERY` finding per result row. Phase 1c will add multi-query JSON-format packs.

Example: find processes whose parent PID isn't in the live process table (orphans, often suspicious):

```sql
-- /tmp/orphan_processes.sql
SELECT pid, name, parent_pid
FROM processes
WHERE parent_pid NOT IN (SELECT pid FROM processes);
```

An **empty `.sql` file** (whitespace only) is treated as "no OSQuery" — the subprocess never fires.

---

## 2. Author an ExecutionContract

The contract is what the charter enforces. Minimal shape:

```yaml
schema_version: '0.1'
delegation_id: '01J7M3X9Z1K8RPVQNH2T8DBHFZ' # ULID; uuidgen + ULID-encode
source_agent: 'operator-cli'
target_agent: 'runtime_threat'
customer_id: 'cust_acme'
task: 'Runtime threat scan from prod-eks-cluster'
required_outputs:
  - 'findings.json'
  - 'summary.md'
budget:
  llm_calls: 1
  tokens: 1
  wall_clock_sec: 300.0
  cloud_api_calls: 10
  mb_written: 10
permitted_tools:
  - 'falco_alerts_read'
  - 'tracee_alerts_read'
  - 'osquery_run'
completion_condition: 'findings.json AND summary.md exist'
escalation_rules: []
workspace: '/tmp/nexus-runtime-threat/cust_acme/run-2026-05-11/ws'
persistent_root: '/tmp/nexus-runtime-threat/cust_acme/run-2026-05-11/p'
created_at: '2026-05-11T12:00:00+00:00'
expires_at: '2026-05-11T12:05:00+00:00'
```

Save to `/tmp/runtime-scan.yaml`. The agent's tools all carry `cloud_calls=0` (filesystem + local subprocess), so a small `cloud_api_calls` budget is fine.

---

## 3. Run the agent

```bash
uv run runtime-threat-agent run \
    --contract /tmp/runtime-scan.yaml \
    --falco-feed /tmp/falco-snapshot.jsonl \
    --tracee-feed /tmp/tracee-snapshot.jsonl \
    --osquery-pack /tmp/orphan_processes.sql \
    --osquery-severity 2 \
    --osquery-finding-context orphan_process
```

You can omit any feed flag; the agent skips it cleanly. The minimal incantation is just `--contract` (empty report).

Expected output:

```
agent: runtime_threat (v0.1.0)
customer: cust_acme
run_id: 01J7M3X9Z1K8RPVQNH2T8DBHFZ
findings: 3
  critical: 1
  high: 1
  medium: 1
  low: 0
  info: 0
  runtime_process: 1
  runtime_file: 0
  runtime_network: 0
  runtime_syscall: 0
  runtime_osquery: 1
workspace: /tmp/nexus-runtime-threat/cust_acme/run-2026-05-11/ws
```

---

## 4. Read the outputs

Three files in the workspace:

```bash
ls /tmp/nexus-runtime-threat/cust_acme/run-2026-05-11/ws/
# findings.json  summary.md  audit.jsonl
```

- **`summary.md`** — start here. The "Critical runtime alerts" section pinned at the top is the 30-second triage. Anything listed there is a drop-everything signal.
- **`findings.json`** — the OCSF wire format. Hand to fabric / downstream agents. Pretty-print with `jq` if needed.
- **`audit.jsonl`** — hash-chained audit log. Verify integrity with `uv run charter audit verify <path>`.

---

## 5. Triage workflow

| Finding family    | Typical severity                         | Default next step                                                                                                                                       |
| ----------------- | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `runtime_process` | Medium → Critical                        | Inspect the container (`docker exec` / `kubectl exec`). If the shell is unexpected, capture process tree, then kill the container per blast-radius cap. |
| `runtime_file`    | Critical                                 | `/etc/shadow` / SSH key / credential file reads are almost always lateral-movement indicators. Quarantine the host.                                     |
| `runtime_network` | Critical (public) / High (cross-account) | Pull NetFlow / Suricata corroboration. If the destination IP is on a threat feed, isolate the source.                                                   |
| `runtime_syscall` | Critical                                 | Kernel-module loads on a production container are catastrophic. Treat as compromised; rebuild the host.                                                 |
| `runtime_osquery` | Caller-defined                           | Query-pack author decides severity. Common pack: orphan processes (medium), suid-binary changes (high).                                                 |

The Phase 1 caps documented in the [README](../README.md) mean v0.1 doesn't yet correlate Falco + Tracee findings for the same incident — you'll see two findings if both sensors fire. **That's intentional**; D.7 Investigation Agent owns the correlation pass.

---

## 6. Common failures

| Symptom                                                | Cause                                                        | Fix                                                                             |
| ------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------------------------- |
| `FalcoError: falco feed missing: /tmp/...`             | Path typo or Falco not configured for `json_output`          | Confirm Section 1 prerequisites                                                 |
| `OsqueryError: osqueryi binary not found`              | `osqueryi` not installed or not on PATH                      | `brew install osquery` / install from `https://osquery.io/downloads`            |
| `OsqueryError: osqueryi exited 1: syntax error`        | Bad SQL in the `.sql` file                                   | Run the query interactively: `osqueryi`                                         |
| Empty `findings.json` despite Falco alerts in the feed | Falco alerts missing required fields (`time`, `rule`)        | Falco emitted malformed JSON; check Falco's stderr for warnings                 |
| `BudgetExhausted: wall_clock_sec`                      | Very large feed file                                         | Split the feed: `split -l 10000 falco.jsonl chunk_` and run the agent per chunk |
| Findings have host_id="unknown-host"                   | Sensor didn't include `container.id` / `k8s.pod.name` / etc. | Confirm Falco is configured with `container.id` enabled                         |

---

## 7. Cleanup

The agent writes only to `workspace` and `persistent_root`. Once you've exported the report:

```bash
rm -rf /tmp/nexus-runtime-threat/cust_acme/run-2026-05-11
```

The original feed files (`/tmp/falco-snapshot.jsonl`, etc.) are not touched.

---

## See also

- [README](../README.md) — package overview + ADR-007 v1.2 conformance addendum.
- [D.3 plan](../../../../docs/superpowers/plans/2026-05-11-d-3-runtime-threat-agent.md).
- [ADR-002](../../../../docs/_meta/decisions/ADR-002-charter-as-context-manager.md) — audit-chain requirement.
- [ADR-004](../../../../docs/_meta/decisions/ADR-004-fabric-layer.md) — OCSF v1.3 + `NexusEnvelope` wire format.
- [ADR-007 v1.2](../../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) — reference template + amendment history.
- [Cloud Posture Agent runbook](../../cloud-posture/runbooks/) — for the CSPM side of a Phase 1a customer setup.
