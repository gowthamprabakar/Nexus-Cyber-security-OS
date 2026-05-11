# Example 2 — Clean cluster (no findings)

A well-governed Kubernetes cluster with no Falco / Tracee alerts firing and no anomalous OSQuery rows. This is the "happy path" the agent must handle without false positives.

## Inputs

`agent.run(... falco_feed=empty.jsonl, tracee_feed=empty.jsonl, osquery_pack=baseline.sql ...)`.

- `empty.jsonl` exists but contains zero lines.
- `baseline.sql` returns zero rows (e.g. `SELECT pid, name FROM processes WHERE parent_pid NOT IN (SELECT pid FROM processes)` — no orphans).

## Output

`findings.json`:

```json
{
  "agent": "runtime_threat",
  "agent_version": "0.1.0",
  "customer_id": "cust_acme",
  "run_id": "run_2",
  "scan_started_at": "2026-05-11T12:00:00+00:00",
  "scan_completed_at": "2026-05-11T12:00:01+00:00",
  "findings": []
}
```

`summary.md`:

```markdown
# Runtime Threat Scan

- Customer: `cust_acme`
- Run ID: `run_2`
- Scan window: 2026-05-11T12:00:00+00:00 → 2026-05-11T12:00:01+00:00
- Total findings: **0**

## Summary

No runtime threats detected in this scan window.
```

## Why this shape

- A zero-finding scan is a valid and common output. Downstream consumers must handle the empty-findings path without special-casing.
- An empty `falco.jsonl` is NOT a missing feed — `FalcoError` raises only when the file is **missing**, not when it's empty. Operators routinely tail a Falco feed to a file that hasn't seen alerts yet.
- The agent must not synthesize findings from "everything looks normal" — false positives in CWPP are the primary reason analysts disable runtime sensors.
