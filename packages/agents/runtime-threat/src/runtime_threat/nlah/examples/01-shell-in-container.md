# Example 1 — Shell-in-container (Falco) → CRITICAL finding

The canonical CWPP finding: a Falco rule fires when an interactive shell is spawned inside a production container. This is the precise shape downstream consumers (control plane, ChatOps S.3) page on.

## Inputs

Falco JSONL feed (`falco.jsonl`):

```json
{
  "time": "2026-05-11T12:00:00.123Z",
  "rule": "Terminal shell in container",
  "priority": "Critical",
  "output": "A shell was used as the entrypoint/exec point",
  "output_fields": {
    "container.id": "abc123def456",
    "container.image.repository": "nginx",
    "proc.cmdline": "/bin/sh",
    "proc.pid": 4242,
    "user.name": "root",
    "k8s.pod.name": "frontend-7f9d-abcde",
    "k8s.ns.name": "production"
  },
  "tags": ["container", "shell", "process", "mitre_execution"]
}
```

`agent.run(... falco_feed=falco.jsonl ...)`.

## Output

`findings.json` — one finding, CRITICAL severity, RUNTIME_PROCESS family:

```json
{
  "agent": "runtime_threat",
  "agent_version": "0.1.0",
  "customer_id": "cust_acme",
  "run_id": "run_1",
  "scan_started_at": "2026-05-11T12:00:00+00:00",
  "scan_completed_at": "2026-05-11T12:00:01+00:00",
  "findings": [
    {
      "class_uid": 2004,
      "class_name": "Detection Finding",
      "severity_id": 5,
      "severity": "Critical",
      "finding_info": {
        "uid": "RUNTIME-PROCESS-ABC123DEF456-001-terminal-shell-in-container",
        "title": "Terminal shell in container",
        "desc": "A shell was used as the entrypoint/exec point",
        "types": ["runtime_process"],
        "product_uid": "Terminal shell in container"
      },
      "affected_hosts": [
        {
          "hostname": "frontend-7f9d-abcde",
          "uid": "abc123def456",
          "image": {"ref": "nginx"},
          "namespace": "production"
        }
      ],
      "evidences": [
        {
          "falco_rule": "Terminal shell in container",
          "falco_priority": "Critical",
          "falco_tags": ["container", "shell", "process", "mitre_execution"],
          "output_fields": {
            "container.id": "abc123def456",
            "proc.cmdline": "/bin/sh",
            "proc.pid": 4242,
            "user.name": "root",
            "k8s.pod.name": "frontend-7f9d-abcde",
            "k8s.ns.name": "production"
          }
        }
      ],
      "nexus_envelope": { "tenant_id": "cust_acme", ... }
    }
  ]
}
```

`summary.md` (excerpt):

```markdown
# Runtime Threat Scan

- Customer: `cust_acme`
- Run ID: `run_1`
- Total findings: **1**

## Critical runtime alerts (1)

Drop-everything alerts — investigate before any other finding family.

- `RUNTIME-PROCESS-ABC123DEF456-001-terminal-shell-in-container` — Terminal shell in container  
  Type: runtime_process; Hosts: abc123def456

## Findings

### Critical (1)

- `RUNTIME-PROCESS-ABC123DEF456-001-terminal-shell-in-container` — Terminal shell in container  
  Type: runtime_process; Hosts: abc123def456
```

## Why this shape

- The "Critical runtime alerts" pin gives an SRE 30-second triage — one finding to focus on.
- The Falco rule lands in `finding_info.product_uid` so downstream consumers can join on it.
- All the Falco `output_fields` survive into `evidences[0]` verbatim — the future Investigation Agent (D.7) reads them to chain into pod / image / build provenance.
- Severity rolls up via the priority normalizer: Falco `Critical` → `severity_id: 5`.
