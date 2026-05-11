# `nexus-runtime-threat`

Runtime Threat Agent — agent **#4 of 18** for Nexus Cyber OS. CWPP (Cloud Workload Protection Platform) — consumes runtime alerts from Falco / Tracee / OSQuery and emits OCSF v1.3 Detection Findings. **First agent built end-to-end against [ADR-007 v1.2](../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)** (post-NLAH-loader-hoist).

## What it does

Reads runtime alert streams produced by eBPF-based sensors (Falco, Tracee) and on-host query engines (OSQuery), normalizes them across the three native severity scales into OCSF v1.3 Detection Findings (`class_uid 2004`), and emits the same wire format every other Track-D agent emits. Five detection families: PROCESS / FILE / NETWORK / SYSCALL / OSQUERY.

The runtime stack itself is **not bundled** — deterministic v0.1 reads JSONL fixture files for Falco / Tracee and invokes a local `osqueryi` subprocess. Live-stream consumption (Falco gRPC, OSQuery distributed scheduler) defers to Phase 1c.

Every action runs through the [runtime charter](../../charter/) — execution contract, per-dimension budget envelope, tool whitelist, audit chain — so the agent cannot exceed its sanctioned scope.

## Quick start

```bash
# 1. Run the local eval suite (10/10 should pass)
uv run runtime-threat-agent eval packages/agents/runtime-threat/eval/cases

# 2. Run via the eval-framework (resolves through nexus_eval_runners entry-point)
uv run eval-framework run \
    --runner runtime_threat \
    --cases packages/agents/runtime-threat/eval/cases \
    --output /tmp/runtime_threat_suite

# 3. Run against real feeds (see runbooks/consume_falco_feed.md)
uv run runtime-threat-agent run \
    --contract path/to/contract.yaml \
    --falco-feed /var/log/falco/falco.jsonl \
    --tracee-feed /var/log/tracee/events.jsonl \
    --osquery-pack /etc/nexus/osquery/orphan_processes.sql
```

## Inputs

A signed `ExecutionContract` (YAML) — schema defined by [`nexus-charter`](../../charter/). Required: budget envelope, permitted-tools whitelist (the three runtime tools listed below), workspace + persistent_root, completion_condition, ULID `delegation_id`.

CLI flags supply the runtime feeds: any combination of `--falco-feed` / `--tracee-feed` / `--osquery-pack`. Each is optional — operators commonly start with Falco-only and add Tracee + OSQuery as their deployments mature.

## Outputs

Three files in the charter-managed workspace:

| File            | Shape                                                                                                     | Purpose                                               |
| --------------- | --------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| `findings.json` | `FindingsReport` ([schemas.py](src/runtime_threat/schemas.py)) — OCSF v1.3 Detection Finding dicts (2004) | Wire format on the future `findings.>` fabric subject |
| `summary.md`    | Markdown digest — severity breakdown, finding-type breakdown, Critical-alerts pin, per-severity sections  | Human-readable for SREs / auditors                    |
| `audit.jsonl`   | Append-only hash chain of every charter event                                                             | Verified by `uv run charter audit verify`             |

## Architecture

```
ExecutionContract (YAML)
    │
    ▼
┌──────────────────────────────────────────────────────────────┐
│ Charter context manager                                      │
│   - workspace setup                                          │
│   - per-dimension budget envelope                            │
│   - tool whitelist (only what the contract permits)          │
│   - hash-chained audit at audit.jsonl                        │
└──────────────────────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────────────────────┐
│ Async tool wrappers (per ADR-005)                            │
│   - falco_alerts_read   (filesystem; JSONL → typed alerts)   │
│   - tracee_alerts_read  (filesystem; JSONL → typed alerts)   │
│   - osquery_run         (subprocess; osqueryi --json)        │
└──────────────────────────────────────────────────────────────┘
    │ concurrent multi-feed read via asyncio.TaskGroup
    ▼
┌──────────────────────────────────────────────────────────────┐
│ Severity normalizer (3 native scales → internal Severity)    │
│   Falco priority (8-level string) / Tracee severity (0-3) /  │
│   OSQuery (caller-supplied 0-3, same scale as Tracee)        │
└──────────────────────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────────────────────┐
│ Findings normalizer — alerts + OSQuery rows → OCSF v1.3      │
│   Detection Finding (class_uid 2004) wrapped with            │
│   NexusEnvelope (per ADR-004).                               │
│   Five families: RUNTIME_PROCESS / RUNTIME_FILE /            │
│   RUNTIME_NETWORK / RUNTIME_SYSCALL / RUNTIME_OSQUERY.       │
│   No cross-sensor dedup in v0.1 (deferred to D.7).           │
└──────────────────────────────────────────────────────────────┘
    │
    ▼
findings.json + summary.md + audit.jsonl
    │
    ▼
eval suite (10/10 cases via the F.2 framework)
```

## Public surface

```python
from runtime_threat.agent import run
from runtime_threat.schemas import (
    Severity,
    FindingType,
    AffectedHost,
    RuntimeFinding,
    FindingsReport,
    build_finding,
    short_host_id,
)
from runtime_threat.tools.falco import falco_alerts_read, FalcoAlert, FalcoError
from runtime_threat.tools.tracee import tracee_alerts_read, TraceeAlert, TraceeError
from runtime_threat.tools.osquery import osquery_run, OsqueryResult, OsqueryError
from runtime_threat.severity import (
    falco_to_severity,
    tracee_to_severity,
    osquery_to_severity,
)
from runtime_threat.normalizer import normalize_to_findings
from runtime_threat.summarizer import render_summary
from runtime_threat.eval_runner import RuntimeThreatEvalRunner
from runtime_threat.nlah_loader import load_system_prompt, default_nlah_dir

# ADR-007 v1.1 + v1.2: no per-agent llm.py and a 25-line nlah_loader shim.
from charter.llm_adapter import LLMConfig, make_provider, config_from_env
from charter.nlah_loader import load_system_prompt as charter_load_system_prompt
```

Registered via `[project.entry-points."nexus_eval_runners"]` so the framework CLI can resolve `--runner runtime_threat` without import gymnastics.

## ADR-007 v1.2 conformance addendum

D.3 is the **first agent built end-to-end against the post-v1.2 canon** (LLM adapter hoisted in v1.1, NLAH loader hoisted in v1.2). Per-pattern verdicts:

| ADR-007 pattern                               | Task    | Verdict                                                                           |
| --------------------------------------------- | ------- | --------------------------------------------------------------------------------- |
| Schema-as-typing-layer (OCSF wire format)     | 2       | ✅ generalizes (`class_uid 2004` shared with D.2)                                 |
| Async-by-default tool wrappers                | 3, 4, 5 | ✅ generalizes (filesystem + subprocess instead of boto3/HTTP)                    |
| HTTP-wrapper convention                       | —       | n/a — Runtime Threat is filesystem + subprocess at the tool layer                 |
| Concurrent `asyncio.TaskGroup` enrichment     | 11      | ✅ generalizes (3-feed fan-out; each feed independently skippable)                |
| Markdown summarizer (top-down severity)       | 8       | ✅ generalizes; one delta — "Critical runtime alerts" section pinned              |
| NLAH layout (README + tools.md + examples/)   | 9       | ✅ **generalizes via the v1.2 hoist** — `nlah_loader.py` is 25 LOC                |
| LLM adapter via `charter.llm_adapter`         | 10      | ✅ **thrice-validated** — anti-pattern guard test in place                        |
| Charter context + `agent.run` signature shape | 11      | ✅ generalizes (4th agent with the same `(contract, *, llm_provider, ...)` shape) |
| Eval-runner via entry-point group             | 13      | ✅ generalizes (10/10 acceptance via framework CLI)                               |
| CLI subcommand pattern (`eval` + `run`)       | 14      | ✅ generalizes                                                                    |

**v1.2 twice-validated:** Three retrofitted agents (cloud-posture / vulnerability / identity) all run on the shim; D.3 is the first agent to ship with the shim from day one. The shim diff vs the original 55-LOC `nlah_loader.py` (-30 LOC × 3 agents + this fresh agent) is the visible savings the hoist was supposed to buy.

**v1.3 candidate flagged earlier** — severity normalization across heterogeneous sensors (Falco priority strings + Tracee int + caller-supplied OSQuery) currently lives at `runtime_threat.severity`. If D.4 Network Threat Agent's pcap classifier ships a third severity scale, hoist into `charter.severity` per ADR-007 v1.1's "amend on the third duplicate" rule.

## Phase 1 caps (deferred)

- **Live Falco gRPC** ingestion — Phase 1c (long-running stream consumer with backpressure).
- **Kubernetes-native DaemonSet** wiring — Phase 1b (single-cluster scope first).
- **Windows runtime sensors** (Sysmon parsers) — Phase 2 multi-OS.
- **MITRE ATT&CK technique mapping** per finding — Phase 1b D.8 Threat Intel Agent injects cross-agent.
- **Asset enrichment** (which pod / deployment / image scanned by D.1) — Phase 1b D.7 Investigation Agent.
- **Multi-feed dedup** when Falco + Tracee describe the same incident — Phase 1b D.7 Investigation Agent.
- **Multi-query OSQuery packs** (JSON format) — Phase 1c.
- **Distributed OSQuery scheduler** — Phase 1c.

## License

BSL 1.1 — agent-specific code per [ADR-001](../../../docs/_meta/decisions/ADR-001-monorepo-bootstrap.md). The runtime substrate (`nexus-charter`, `nexus-eval-framework`) ships under Apache 2.0.

## See also

- [D.3 plan](../../../docs/superpowers/plans/2026-05-11-d-3-runtime-threat-agent.md) — implementation plan (16 tasks).
- [Cloud Posture Agent](../cloud-posture/) — the F.3 reference template.
- [Vulnerability Agent](../vulnerability/) — D.1 second-template validation.
- [Identity Agent](../identity/) — D.2 third-template validation (NLAH-loader hoist source).
- [`charter.llm_adapter`](../../charter/src/charter/llm_adapter.py) — shared LLM adapter (no per-agent `llm.py`).
- [`charter.nlah_loader`](../../charter/src/charter/nlah_loader.py) — shared NLAH loader (ADR-007 v1.2).
- Runbook: [consume_falco_feed.md](runbooks/consume_falco_feed.md).
