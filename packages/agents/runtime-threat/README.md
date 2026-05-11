# `nexus-runtime-threat`

Runtime Threat Agent — agent **#4 of 18** for Nexus Cyber OS. CWPP (Cloud Workload Protection Platform) — consumes runtime alerts from Falco / Tracee / OSQuery and emits OCSF v1.3 Detection Findings. **First agent built end-to-end against [ADR-007 v1.2](../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)** (post-NLAH-loader-hoist).

> **Status:** D.3 plan in flight. This README will be expanded as tasks land.

## What it does

Reads runtime alert streams produced by eBPF-based sensors (Falco, Tracee) and on-host query engines (OSQuery), normalizes them across the three native severity scales into OCSF v1.3 Detection Findings (`class_uid 2004`), and emits the same shape every other Track-D agent emits. Five detection families: PROCESS / FILE / NETWORK / SYSCALL / OSQUERY.

The runtime stack itself is **not** bundled — deterministic v0.1 reads JSONL fixture files for Falco / Tracee and invokes a local `osqueryi` subprocess. Live-stream consumption (Falco gRPC, OSQuery distributed scheduler) defers to Phase 1c.

## License

BSL 1.1 — agent-specific code per [ADR-001](../../../docs/_meta/decisions/ADR-001-monorepo-bootstrap.md). The runtime substrate (`nexus-charter`, `nexus-eval-framework`) ships under Apache 2.0.

## See also

- [D.3 plan](../../../docs/superpowers/plans/2026-05-11-d-3-runtime-threat-agent.md).
- [Cloud Posture Agent](../cloud-posture/) — the F.3 reference template.
- [Vulnerability Agent](../vulnerability/) — the D.1 second-template validation.
- [Identity Agent](../identity/) — the D.2 third-template validation (NLAH-loader hoist source).
- [`charter.llm_adapter`](../../charter/src/charter/llm_adapter.py) — shared LLM adapter (no per-agent `llm.py`).
- [`charter.nlah_loader`](../../charter/src/charter/nlah_loader.py) — shared NLAH loader (ADR-007 v1.2).
