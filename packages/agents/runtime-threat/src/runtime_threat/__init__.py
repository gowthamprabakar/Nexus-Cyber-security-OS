"""Nexus Runtime Threat Agent — CWPP.

Agent #4 of 18. **First agent built end-to-end against ADR-007 v1.2** (the
post-D.2 NLAH-loader hoist). Consumes runtime alerts from eBPF-based
sensors (Falco, Tracee) and on-host query engines (OSQuery), normalizes
them to OCSF v1.3 Detection Findings (`class_uid 2004`).

The runtime stack is intentionally **not** bundled with the agent —
deterministic v0.1 reads JSONL fixtures + invokes a local `osqueryi`
subprocess. Live-stream consumption (Falco gRPC, OSQuery distributed
scheduler) defers to Phase 1c.
"""

from __future__ import annotations

__version__ = "0.1.0"
