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

# D.3 Runtime Threat v0.2 (Cycle 6 — first Group A real-time-class agent) — Level 1 →
# Level 2: live Falco + Tracee real-time event subscription, MITRE ATT&CK technique
# mapping with confidence, passive behavioral baseline, read-only forensic snapshot
# action (no kill/quarantine — A.1 Remediation cycle), Investigation handoff flag.
# ADR-010 version-extension bump. OCSF emission stays class_uid 2004 (verified, WI-R5).
__version__ = "0.2.0"
