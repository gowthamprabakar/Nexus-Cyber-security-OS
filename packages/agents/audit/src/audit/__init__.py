"""Nexus Audit Agent — F.6 / Agent #14.

The append-only hash-chained log writer the other agents cannot disable.
Wraps the existing `charter.audit.AuditLog` + `charter.verifier.verify_audit_log`
primitives and the F.5 memory-engine audit emissions as a queryable
surface for compliance teams.

Built end-to-end against [ADR-007 v1.1 + v1.2](../../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)
and introduces the **always-on agent class** (ADR-007 v1.3, drafted
alongside F.6 Task 16). Budget envelope honours only `wall_clock_sec`;
every other axis logs a structlog warning and proceeds. F.6 is the
first member of the always-on class.
"""

from __future__ import annotations

# audit v0.2 (Cycle 11 — F.6, the institutional-integrity agent; the always-on class with the
# single BY_DESIGN_EXEMPT tool-proxy deviation, ADR-007 v1.3 — PRESERVED, no new exemptions
# WI-F10). Level 1 -> Level 2 INFRASTRUCTURE: cross-agent audit aggregation (10 closed-cycle
# agents), a Merkle indexing layer, tamper detection + alerts (NEVER auto-repair, WI-F2), a
# broad typed query filter, compliance-evidence integration, and code-level read-only +
# cross-tenant invariants. Per Path 1: continuous mode is INFRASTRUCTURE here; agent.run()
# wiring is the Phase C consolidated retrofit. OCSF stays class_uid 6003 API Activity (the
# first 6003 emitter; chain hashes in the unmapped slot, byte-identical WI-F5). ADR-010 bump.
__version__ = "0.2.0"
