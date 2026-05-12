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

__version__ = "0.1.0"
