"""Nexus Investigation Agent — D.7 / Agent #8.

The first Phase-1b agent. Implements the Orchestrator-Workers pattern
(depth ≤ 3, parallel ≤ 5) for forensic incident analysis. First agent
to consume the full Phase-1a substrate: F.5 memory engines (semantic
neighbor walks + procedural hypothesis writes), F.6 audit query
(cross-agent action history), F.1 charter (extended budget caps for
sub-agent flows), F.4 tenant-scoped sessions.

Six-stage pipeline (per the agent spec):

  SCOPE → SPAWN → SYNTHESIZE → VALIDATE → PLAN → HANDOFF

Sub-agent flavors (4): timeline, ioc_pivot, asset_enum, attribution.
Each runs under its own Charter with narrower scope and tools; results
merge at Stage 3. The orchestrator (Task 8) enforces the depth + parallel
caps and the allowlist for which agents are permitted to spawn at all
(currently one entry: `investigation`).
"""

from __future__ import annotations

__version__ = "0.1.0"
