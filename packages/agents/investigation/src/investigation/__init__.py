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

# investigation v0.2 (Cycle 14 — D.7, the 2nd LLM-heavy agent; the structured-LLM
# Orchestrator-Workers deviator: FULL Charter context + ToolRegistry (5 worker tools via
# ctx.call_tool) + LLM via charter.llm_adapter; sole OCSF 2005 Incident Finding emitter).
# Level 1 -> Level 2 INFRASTRUCTURE: live evidence collection across the 13 closed-cycle agents
# (Q2), DeepSeek primary + Anthropic fallback (Q3, inherits D.13 Q5), continuous-investigation
# infrastructure, and SIX code-level invariants. INHERITED from D.13 (the LLM-agent template):
# assert_categorical_only + assert_bounded_retry + assert_findings_cited (extended to
# evidence_refs). NEW (the Orchestrator-Workers template): assert_worker_bounded (depth<=3,
# parallel<=5 H5), assert_evidence_chain (every hypothesis cites resolved evidence H2), and
# assert_no_speculation (hypothesis grounded in evidence H1). Sub-agent allowlist stays
# {"investigation"} (WI-I15); D.7 is ADVISORY (WI-I14). Per Path 1: continuous mode is
# INFRASTRUCTURE here; production-loop wiring is the Phase C consolidated retrofit. ADR-010 bump.
__version__ = "0.2.0"
