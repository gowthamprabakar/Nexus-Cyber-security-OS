"""Nexus Meta-Harness Agent — A.4 / Agent #16 under ADR-007.

The sixth of the 7 unbuilt agents shipped under the 2026-05-20
Path-B-breadth-first operating rule. **The first agent that reads
other agents** — runs cross-agent batch eval, A/B-compares NLAH
variants, tracks scorecard deltas, flags regressions. Producer of
operator-facing diagnostics; ruthlessly read-only in v0.1.

Scope (v0.1, locked 2026-05-21):

- 2 emit directions per run:
    1. ``SemanticStore`` entities (``entity_type="agent_scorecard"``
       and ``"ab_comparison_result"``; persistent KG record).
    2. ``meta_harness_report.md`` workspace markdown for operator
       review.
- **No bus emission** (Q-ARCH-2 deferred to v0.2).
- **No NLAH writes** (Q-ARCH-1 deferred to v0.2 — v0.2 MUST review
  subscriber-ACL per ADR-012 since it introduces auto-acting).
- Single-tenant ``semantic_store=None`` opt-in default.
- Eval-framework consumed directly; agent-local ``BatchEvalRunner``
  stays package-local per ADR-007 3rd-consumer hoist rule
  (Q-ARCH-3).

Six-stage pipeline (one fewer than D.12 — no PUBLISH stage):

  INTROSPECT -> BATCH_EVAL -> AB_COMPARE -> DELTA -> REPORT -> HANDOFF

Watch-items:

- WI-1: substrate sealed (zero ``packages/charter/`` or
  ``packages/shared/`` touches).
- WI-2: single-tenant default (``semantic_store=None`` opt-in).
- WI-3: stub-LLM determinism; A/B byte-equal under identical NLAH.
- WI-4: read-only NLAH access enforced by integration-test guard.
- WI-5: Q-ARCH-1 carry-forward — A.4 v0.2 plan MUST include
  subscriber-ACL review per ADR-012 since v0.2 introduces
  auto-acting behavior.

Autonomous skill creation, NLAH auto-deploy, new fabric subject,
autonomous Curator behavior, multi-tenant production, and
eval-framework substrate hoist are all deferred per the
2026-05-21 plan doc (A.4 v0.2 / v0.3 / v0.x post-SET-LOCAL-fix).
"""

from __future__ import annotations

__version__ = "0.1.0"
