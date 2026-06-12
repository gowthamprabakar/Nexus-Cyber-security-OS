"""Nexus Supervisor Agent — #0 / Agent #17 under ADR-007.

The seventh and FINAL unbuilt agent shipped under the 2026-05-20
Path-B-breadth-first operating rule. **The platform orchestrator.**
Closes the breadth-first push: 17/17 agents at v0.1 when this
verification record lands.

Supervisor routes incoming work to the right specialist; fans out
pre-declared independent tasks in parallel; emits to F.6 audit
chain; escalates on timeout. Ruthlessly read-only against
speculation in v0.1 — structurally fenced from ``claims.>``.

Scope (v0.1, locked 2026-05-21):

- 5 allowed capabilities:
    1. Declarative routing via ``routing/agents.md`` (no LLM in
       the routing path).
    2. Parallel dispatch of pre-declared independent tasks
       (``asyncio.Semaphore(5)``; NOT multi-agent planning).
    3. Time-boxing per F.1 charter budgets; one attempt per
       delegation (no auto-retry).
    4. F.6 audit chain emit (4 additive audit-action vocabulary
       entries).
    5. 60-second heartbeat loop; single-threaded per customer
       via ``fcntl.flock`` distributed lock.
- 2 + 1 emit directions: F.6 audit chain + ``supervisor_report.md``
  + conditional escalation markdown. **No bus emission; no OCSF;
  no NLAH writes.**
- Single-tenant ``semantic_store=None`` opt-in default.
- File-backed scheduled-task queue (no cron).

Five-stage pipeline (one fewer than A.4 — Supervisor is stateless
in v0.1, so there's no DELTA stage):

  INGEST -> ROUTE -> DISPATCH -> AUDIT -> HANDOFF

Plus the outer 60-second heartbeat loop (single-threaded per
customer via fcntl.flock).

Watch-items:

- WI-1: substrate sealed except Task 8 (the single SAFETY-CRITICAL
  substrate touch adding Supervisor to ``_FORBIDDEN_SUBSCRIPTIONS``).
- WI-2: single-tenant default (``semantic_store=None`` opt-in).
- WI-3: stub-LLM determinism (routing is rule-based; naturally
  deterministic).
- WI-4: no NLAH writes + no OCSF payload reads (router never
  accesses any OCSF field beyond envelope routing-keys).
- WI-5: forward-carry — three forbidden subscribers eventually
  (A.1 + Supervisor + A.4 v0.2+). The A.4 v0.2 plan author MUST
  add ``_FORBIDDEN_SUBSCRIPTIONS["meta_harness"]`` before any
  auto-acting code lands.
- WI-6: no LLM + no A.4-introspection coupling in the routing
  path.

LLM-driven routing, multi-agent planning, customer_context.md
writes, auto-retry, cron scheduling, F.5 SemanticStore reads,
subprocess specialist isolation, and multi-tenant production are
all deferred per the 2026-05-21 plan doc (Supervisor v0.2 / v0.3
/ v0.x post-SET-LOCAL-fix).
"""

from __future__ import annotations

# supervisor v0.2 (Cycle 12 — Agent #0, the platform orchestrator; the lightweight
# router/dispatcher class with a BY-DESIGN deviation from the specialist profile, ADR-007 —
# PRESERVED, no Charter wrap / no ToolRegistry / no OCSF emission, WI-O11). Level 1 -> Level 2
# INFRASTRUCTURE: live dispatch to the 11 closed-cycle agents, per-agent concurrency, bounded
# transient/permanent/timeout failure classification + retry (max 1, H4), an additive F.6
# audit vocabulary (4 -> 8 entries, existing 4 byte-identical WI-O5), a SQLite/WAL scheduled
# queue, and event-driven + heartbeat coexistence. Two new code-level invariants:
# assert_no_peer_to_peer (WI-O8/H2) + assert_signed_contract (WI-O9). The
# _FORBIDDEN_SUBSCRIPTIONS fence (never subscribe to claims.>, WI-O10) is preserved. Per Path 1:
# continuous orchestration is INFRASTRUCTURE here; the production-loop wiring is the Phase C
# consolidated retrofit. NO OCSF emission (emits F.6 audit + supervisor_report.md + escalation
# files). ADR-010 bump.
__version__ = "0.2.0"
