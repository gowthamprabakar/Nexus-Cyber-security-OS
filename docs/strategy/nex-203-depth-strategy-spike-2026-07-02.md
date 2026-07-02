# NEX-203 — Depth-Strategy Spike (ADR) — SPIKE OUTPUT

**Timebox: 1 day. Deliverable: a design decision. Status: RESOLVED.**

## The problem

`DEFAULT_MAX_DEPTH = 4` on the generic walker. Planned families exceed it — K8s RBAC escalation is
`pod → USES_SERVICE_ACCOUNT → SA → BINDS → admin-role → (reaches) secret → data` ≈ 5–6 hops. At depth 4
these never emerge. Options: (a) bump the global default, (b) path-stitching, (c) per-family depth, (d)
named detectors for deep shapes.

## Empirical measurement (fixtures)

Ran the report-card runner + full-moat smoke at depth 4 / 5 / 6:

| depth | result | wall |
|---|---|---|
| 4 | PASS, card unchanged | ~1.0s |
| 5 | PASS, card unchanged | ~0.8s |
| 6 | PASS, card unchanged | ~0.8s |

**Caveat (the honest limit):** the fixtures are tiny (< 30 nodes), so this proves depth 5/6 doesn't
add noise or cost *on small graphs* — it does NOT capture the real risk, which is **recursive-CTE
fan-out on a large, densely-connected tenant graph** (depth is exponential in branching factor). We
have no real tenant to benchmark, so a global bump can't be de-risked here.

## Decision

**Keep the generic discovery walker at depth 4; implement deep/known families as NAMED detectors.**

- The generic walker is for open-ended NOVEL-path *discovery* — it must stay perf-safe on large graphs,
  so depth stays 4 (the measured-safe, fan-out-bounded default).
- Deep families with a KNOWN shape (K8s RBAC, and any future 5–6-hop archetype) are **named detectors**
  — targeted multi-hop queries that follow ONE specific shape, so they pay no exponential fan-out. This
  is exactly how `crown_jewel` (a 4-hop path) is already implemented: a hand-written join, not a
  depth-bounded BFS. A named detector can join arbitrarily many hops of a fixed shape cheaply.
- A **global depth bump is deferred to a real-graph benchmark** (v0.5): only bump once we can measure
  CTE cost + candidate-noise on a real dense tenant. Bumping blind is the landmine.

## Consequence

- **NEX-301 (K8s RBAC) is a NAMED detector**, not a generic-walker family — no depth change needed.
- The generic engine stays depth-4 (safe). Novel >4-hop *discovery* is a measured v0.5 decision.
- No substrate change this sprint. The depth-4 "ceiling" is not a blocker — it's a routing decision
  (deep shapes → named detectors).
