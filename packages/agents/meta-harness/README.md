# Nexus Meta-Harness Agent (A.4)

**Status:** v0.1 — bootstrap (Task 1 / 16).

The first agent in the Nexus fleet that **reads other agents**.
Runs cross-agent batch eval, A/B-compares NLAH variants, tracks
scorecard deltas, flags regressions. **Producer of operator-facing
diagnostics; ruthlessly read-only in v0.1.**

## v0.1 surface

Five capabilities only:

1. **Cross-agent batch evaluation** — runs the eval suites of all
   16 prior agents in a single batch.
2. **A/B comparison runner** — two NLAH variants of the same agent,
   same cases, deterministic diff.
3. **Agent introspection primitives** — parses NLAH directories per
   ADR-007 v1.2 (read-only).
4. **Scorecard delta tracking** — persists scorecards in
   SemanticStore; compares each run to prior run.
5. **Markdown report output** — `meta_harness_report.md`
   summarizing batch eval, A/B, regressions, watch-list.

## Out of scope (v0.1)

- **No autonomous skill creation** (deferred to v0.2).
- **No NLAH auto-deploy** (deferred to v0.3).
- **No new fabric subject** (deferred to v0.2 conditional).
- **No autonomous Curator** (deferred to v0.3).
- **No multi-tenant production** (blocks on SET LOCAL `$1` fix).
- **No `claims.>` publish, no bus emission, no NLAH writes.**

See [docs/superpowers/plans/2026-05-21-a-4-meta-harness-v0-1.md](../../../docs/superpowers/plans/2026-05-21-a-4-meta-harness-v0-1.md)
for the full v0.1 scope and 16-task table.
