# Nexus Supervisor Agent (#0)

**Status:** v0.1 — bootstrap (Task 1 / 16). Seventh and FINAL unbuilt agent under [Path-B-breadth-first](../../../docs/superpowers/sketches/2026-05-20-agent-version-roadmaps.md). Closes the breadth-first push at 17/17 when the verification record lands.

The platform orchestrator. Routes incoming work to the right specialist; fans out pre-declared independent tasks in parallel; emits to F.6 audit chain; escalates on timeout. **Ruthlessly read-only against speculation in v0.1** — structurally fenced from `claims.>` (Task 8 SAFETY-CRITICAL substrate touch).

## v0.1 allowed capabilities (5)

1. **Declarative routing** via `routing/agents.md` — no LLM in the routing path.
2. **Parallel dispatch** of pre-declared independent tasks (`asyncio.Semaphore(5)`); NOT multi-agent planning.
3. **Time-boxing** per F.1 charter budgets; one attempt per delegation (no auto-retry).
4. **F.6 audit chain** emit (4 additive audit-action vocabulary entries).
5. **60-second heartbeat loop**; single-threaded per customer via `fcntl.flock` distributed lock.

## Out of scope (v0.1)

- No LLM-driven routing (deferred to v0.2).
- No multi-agent planning (deferred to v0.3+).
- No `customer_context.md` writes (deferred to v0.2 with operator approval gate).
- No auto-retry on delegation failure (deferred to v0.2).
- No cron scheduler (file-backed queue only).
- No F.5 SemanticStore reads (deferred to v0.2+).
- No subprocess specialist isolation (in-process only in v0.1).
- No multi-tenant production (blocks on SET LOCAL `$1` substrate-fix).
- **No `claims.>` subscription** — structurally fenced via Task 8.
- **No NLAH writes** to any agent's directory.

See [docs/superpowers/plans/2026-05-21-supervisor-v0-1.md](../../../docs/superpowers/plans/2026-05-21-supervisor-v0-1.md) for the full v0.1 scope and 16-task table.
