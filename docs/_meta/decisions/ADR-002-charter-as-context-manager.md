# ADR-002 — Charter exposed as a Python context manager

- **Status:** accepted
- **Date:** 2026-05-08
- **Authors:** Winston (architect), AI/Agent Eng
- **Stakeholders:** all engineers writing agents

## Context

The runtime charter must wrap every agent invocation. Three plausible API shapes:

1. **Decorator** — `@charter(contract)` on the agent function
2. **Middleware framework** — agents inherit from a base class with charter hooks
3. **Context manager** — `with Charter(contract) as ctx: ...`

## Decision

Use a context manager. Public API: `with Charter(contract, tools=registry) as ctx`.

## Consequences

### Positive

- Lifecycle is explicit: setup on `__enter__`, teardown on `__exit__`.
- Audit log entries for `invocation_started`, `invocation_failed`, `invocation_completed` are guaranteed by the `with` block, even on exceptions.
- Works in both sync and async code paths (async wrapper is a thin sibling).
- No magic — the engineer writing an agent reads the code top-to-bottom and sees what's happening.

### Negative

- Engineer must remember to call `ctx.call_tool` (not the underlying function directly). Mitigation: tool registry isolates the underlying functions; agents only have access to `ctx`.

### Neutral

- Slight verbosity vs. a decorator. Acceptable cost for explicitness.

## Alternatives considered

### Alt 1: Decorator (`@charter(contract)`)

- Why rejected: hides lifecycle; harder to reason about exception paths; conflicts with async/sync polymorphism; harder to unit-test individual phases (workspace setup vs. audit close).

### Alt 2: Base class inheritance

- Why rejected: implicit composition; harder for new engineers to trace what runs when; locks agent shape to a class hierarchy that may not fit all 18 agents (e.g. functional Curiosity Agent vs. Investigation Agent's sub-agent orchestration).

## References

- Implementation: `packages/charter/src/charter/context.py`
- Reference agent: `packages/charter/src/charter/examples/hello_world_agent/`
- Plan: `docs/superpowers/plans/2026-05-08-f-1-runtime-charter-v0.1.md`
